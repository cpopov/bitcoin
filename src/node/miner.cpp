// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/demurrage.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/mining_args.h>
#include <node/mining_types.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <tinyformat.h>
#include <txgraph.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/hasher.h>
#include <util/log.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <versionbits.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace node {

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    // Account for the BIP54 Murch-Zawy rule on all networks: the last block of
    // a difficulty adjustment period may not be earlier than its first block.
    if (height % difficulty_adjustment_interval == difficulty_adjustment_interval - 1) {
        const int first_height{height - static_cast<int>(difficulty_adjustment_interval) + 1};
        const CBlockIndex* first_block{Assert(pindexPrev->GetAncestor(first_height))};
        min_time = std::max<int64_t>(min_time, first_block->GetBlockTime());
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval()),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockAssembler::BlockAssembler(Chainstate& chainstate,
                               const CTxMemPool* mempool,
                               BlockCreateOptions options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_options{[&] {
          if (auto result{CheckMiningOptions(options, /*use_argnames=*/false)}; !result) {
              throw std::runtime_error(util::ErrorString(result).original);
          }
          return FlattenMiningOptions(std::move(options));
      }()}
{
}

void BlockAssembler::resetBlock()
{
    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockWeight = *Assert(m_options.block_reserved_weight);
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

util::NotNullUniquePtr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate = std::make_unique<CBlockTemplate>();
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction. It is skipped by the
    // getblocktemplate RPC and mining interface consumers must not use it.
    pblock->vtx.emplace_back();

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    // BIP 462b: the claim transaction is determined by the chain alone. It
    // goes at index 1 once the other transactions have been selected.
    ChainstateManager& chainman{m_chainstate.m_chainman};
    const std::optional<int> demurrage_activation{chainman.DemurrageActivationHeight(pindexPrev)};
    CTransactionRef claim_tx;
    CAmount claim_fee{0};
    if (demurrage_activation) {
        std::vector<COutPoint> pool_inputs;
        if (!chainman.GetDemurragePoolInputs(*pindexPrev, *demurrage_activation, pool_inputs)) {
            throw std::runtime_error("Failed to find the demurrage pool inputs");
        }
        if (!pool_inputs.empty()) {
            CAmount pool_value{0};
            for (const COutPoint& outpoint : pool_inputs) {
                pool_value += Assert(m_chainstate.CoinsTip().GetCoin(outpoint))->out.nValue;
            }
            claim_tx = MakeTransactionRef(demurrage::BuildClaimTransaction(pool_inputs, pool_value));
            claim_fee = demurrage::PoolPayout(pool_value);
            nBlockWeight += GetTransactionWeight(*claim_tx);
        }
    }

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    if (m_mempool) {
        LOCK(m_mempool->cs);
        m_mempool->StartBlockBuilding();
        addChunks();
        m_mempool->StopBlockBuilding();
    }

    const auto time_1{SteadyClock::now()};

    // BIP 462b: the block owes the charge of every input it spends, except the
    // claim transaction's, and the coinbase pays it as the contribution.
    CAmount demurrage_contribution{0};
    if (demurrage_activation) {
        auto& charges{pblocktemplate->vTxDemurrageCharges};
        // No input owes a charge until the index starts to fall at CHARGE_HEIGHT.
        const std::optional<int> charge_height{chainman.DemurrageChargeHeight(pindexPrev)};
        charges = charge_height ?
            GetDemurrageCharges(std::span{pblock->vtx}.subspan(1), m_chainstate.CoinsTip(), chainman.DemurrageSchedule(*charge_height), nHeight) :
            std::vector<CAmount>(pblock->vtx.size() - 1, 0);
        demurrage_contribution = std::accumulate(charges.begin(), charges.end(), CAmount{0});
        // The coinbase pays the contribution out of the subsidy and the fees. A
        // transaction whose charge exceeds its fee can only have been selected
        // because it was prioritised. If the block cannot fund it, leave it out.
        const CAmount subsidy_and_payout{claim_fee + GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
        while (demurrage_contribution > nFees + subsidy_and_payout) {
            demurrage_contribution -= RemoveUnfundedTransaction(charges);
        }
        pblocktemplate->demurrage_contribution = demurrage_contribution;
        if (claim_tx) {
            pblock->vtx.insert(pblock->vtx.begin() + 1, claim_tx);
            charges.insert(charges.begin(), 0); // The claim's inputs have no charge.
            pblocktemplate->vTxFees.insert(pblocktemplate->vTxFees.begin(), claim_fee);
            pblocktemplate->vTxSigOpsCost.insert(pblocktemplate->vTxSigOpsCost.begin(), GetLegacySigOpCount(*claim_tx) * WITNESS_SCALE_FACTOR);
            ++nBlockTx;
            nFees += claim_fee;
        }
    }

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;

    // Construct coinbase transaction struct in parallel
    CoinbaseTx& coinbase_tx{pblocktemplate->m_coinbase_tx};
    coinbase_tx.version = coinbaseTx.version;

    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
    coinbase_tx.sequence = coinbaseTx.vin[0].nSequence;

    // Add an output that spends the full coinbase reward.
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    // Block subsidy + fees, less the demurrage contribution
    const CAmount block_reward{nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
    Assert(demurrage_contribution <= block_reward);
    coinbaseTx.vout[0].nValue = block_reward - demurrage_contribution;
    coinbase_tx.block_reward_remaining = block_reward - demurrage_contribution;
    if (demurrage_contribution > 0) {
        coinbaseTx.vout.emplace_back(demurrage_contribution, demurrage::PoolScript());
    }

    // Start the coinbase scriptSig with the block height as required by BIP34.
    // Mining clients are expected to append extra data to this prefix, so
    // increasing its length would reduce the space they can use and may break
    // existing clients.
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight;
    // Set script_sig_prefix here, so IPC mining clients are not affected by
    // the optional scriptSig padding below. They provide their own extraNonce,
    // and in a typical setup a pool name or realistic extraNonce already makes
    // the scriptSig long enough.
    coinbase_tx.script_sig_prefix = coinbaseTx.vin[0].scriptSig;
    if (nHeight <= 16) {
        // For blocks at heights <= 16, the BIP34-encoded height alone is only
        // one byte. Consensus requires coinbase scriptSigs to be at least two
        // bytes long (bad-cb-length), so an OP_0 is always appended at those
        // heights.
        coinbaseTx.vin[0].scriptSig << OP_0;
    }
    Assert(nHeight > 0);
    coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1);
    coinbase_tx.lock_time = coinbaseTx.nLockTime;

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);

    const CTransactionRef& final_coinbase{pblock->vtx[0]};
    if (final_coinbase->HasWitness()) {
        const auto& witness_stack{final_coinbase->vin[0].scriptWitness.stack};
        // Consensus requires the coinbase witness stack to have exactly one
        // element of 32 bytes.
        Assert(witness_stack.size() == 1 && witness_stack[0].size() == 32);
        coinbase_tx.witness = uint256(witness_stack[0]);
    }
    if (demurrage_contribution > 0) {
        coinbase_tx.required_outputs.push_back(final_coinbase->vout.at(1));
    }
    if (const int witness_index = GetWitnessCommitmentIndex(*pblock); witness_index != NO_WITNESS_COMMITMENT) {
        Assert(witness_index >= 0 && static_cast<size_t>(witness_index) < final_coinbase->vout.size());
        coinbase_tx.required_outputs.push_back(final_coinbase->vout[witness_index]);
    }

    LogDebug(BCLog::MINING, "CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;

    if (m_options.test_block_validity) {
        if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
            throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() chunks: %.2fms, validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return util::NotNull{std::move(pblocktemplate)};
}

bool BlockAssembler::TestChunkBlockLimits(int64_t chunk_weight, int64_t chunk_sigops_cost) const
{
    // block_max_weight has been flattened before block assembly limit checks.
    Assert(m_options.block_max_weight);
    if (nBlockWeight + chunk_weight >= m_options.block_max_weight) {
        return false;
    }
    if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const
{
    for (const auto tx : txs) {
        if (!IsFinalTx(tx.get().GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(const CTxMemPoolEntry& entry)
{
    pblocktemplate->block.vtx.emplace_back(entry.GetSharedTx());
    pblocktemplate->vTxFees.push_back(entry.GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(entry.GetSigOpCost());
    nBlockWeight += entry.GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += entry.GetSigOpCost();
    nFees += entry.GetFee();

    if (*m_options.print_modified_fee) {
        LogInfo("fee rate %s txid %s\n",
                  CFeeRate(entry.GetModifiedFee(), entry.GetTxSize()).ToString(),
                  entry.GetTx().GetHash().ToString());
    }
}

void BlockAssembler::addChunks()
{
    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> selected_transactions;
    selected_transactions.reserve(MAX_CLUSTER_COUNT_LIMIT);
    FeePerWeight chunk_feerate;

    // This fills selected_transactions
    chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
    FeePerVSize chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);

    while (selected_transactions.size() > 0) {
        // Check to see if min fee rate is still respected.
        if (ByRatio{chunk_feerate_vsize} < ByRatio{m_options.block_min_fee_rate->GetFeePerVSize()}) {
            // Everything else we might consider has a lower feerate
            return;
        }

        int64_t chunk_sig_ops = 0;
        int64_t chunk_weight = 0;
        for (const auto& tx : selected_transactions) {
            chunk_sig_ops += tx.get().GetSigOpCost();
            chunk_weight += tx.get().GetTxWeight();
        }

        // Check to see if this chunk will fit.
        if (!TestChunkBlockLimits(chunk_weight, chunk_sig_ops) || !TestChunkTransactions(selected_transactions)) {
            // This chunk won't fit, so we skip it and will try the next best one.
            m_mempool->SkipBuilderChunk();
            ++nConsecutiveFailed;

            // block_max_weight has been flattened before block assembly limit checks.
            Assert(m_options.block_max_weight);
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
                    BLOCK_FULL_ENOUGH_WEIGHT_DELTA > *m_options.block_max_weight) {
                // Give up if we're close to full and haven't succeeded in a while
                return;
            }
        } else {
            m_mempool->IncludeBuilderChunk();

            // This chunk will fit, so add it to the block.
            nConsecutiveFailed = 0;
            for (const auto& tx : selected_transactions) {
                AddToBlock(tx);
            }
            pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize);
        }

        selected_transactions.clear();
        chunk_feerate = m_mempool->GetBlockBuilderChunk(selected_transactions);
        chunk_feerate_vsize = ToFeePerVSize(chunk_feerate);
    }
}

CAmount BlockAssembler::RemoveUnfundedTransaction(std::vector<CAmount>& charges)
{
    CBlock& block{pblocktemplate->block};
    auto& fees{pblocktemplate->vTxFees};
    auto& sigops{pblocktemplate->vTxSigOpsCost};
    // Transaction i of the template is block.vtx[i + 1]: the claim transaction is not in the block yet.
    Assert(charges.size() == fees.size() && fees.size() == sigops.size() && fees.size() + 1 == block.vtx.size());

    // The transaction that costs the block the most.
    size_t worst{0};
    for (size_t i{1}; i < charges.size(); ++i) {
        if (charges[i] - fees[i] > charges[worst] - fees[worst]) worst = i;
    }
    // The contribution exceeds the fees, so some transaction's charge exceeds its fee.
    Assert(!charges.empty() && charges[worst] > fees[worst]);

    // Remove it, and the later transactions that spend its outputs or theirs.
    std::unordered_set<Txid, SaltedTxidHasher> removed;
    CAmount removed_charge{0};
    size_t kept{0};
    for (size_t i{0}; i < charges.size(); ++i) {
        const CTransactionRef tx{block.vtx[i + 1]};
        const bool remove{i == worst || std::ranges::any_of(tx->vin, [&](const CTxIn& txin) { return removed.contains(txin.prevout.hash); })};
        if (remove) {
            LogWarning("Leaving transaction %s out of the block template: its demurrage charge %d exceeds what the block can fund", tx->GetHash().ToString(), charges[i]);
            removed.insert(tx->GetHash());
            removed_charge += charges[i];
            nFees -= fees[i];
            nBlockWeight -= GetTransactionWeight(*tx);
            nBlockSigOpsCost -= sigops[i];
            --nBlockTx;
            continue;
        }
        block.vtx[kept + 1] = tx;
        charges[kept] = charges[i];
        fees[kept] = fees[i];
        sigops[kept] = sigops[i];
        ++kept;
    }
    block.vtx.resize(kept + 1);
    charges.resize(kept);
    fees.resize(kept);
    sigops.resize(kept);
    return removed_charge;
}

std::vector<CAmount> GetDemurrageCharges(std::span<const CTransactionRef> txs, const CCoinsViewCache& coins,
                                         demurrage::IndexSchedule& schedule, int height)
{
    std::unordered_set<Txid, SaltedTxidHasher> earlier_txids;
    std::vector<CAmount> charges;
    charges.reserve(txs.size());
    for (const CTransactionRef& tx : txs) {
        CAmount charge{0};
        for (const CTxIn& txin : tx->vin) {
            // An output created in the same block has no charge.
            if (earlier_txids.contains(txin.prevout.hash)) continue;
            const Coin& coin{coins.AccessCoin(txin.prevout)};
            if (coin.IsSpent()) continue; // Block validation will reject it.
            charge += schedule.ChargeFor(coin.out.nValue, coin.nHeight, height);
        }
        charges.push_back(charge);
        earlier_txids.insert(tx->GetHash());
    }
    return charges;
}

CAmount GetBlockDemurrageCharge(std::span<const CTransactionRef> txs, const CCoinsViewCache& coins,
                                demurrage::IndexSchedule& schedule, int height)
{
    const std::vector<CAmount> charges{GetDemurrageCharges(txs, coins, schedule, height)};
    return std::accumulate(charges.begin(), charges.end(), CAmount{0});
}

void UpdateDemurrageContribution(CBlock& block, ChainstateManager& chainman)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* prev{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
    if (!prev) return;
    const auto activation{chainman.DemurrageActivationHeight(prev)};
    if (!activation) return;
    std::vector<COutPoint> pool_inputs;
    if (!chainman.GetDemurragePoolInputs(*prev, *activation, pool_inputs)) {
        throw std::runtime_error("Failed to find the demurrage pool inputs");
    }
    const size_t first_charged{pool_inputs.empty() ? size_t{1} : size_t{2}};
    const std::optional<int> charge_height{chainman.DemurrageChargeHeight(prev)};
    const CAmount charge{charge_height && block.vtx.size() > first_charged ?
        GetBlockDemurrageCharge(std::span{block.vtx}.subspan(first_charged), chainman.ActiveChainstate().CoinsTip(),
                                chainman.DemurrageSchedule(*charge_height), prev->nHeight + 1) :
        CAmount{0}};

    CMutableTransaction coinbase{*block.vtx.at(0)};
    // Return any previous contribution to the first output.
    for (auto it{coinbase.vout.begin()}; it != coinbase.vout.end();) {
        if (demurrage::IsPoolScript(it->scriptPubKey)) {
            coinbase.vout[0].nValue += it->nValue;
            it = coinbase.vout.erase(it);
        } else {
            ++it;
        }
    }
    if (charge > 0) {
        if (coinbase.vout[0].nValue < charge) {
            throw std::runtime_error(strprintf("Demurrage charge %d exceeds the coinbase output %d", charge, coinbase.vout[0].nValue));
        }
        coinbase.vout[0].nValue -= charge;
        coinbase.vout.insert(coinbase.vout.begin() + 1, CTxOut{charge, demurrage::PoolScript()});
    }
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
}

void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Reset cached checks
    block.m_checked_witness_commitment = false;
    block.m_checked_merkle_root = false;
    block.fChecked = false;
}

} // namespace node
