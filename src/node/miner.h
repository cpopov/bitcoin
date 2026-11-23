// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINER_H
#define BITCOIN_NODE_MINER_H

#include <consensus/amount.h>
#include <kernel/cs_main.h>
#include <node/mining_types.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <threadsafety.h>
#include <txmempool.h>
#include <util/feefrac.h>
#include <util/not_null.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

class CBlockIndex;
class CChainParams;
class CCoinsViewCache;
class Chainstate;
class ChainstateManager;

namespace Consensus {
struct Params;
} // namespace Consensus
namespace demurrage {
class IndexSchedule;
} // namespace demurrage
namespace node {

struct CBlockTemplate
{
    CBlock block;
    // Fees per transaction, not including coinbase transaction (unlike CBlock::vtx).
    std::vector<CAmount> vTxFees;
    // Sigops per transaction, not including coinbase transaction (unlike CBlock::vtx).
    std::vector<int64_t> vTxSigOpsCost;
    // BIP 462b, while the deployment is active: the demurrage charge per
    // transaction at the template's height, not including the coinbase
    // transaction, and their sum, the coinbase's contribution C(h).
    std::vector<CAmount> vTxDemurrageCharges;
    std::optional<CAmount> demurrage_contribution;
    /* A vector of package fee rates, ordered by the sequence in which
     * packages are selected for inclusion in the block template.*/
    std::vector<FeePerVSize> m_package_feerates;
    /*
     * Template containing all coinbase transaction fields that are set by our
     * miner code.
     */
    CoinbaseTx m_coinbase_tx;
};

/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    CAmount nFees;

    // Chain context for the block
    int nHeight;
    int64_t m_lock_time_cutoff;

    const CChainParams& chainparams;
    const CTxMemPool* const m_mempool;
    Chainstate& m_chainstate;

public:
    explicit BlockAssembler(Chainstate& chainstate,
                            const CTxMemPool* mempool,
                            BlockCreateOptions create_options);

    /** Construct a new block template */
    util::NotNullUniquePtr<CBlockTemplate> CreateNewBlock();

    /** The number of transactions in the last assembled block (excluding coinbase transaction) */
    inline static std::optional<int64_t> m_last_block_num_txs{};
    /** The weight of the last assembled block (including reserved weight for block header, txs count and coinbase tx) */
    inline static std::optional<int64_t> m_last_block_weight{};

private:
    const BlockCreateOptions m_options;

    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(const CTxMemPoolEntry& entry);

    // Methods for how to add transactions to a block.
    /** Add transactions based on chunk feerate
      *
      * @pre BlockAssembler::m_mempool must not be nullptr
    */
    void addChunks() EXCLUSIVE_LOCKS_REQUIRED(m_mempool->cs);
    /**
     * BIP 462b: remove from the block being built the transaction whose
     * charge exceeds its fee by the most, and its descendants in the block.
     * charges has one entry per selected transaction and is updated to match.
     * Returns the charges of the transactions removed.
     */
    CAmount RemoveUnfundedTransaction(std::vector<CAmount>& charges);

    // helper functions for addChunks()
    /** Test if a new chunk would "fit" in the block */
    bool TestChunkBlockLimits(int64_t chunk_weight, int64_t chunk_sigops_cost) const;
    /** Perform locktime checks on each transaction in a chunk:
      * This check should always succeed, and is here
      * only as an extra check in case of a bug */
    bool TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const;
};

/**
 * Get the minimum time a miner should use in the next block. This always
 * accounts for the BIP94 timewarp rule, so does not necessarily reflect the
 * consensus limit.
 */
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, int64_t difficulty_adjustment_interval);

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

/** Update an old GenerateCoinbaseCommitment from CreateNewBlock after the block txs have changed */
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman);

/**
 * BIP 462b: the demurrage charge of each of txs, which must not include the
 * claim transaction, in a block at height `height`. Inputs that spend outputs
 * of earlier transactions in txs have no charge.
 */
std::vector<CAmount> GetDemurrageCharges(std::span<const CTransactionRef> txs, const CCoinsViewCache& coins,
                                         demurrage::IndexSchedule& schedule, int height);

/** BIP 462b: C(h), the sum of GetDemurrageCharges(). */
CAmount GetBlockDemurrageCharge(std::span<const CTransactionRef> txs, const CCoinsViewCache& coins,
                                demurrage::IndexSchedule& schedule, int height);

/**
 * BIP 462b: after the transactions of a block on top of the active tip have
 * changed, replace the coinbase's contribution with one that pays the block's
 * demurrage charge out of the coinbase's first output. The block's claim
 * transaction, if it needs one, must already be at index 1.
 */
void UpdateDemurrageContribution(CBlock& block, ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/* Compute the block's merkle root, insert or replace the coinbase transaction and the merkle root into the block */
void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase, uint32_t version, uint32_t timestamp, uint32_t nonce);
} // namespace node

#endif // BITCOIN_NODE_MINER_H
