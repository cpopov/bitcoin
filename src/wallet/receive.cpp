// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/check.h>

#include <algorithm>
#include <wallet/receive.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

namespace wallet {
bool InputIsMine(const CWallet& wallet, const CTxIn& txin)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* prev = wallet.GetWalletTx(txin.prevout.hash);
    if (prev && txin.prevout.n < prev->GetTx()->vout.size()) {
        return wallet.IsMine(prev->GetTx()->vout[txin.prevout.n]);
    }
    return false;
}

bool AllInputsMine(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (!InputIsMine(wallet, txin)) return false;
    }
    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout)
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    return (wallet.IsMine(txout) ? txout.nValue : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx)
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += OutputGetCredit(wallet, txout);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CTxOut& txout)
{
    return ScriptIsChange(wallet, txout.scriptPubKey);
}

CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, txout) ? txout.nValue : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += OutputGetChange(wallet, txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, bool avoid_reuse)
{
    auto& amount = wtx.m_amounts[type];
    if (!amount.IsCached(avoid_reuse)) {
        amount.Set(avoid_reuse, type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.GetTx()) : TxGetCredit(wallet, *wtx.GetTx()));
        wtx.m_is_cache_empty = false;
    }
    return amount.Get(avoid_reuse);
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse)
{
    AssertLockHeld(wallet.cs_wallet);

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    // GetBalance can assume transactions in mapWallet won't change
    return GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, avoid_reuse);
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse)
{
    if (wtx.GetTx()->vin.empty())
        return 0;

    return GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, avoid_reuse);
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, *wtx.GetTx());
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                  std::list<COutputEntry>& listReceived,
                  std::list<COutputEntry>& listSent, CAmount& nFee,
                  bool include_change)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = CachedTxGetDebit(wallet, wtx, /*avoid_reuse=*/false);

    LOCK(wallet.cs_wallet);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = wtx.GetTx()->GetValueOut();
        // BIP 462: value the inputs as consensus does, at the transaction's reference height.
        const std::optional<DemurrageDebit> demurrage_debit{CachedTxGetDemurrageDebit(wallet, wtx)};
        nFee = (demurrage_debit ? demurrage_debit->debit : nDebit) - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < wtx.GetTx()->vout.size(); ++i)
    {
        const CTxOut& txout = wtx.GetTx()->vout[i];
        bool ismine = wallet.IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            if (!include_change && OutputIsChange(wallet, txout))
                continue;
        }
        else if (!ismine)
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s",
                                    wtx.GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (ismine)
            listReceived.push_back(output);
    }

}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx)
{
    if (!wtx.m_cached_from_me.has_value()) {
        wtx.m_cached_from_me = wallet.IsFromMe(*wtx.GetTx());
    }
    return wtx.m_cached_from_me.value();
}

// NOLINTNEXTLINE(misc-no-recursion)
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<Txid>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);

    // This wtx is already trusted
    if (trusted_parents.contains(wtx.GetHash())) return true;

    if (wtx.isConfirmed()) return true;
    if (wtx.isBlockConflicted()) return false;
    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : wtx.GetTx()->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.GetWalletTx(txin.prevout.hash);
        if (parent == nullptr) return false;
        const CTxOut& parentOut = parent->GetTx()->vout[txin.prevout.n];
        // Check that this specific input being spent is trusted
        if (!wallet.IsMine(parentOut)) return false;
        // If we've already trusted this parent, continue
        if (trusted_parents.contains(parent->GetHash())) continue;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<Txid> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

/**
 * BIP 462: whether an input of @p tx that spends a taproot output by the key
 * path is signed with SIGHASH_DEMURRAGE. Consensus checks that signature, and
 * BIP 341 rejects its hash type, so the transaction is invalid on a chain that
 * does not apply BIP 462. Script-path spends are not considered: which of their
 * witness elements are signatures depends on the script.
 */
static bool HasDemurrageKeyPathSignature(const CTransaction& tx, const std::vector<CScript>& spent_scripts)
{
    if (spent_scripts.size() != tx.vin.size()) return false;
    for (size_t i{0}; i < tx.vin.size(); ++i) {
        if (!spent_scripts[i].IsPayToTaproot()) continue;
        const std::vector<std::vector<unsigned char>>& stack{tx.vin[i].scriptWitness.stack};
        size_t size{stack.size()};
        // The annex, if any, is the last element.
        if (size >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) --size;
        if (size != 1) continue;
        // A 64-byte signature uses SIGHASH_DEFAULT.
        if (stack[0].size() == 65 && (stack[0].back() & SIGHASH_DEMURRAGE)) return true;
    }
    return false;
}

std::optional<DemurrageDebit> CachedTxGetDemurrageDebit(const CWallet& wallet, const CWalletTx& wtx)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wtx.IsCoinBase()) return std::nullopt;
    const int activation_height{wallet.chain().getDemurrageActivationHeight()};
    const auto* conf{wtx.state<TxStateConfirmed>()};
    if (conf ? conf->confirmed_block_height < activation_height : wallet.GetLastBlockHeight() + 1 < activation_height) {
        return std::nullopt;
    }
    if (conf && wtx.m_cached_demurrage_debit && wtx.m_cached_demurrage_debit->first == conf->confirmed_block_hash) {
        return wtx.m_cached_demurrage_debit->second;
    }
    std::optional<DemurrageDebit> result;
    if (const auto values{wallet.chain().getDemurrageInputValues(*wtx.GetTx(), conf ? conf->confirmed_block_hash : uint256{}, conf ? conf->position_in_block : 0)}) {
        CAmount debit{0};
        for (size_t i{0}; i < wtx.GetTx()->vin.size(); ++i) {
            if (InputIsMine(wallet, wtx.GetTx()->vin[i])) debit += values->values.at(i);
        }
        result = DemurrageDebit{.ref_height = values->ref_height, .debit = debit,
                                .demurrage_signed = HasDemurrageKeyPathSignature(*wtx.GetTx(), values->script_pubkeys)};
    }
    // The coins a confirmed transaction spends are fixed; cache its valuation
    // for the block it is confirmed in.
    if (conf) {
        wtx.m_cached_demurrage_debit.emplace(conf->confirmed_block_hash, result);
        wtx.m_is_cache_empty = false;
    }
    return result;
}

bool TxDescendsFromDemurrageSignature(const CWallet& wallet, const CWalletTx& wtx, std::map<Txid, bool>& memo)
{
    AssertLockHeld(wallet.cs_wallet);
    if (const auto it{memo.find(wtx.GetHash())}; it != memo.end()) return it->second;
    const int activation_height{wallet.chain().getDemurrageActivationHeight()};
    // Depth first through the wallet transactions it spends, without recursion,
    // since a chain of them can be long. A transaction is in the memo, as
    // whether it has such a signature itself, while its inputs are followed.
    struct Frame {
        const CWalletTx* tx;
        size_t next_input;
    };
    std::vector<Frame> stack;
    const auto visit{[&](const CWalletTx& tx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet) {
        const std::optional<DemurrageDebit> debit{CachedTxGetDemurrageDebit(wallet, tx)};
        memo[tx.GetHash()] = debit && debit->demurrage_signed;
        // Neither a coinbase nor a transaction confirmed before activation, nor
        // the transactions they descend from, can have such a signature.
        const auto* conf{tx.state<TxStateConfirmed>()};
        const bool before_activation{conf && conf->confirmed_block_height < activation_height};
        stack.push_back({&tx, tx.IsCoinBase() || before_activation ? tx.GetTx()->vin.size() : 0});
    }};
    visit(wtx);
    while (!stack.empty()) {
        const CWalletTx& tx{*stack.back().tx};
        bool& result{memo.at(tx.GetHash())};
        size_t& next_input{stack.back().next_input};
        if (result || next_input == tx.GetTx()->vin.size()) {
            stack.pop_back();
            if (result && !stack.empty()) memo.at(stack.back().tx->GetHash()) = true;
            continue;
        }
        const CWalletTx* parent{wallet.GetWalletTx(tx.GetTx()->vin[next_input++].prevout.hash)};
        if (!parent) continue;
        if (const auto it{memo.find(parent->GetHash())}; it != memo.end()) {
            result = result || it->second;
            continue;
        }
        visit(*parent);
    }
    return memo.at(wtx.GetHash());
}

/** Longest chain of unconfirmed wallet transactions followed to derive a
 *  reference height (well above the mempool's ancestor limits). */
static constexpr int MAX_UNBROADCAST_DEPTH{100};

/**
 * BIP 462: the reference height of a wallet transaction that is neither
 * confirmed nor in the mempool (for example, one never broadcast): the highest
 * reference height among the coins it spends, looked up in the UTXO set and the
 * mempool, or derived the same way from the wallet transaction that created
 * them. Returns nullopt if a coin it spends is not found.
 */
static std::optional<uint32_t> UnbroadcastRefHeight(const CWallet& wallet, const CWalletTx& wtx, std::map<Txid, std::optional<uint32_t>>& memo, int depth)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (const auto it{memo.find(wtx.GetHash())}; it != memo.end()) return it->second;
    // Inserted before following the inputs, so that it reads as unknown while
    // they are being derived. References into a std::map stay valid.
    std::optional<uint32_t>& result{memo[wtx.GetHash()]};
    if (depth > MAX_UNBROADCAST_DEPTH || wtx.IsCoinBase() || wtx.isConfirmed()) return result;
    std::map<COutPoint, Coin> inputs;
    for (const CTxIn& txin : wtx.GetTx()->vin) inputs.try_emplace(txin.prevout);
    wallet.chain().findCoins(inputs);
    uint32_t ref_height{0};
    for (const auto& [prevout, coin] : inputs) {
        if (!coin.IsSpent()) {
            ref_height = std::max(ref_height, coin.nRefHeight);
            continue;
        }
        const CWalletTx* parent{wallet.GetWalletTx(prevout.hash)};
        if (!parent || prevout.n >= parent->GetTx()->vout.size()) return std::nullopt;
        const std::optional<uint32_t> parent_ref_height{UnbroadcastRefHeight(wallet, *parent, memo, depth + 1)};
        if (!parent_ref_height) return std::nullopt;
        ref_height = std::max(ref_height, *parent_ref_height);
    }
    result = ref_height;
    return result;
}

std::optional<uint64_t> GetDemurrageWalletIndex(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    // A wallet without a chain, or that has not processed a block yet, values nothing.
    if (!wallet.HaveChain() || !wallet.HaveLastBlock()) return std::nullopt;
    const int height{wallet.GetLastBlockHeight()};
    if (height + 1 < wallet.chain().getDemurrageActivationHeight()) return std::nullopt;
    return wallet.chain().getDemurrageIndex(height);
}

std::optional<DemurrageValuation> GetDemurrageValuation(const CWallet& wallet, const std::vector<COutPoint>& outpoints)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!wallet.HaveChain() || !wallet.HaveLastBlock()) return std::nullopt;
    const int height{wallet.GetLastBlockHeight()};
    const std::optional<uint64_t> index{GetDemurrageWalletIndex(wallet)};
    if (!index) return std::nullopt;
    DemurrageValuation valuation{.height = height, .index = *index, .coins = {}};

    std::map<COutPoint, Coin> coins;
    for (const COutPoint& outpoint : outpoints) coins.try_emplace(outpoint);
    wallet.chain().findCoins(coins);
    // Outputs of wallet transactions that are not in the mempool (for example,
    // never broadcast) are not found. Their reference height is their
    // transaction's, derived from the coins it spends.
    std::map<Txid, std::optional<uint32_t>> unbroadcast_ref_heights;
    for (auto& [outpoint, coin] : coins) {
        if (!coin.IsSpent()) continue;
        const CWalletTx* wtx{wallet.GetWalletTx(outpoint.hash)};
        if (!wtx || outpoint.n >= wtx->GetTx()->vout.size() || wtx->isConfirmed() || wallet.IsSpent(outpoint)) continue;
        if (const auto ref_height{UnbroadcastRefHeight(wallet, *wtx, unbroadcast_ref_heights, /*depth=*/0)}) {
            // Only the output and its reference height are used below.
            coin = Coin{wtx->GetTx()->vout[outpoint.n], /*nHeightIn=*/0, /*fCoinBaseIn=*/false};
            coin.nRefHeight = *ref_height;
        }
    }
    std::map<uint32_t, std::optional<uint64_t>> indexes;
    for (const auto& [outpoint, coin] : coins) {
        if (coin.IsSpent() || coin.nRefHeight > static_cast<uint32_t>(height)) continue;
        auto [it, inserted]{indexes.try_emplace(coin.nRefHeight)};
        if (inserted) it->second = wallet.chain().getDemurrageIndex(static_cast<int>(coin.nRefHeight));
        if (!it->second) continue;
        valuation.coins.emplace(outpoint, DemurrageValuation::CoinInfo{.nominal = coin.out.nValue, .ref_height = coin.nRefHeight, .index_created = *it->second});
    }
    return valuation;
}

std::optional<DemurrageInputFields> GetDemurrageInputFields(const CWallet& wallet, const std::vector<COutPoint>& outpoints)
{
    AssertLockHeld(wallet.cs_wallet);
    if (outpoints.empty()) return std::nullopt;
    const std::optional<DemurrageValuation> valuation{GetDemurrageValuation(wallet, outpoints)};
    if (!valuation) return std::nullopt;
    const int activation_height{wallet.chain().getDemurrageActivationHeight()};
    // The transaction's reference height is the highest among the coins it
    // spends, and its index, I(ref_height), the lowest of theirs.
    std::vector<const DemurrageValuation::CoinInfo*> coins;
    uint32_t ref_height{0};
    uint64_t tx_index{demurrage::INDEX_ONE};
    for (const COutPoint& outpoint : outpoints) {
        const auto it{valuation->coins.find(outpoint)};
        if (it == valuation->coins.end()) return std::nullopt;
        coins.push_back(&it->second);
        ref_height = std::max(ref_height, it->second.ref_height);
        tx_index = std::min(tx_index, it->second.index_created);
    }
    DemurrageInputFields fields{.ref_heights = {}, .values = {}, .committed_ref_height = demurrage::CommittedRefHeight(ref_height, activation_height)};
    for (const DemurrageValuation::CoinInfo* coin : coins) {
        fields.ref_heights.push_back(demurrage::CommittedRefHeight(coin->ref_height, activation_height));
        fields.values.push_back(demurrage::EffectiveValue(coin->nominal, coin->index_created, tx_index));
    }
    return fields;
}

std::optional<CAmount> GetEffectiveOutputValue(const COutPoint& outpoint, const DemurrageValuation& valuation)
{
    const auto it{valuation.coins.find(outpoint)};
    if (it == valuation.coins.end()) return std::nullopt;
    return demurrage::EffectiveValue(it->second.nominal, it->second.index_created, valuation.index);
}

bool ConvertOutputsToRefHeight(CMutableTransaction& tx, const DemurrageValuation& valuation, std::optional<unsigned int> change_pos,
                               const std::map<unsigned int, DemurrageFixedOutput>& fixed_outputs,
                               const std::optional<DemurrageFeeFloor>& fee_floor)
{
    // I(ref_height) is the lowest index among the inputs (the index never rises).
    uint64_t tx_index{demurrage::INDEX_ONE};
    std::vector<const DemurrageValuation::CoinInfo*> inputs;
    for (const CTxIn& txin : tx.vin) {
        const auto it{valuation.coins.find(txin.prevout)};
        if (it == valuation.coins.end()) return false;
        inputs.push_back(&it->second);
        tx_index = std::min(tx_index, it->second.index_created);
    }
    CAmount value_in{0};
    for (const auto* coin : inputs) value_in += demurrage::EffectiveValue(coin->nominal, coin->index_created, tx_index);
    CAmount value_out{0};
    for (unsigned int pos{0}; pos < tx.vout.size(); ++pos) {
        CTxOut& txout{tx.vout[pos]};
        // An output with a fixed nominal amount is re-expressed from its own
        // index, so that it is unchanged if the reference height is.
        const auto fixed{fixed_outputs.find(pos)};
        const std::optional<CAmount> value{fixed == fixed_outputs.end() ?
                                           demurrage::ConvertValue(txout.nValue, valuation.index, tx_index) :
                                           demurrage::ConvertValue(fixed->second.nominal, fixed->second.index, tx_index)};
        if (!value || !MoneyRange(*value)) return false;
        txout.nValue = *value;
        value_out += txout.nValue;
    }
    // Rounding can only cost the inputs a few satoshis; take them from the change.
    if (value_out > value_in) {
        if (!change_pos || tx.vout.at(*change_pos).nValue < value_out - value_in) return false;
        tx.vout.at(*change_pos).nValue -= value_out - value_in;
        value_out = value_in;
    }
    // The mempool measures a fee as fee_effective in the next block. Rounding,
    // and that block's demurrage, can leave it a few satoshis below the fee
    // that was computed at the wallet's last block.
    if (fee_floor && change_pos && fee_floor->index > 0 && fee_floor->index <= tx_index) {
        const CAmount fee{value_in - value_out};
        std::optional<CAmount> needed{demurrage::ConvertValue(fee_floor->fee, fee_floor->index, tx_index)};
        if (!needed) return false;
        while (demurrage::EffectiveValue(*needed, tx_index, fee_floor->index) < fee_floor->fee) ++*needed;
        CTxOut& change{tx.vout.at(*change_pos)};
        if (*needed > fee && change.nValue >= *needed - fee) change.nValue -= *needed - fee;
    }
    return true;
}

CAmount GetEffectiveTxOutValue(const CWallet& wallet, const CWalletTx& wtx, CAmount nominal)
{
    AssertLockHeld(wallet.cs_wallet);
    const std::optional<uint64_t> index{GetDemurrageWalletIndex(wallet)};
    if (!index) return nominal;
    // The index at which the transaction's amounts are expressed: I(reference height).
    std::optional<uint64_t> tx_index;
    const auto* conf{wtx.state<TxStateConfirmed>()};
    if (conf && conf->confirmed_block_height < wallet.chain().getDemurrageActivationHeight()) {
        tx_index = demurrage::INDEX_ONE;
    } else if (wtx.IsCoinBase()) {
        // A coinbase output's reference height is the height of its block.
        if (conf) tx_index = wallet.chain().getDemurrageIndex(conf->confirmed_block_height);
    } else if (const auto debit{CachedTxGetDemurrageDebit(wallet, wtx)}) {
        tx_index = wallet.chain().getDemurrageIndex(static_cast<int>(debit->ref_height));
    }
    if (!tx_index || *index > *tx_index) return nominal;
    return demurrage::EffectiveValue(nominal, *tx_index, *index);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse, bool include_nonmempool)
{
    Balance ret;
    bool allow_used_addresses = !avoid_reuse || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    {
        LOCK(wallet.cs_wallet);
        // BIP 462: report effective values at the wallet's last processed block
        std::vector<COutPoint> outpoints;
        outpoints.reserve(wallet.GetTXOs().size());
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) outpoints.push_back(outpoint);
        const std::optional<DemurrageValuation> demurrage_valuation{GetDemurrageValuation(wallet, outpoints)};
        std::set<Txid> trusted_parents;
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
            const CWalletTx& wtx = txo.GetWalletTx();

            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};

            bool nonmempool_spent = false;
            switch (wallet.HowSpent(outpoint)) {
            case CWallet::SpendType::CONFIRMED:
            case CWallet::SpendType::MEMPOOL:
                // treat as spent; ignore
                break;
            case CWallet::SpendType::NONMEMPOOL:
                if (!include_nonmempool) break;
                nonmempool_spent = true;
                [[fallthrough]];
            case CWallet::SpendType::UNSPENT:
                CAmount* bucket = nullptr;

                // Set the amounts in the return object
                if (wallet.IsTxImmatureCoinBase(wtx) && wtx.isConfirmed()) {
                    bucket = &ret.m_mine_immature;
                } else if (is_trusted && tx_depth >= min_depth) {
                    bucket = &ret.m_mine_trusted;
                } else if (!is_trusted && wtx.InMempool()) {
                    bucket = &ret.m_mine_untrusted_pending;
                }
                if (bucket) {
                    // Get the amounts for mine
                    CAmount credit_mine = txo.GetTxOut().nValue;
                    if (demurrage_valuation) {
                        credit_mine = GetEffectiveOutputValue(outpoint, *demurrage_valuation).value_or(credit_mine);
                    }

                    if (!allow_used_addresses && wallet.IsSpentKey(txo.GetTxOut().scriptPubKey)) {
                        bucket = &ret.m_mine_used;
                    }
                    *bucket += credit_mine;
                    if (nonmempool_spent) {
                        ret.m_mine_nonmempool -= credit_mine;
                    }
                }
            }
        }
    }
    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        // BIP 462: report effective values at the wallet's last processed block, like GetBalance()
        std::vector<COutPoint> outpoints;
        outpoints.reserve(wallet.GetTXOs().size());
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) outpoints.push_back(outpoint);
        const std::optional<DemurrageValuation> demurrage_valuation{GetDemurrageValuation(wallet, outpoints)};
        std::set<Txid> trusted_parents;
        for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
            const CWalletTx& wtx = txo.GetWalletTx();

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents)) continue;
            if (wallet.IsTxImmatureCoinBase(wtx)) continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx) ? 0 : 1)) continue;

            CTxDestination addr;
            Assume(wallet.IsMine(txo.GetTxOut()));
            if(!ExtractDestination(txo.GetTxOut().scriptPubKey, addr)) continue;

            CAmount n = wallet.IsSpent(outpoint) ? 0 : txo.GetTxOut().nValue;
            if (n > 0 && demurrage_valuation) {
                n = GetEffectiveOutputValue(outpoint, *demurrage_valuation).value_or(n);
            }
            balances[addr] += n;
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > GetAddressGroupings(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet)
    {
        const CWalletTx& wtx = walletEntry.second;

        if (wtx.GetTx()->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : wtx.GetTx()->vin)
            {
                CTxDestination address;
                if(!InputIsMine(wallet, txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(wallet.mapWallet.at(txin.prevout.hash).GetTx()->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               for (const CTxOut& txout : wtx.GetTx()->vout)
                   if (OutputIsChange(wallet, txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : wtx.GetTx()->vout)
            if (wallet.IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (const std::set<CTxDestination>& _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}
} // namespace wallet
