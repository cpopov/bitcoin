// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RECEIVE_H
#define BITCOIN_WALLET_RECEIVE_H

#include <consensus/amount.h>
#include <primitives/transaction_identifier.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace wallet {
bool InputIsMine(const CWallet& wallet, const CTxIn& txin) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Returns whether all of the inputs belong to the wallet*/
bool AllInputsMine(const CWallet& wallet, const CTransaction& tx);

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout);
CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx);

bool ScriptIsChange(const CWallet& wallet, const CScript& script) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
bool OutputIsChange(const CWallet& wallet, const CTxOut& txout) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx);

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, bool avoid_reuse);
CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx);
struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};
void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                        std::list<COutputEntry>& listReceived,
                        std::list<COutputEntry>& listSent,
                        CAmount& nFee,
                        bool include_change);
bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx);
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<Txid>& trusted_parents) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx);

struct Balance {
    CAmount m_mine_trusted{0};           //!< Trusted, at depth=GetBalance.min_depth or more
    CAmount m_mine_untrusted_pending{0}; //!< Untrusted, but in mempool (pending)
    CAmount m_mine_immature{0};          //!< Immature coinbases in the main chain
    CAmount m_mine_used{0};              //!< Trusted/untrusted/immature funds in utxos that have already been spent from (only populated if AVOID REUSE wallet flag is set)
    CAmount m_mine_nonmempool{0};        //!< Coins spent by wallet txs that are not in the mempool
};
/**
 * BIP 462: valuation of coins at the demurrage index of the wallet's last
 * processed block. Every coin's reference height (and so its I_created) is
 * determined by the chain, so the coins are looked up through the node.
 */
struct DemurrageValuation {
    //! The wallet's last processed block, at whose index amounts are valued.
    int height;
    //! I(height)
    uint64_t index;
    //! A coin found in the UTXO set or the mempool.
    struct CoinInfo {
        CAmount nominal;
        uint32_t ref_height;
        //! I_created = I(ref_height)
        uint64_t index_created;
    };
    std::map<COutPoint, CoinInfo> coins;
};

/**
 * BIP 462: the wallet's debit from @p wtx, with its inputs valued as consensus
 * values them, at the transaction's reference height (the unit in which the
 * transaction's own amounts are written), and that height. Returns nullopt if
 * BIP 462 does not apply to the transaction or its inputs cannot be valued
 * (for example, if its block's undo data was pruned); the nominal debit then
 * applies.
 */
std::optional<DemurrageDebit> CachedTxGetDemurrageDebit(const CWallet& wallet, const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: if BIP 462 applies to the block after the wallet's last processed
 *  block, look up @p outpoints and return their valuation at that block. */
std::optional<DemurrageValuation> GetDemurrageValuation(const CWallet& wallet, const std::vector<COutPoint>& outpoints) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: effective value of @p outpoint at @p valuation's height, or
 *  nullopt if the coin was not found. */
std::optional<CAmount> GetEffectiveOutputValue(const COutPoint& outpoint, const DemurrageValuation& valuation);

/**
 * BIP 462: re-express the outputs of @p tx, whose amounts are effective values
 * at @p valuation's height, at the transaction's reference height, the highest
 * reference height among its inputs (all of which must be in @p valuation).
 * The effective value each output delivers, and the fee, are unchanged up to
 * rounding. Returns false if an input is unknown or the outputs would exceed
 * the inputs.
 */
bool ConvertOutputsToRefHeight(CMutableTransaction& tx, const DemurrageValuation& valuation, std::optional<unsigned int> change_pos);

/** Wallet balance. Once BIP 462 is active, balances are effective values at
 *  the wallet's last processed block. */
Balance GetBalance(const CWallet& wallet, int min_depth = 0, bool avoid_reuse = true, bool include_nonmempool = false);

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet);
std::set<std::set<CTxDestination>> GetAddressGroupings(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} // namespace wallet

#endif // BITCOIN_WALLET_RECEIVE_H
