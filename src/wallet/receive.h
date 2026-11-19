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
#include <optional>

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
 * BIP 462: valuation of wallet outputs as inputs of a version 4 transaction
 * with reference height @ref ref_height.
 */
struct DemurrageValuation {
    int activation_height;
    //! Reference height of transactions the wallet creates: the wallet's last
    //! processed block (or the activation height, if that is higher).
    int ref_height;
    //! I(ref_height)
    uint64_t ref_index;
};

/** BIP 462 valuation at the wallet's last processed block, if BIP 462 applies to the next block. */
std::optional<DemurrageValuation> GetDemurrageValuation(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: effective value of @p txout, an output of @p wtx, as an input
 *  valued at @p valuation's reference height. Returns nullopt if the output
 *  cannot be spent at that reference height (its own reference height is
 *  higher or unknown). */
std::optional<CAmount> GetEffectiveOutputValue(const CWallet& wallet, const CWalletTx& wtx, const CTxOut& txout, const DemurrageValuation& valuation)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Wallet balance. Once BIP 462 is active, balances are effective values at
 *  the wallet's last processed block. */
Balance GetBalance(const CWallet& wallet, int min_depth = 0, bool avoid_reuse = true, bool include_nonmempool = false);

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet);
std::set<std::set<CTxDestination>> GetAddressGroupings(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} // namespace wallet

#endif // BITCOIN_WALLET_RECEIVE_H
