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

/** BIP 462: an output whose amount is nominal at a given demurrage index,
 *  rather than an effective value at the wallet's last processed block (see
 *  CRecipient::demurrage_index). */
struct DemurrageFixedOutput {
    CAmount nominal;
    uint64_t index;
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

/**
 * BIP 462: whether @p wtx, or a wallet transaction that it descends from
 * (through the wallet transactions it spends), has an input that spends a
 * taproot output by the key path with a SIGHASH_DEMURRAGE signature (see
 * DemurrageDebit::demurrage_signed). Such a transaction is invalid on a chain
 * that does not apply BIP 462, so the outputs of @p wtx exist only on a chain
 * that does. @p memo holds the transactions already looked at.
 */
bool TxDescendsFromDemurrageSignature(const CWallet& wallet, const CWalletTx& wtx, std::map<Txid, bool>& memo) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: I(h) at the wallet's last processed block, at which the wallet
 *  values amounts, if BIP 462 applies to the block after it. */
std::optional<uint64_t> GetDemurrageWalletIndex(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: if BIP 462 applies to the block after the wallet's last processed
 *  block, look up @p outpoints and return their valuation at that block. */
std::optional<DemurrageValuation> GetDemurrageValuation(const CWallet& wallet, const std::vector<COutPoint>& outpoints) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: what a signer needs to sign a transaction with SIGHASH_DEMURRAGE
 *  and to know its fee: the PSBT input fields. */
struct DemurrageInputFields {
    //! The reference height of each coin spent, in committed form, in input order.
    std::vector<uint32_t> ref_heights;
    //! The value of each coin at the transaction's reference height, in input order.
    std::vector<CAmount> values;
    //! The transaction's reference height, in committed form.
    uint32_t committed_ref_height;
};

/** BIP 462: the input fields of a transaction that spends @p outpoints, in
 *  order, if BIP 462 applies to the block after the wallet's last processed
 *  block and every coin is found (see GetDemurrageValuation()). */
std::optional<DemurrageInputFields> GetDemurrageInputFields(const CWallet& wallet, const std::vector<COutPoint>& outpoints) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** BIP 462: the least fee a transaction should pay, measured as the mempool
 *  measures it: as fee_effective at @p index, the index of the next block. */
struct DemurrageFeeFloor {
    CAmount fee;
    uint64_t index;
};

/** BIP 462: effective value of @p outpoint at @p valuation's height, or
 *  nullopt if the coin was not found. */
std::optional<CAmount> GetEffectiveOutputValue(const COutPoint& outpoint, const DemurrageValuation& valuation);

/**
 * BIP 462: re-express the outputs of @p tx, whose amounts are effective values
 * at @p valuation's height, at the transaction's reference height, the highest
 * reference height among its inputs (all of which must be in @p valuation).
 * The effective value each output delivers, and the fee, are unchanged up to
 * rounding. The outputs at the positions in @p fixed_outputs are instead set to
 * their nominal amount, re-expressed from its own index. If @p fee_floor is
 * set and there is a change output, the few satoshis by which rounding and the
 * next block's demurrage leave the fee below the floor are taken from the
 * change. Returns false if an input is unknown or the outputs would exceed the
 * inputs.
 */
bool ConvertOutputsToRefHeight(CMutableTransaction& tx, const DemurrageValuation& valuation, std::optional<unsigned int> change_pos,
                               const std::map<unsigned int, DemurrageFixedOutput>& fixed_outputs = {},
                               const std::optional<DemurrageFeeFloor>& fee_floor = std::nullopt);

/**
 * BIP 462: the effective value, at the wallet's last processed block, of an
 * output of @p wtx with nominal value @p nominal, whether or not the output is
 * still unspent. Returns @p nominal if BIP 462 does not apply yet, or if the
 * transaction's reference height cannot be determined (for example, if its
 * block's undo data was pruned).
 */
CAmount GetEffectiveTxOutValue(const CWallet& wallet, const CWalletTx& wtx, CAmount nominal) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Wallet balance. Once BIP 462 is active, balances are effective values at
 *  the wallet's last processed block. */
Balance GetBalance(const CWallet& wallet, int min_depth = 0, bool avoid_reuse = true, bool include_nonmempool = false);

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet);
std::set<std::set<CTxDestination>> GetAddressGroupings(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} // namespace wallet

#endif // BITCOIN_WALLET_RECEIVE_H
