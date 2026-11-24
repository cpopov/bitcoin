// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DEMURRAGE_H
#define BITCOIN_CONSENSUS_DEMURRAGE_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

class CScript;
class CTransaction;

namespace Consensus {
struct Params;
} // namespace Consensus

/**
 * BIP 462: Target-Based Demurrage Security Budget.
 *
 * All arithmetic is fixed-point integer arithmetic, rounding down (towards
 * zero) at every step. No floating point is used.
 *
 * - The demurrage index I(h) and the per-block rate r(h) are fixed-point
 *   numbers with scale INDEX_ONE, so that I = INDEX_ONE means 1.0. I(h) is
 *   INDEX_ONE for every height before activation.
 * - Every output has a reference height. A coinbase output's is the height of
 *   its block; any other output's is its transaction's, which is the highest
 *   reference height among the outputs the transaction spends. An output's
 *   I_created is I(reference height).
 * - The UTXO set's effective value is tracked through its "normalized" total
 *   N = sum(floor(v * INDEX_ONE^2 / I_created)) over all unspent outputs, so
 *   that U(h) = floor(N * I(h) / INDEX_ONE^2). N is held as a 256-bit integer.
 */
namespace demurrage {

/** Fixed-point scale of the demurrage index and of the per-block rate (1e18). */
inline constexpr uint64_t INDEX_ONE{1'000'000'000'000'000'000ULL};

/** INDEX_MIN: once the index is at or below it, the rate is zero, so the index
 *  never reaches zero and every division by an index is defined. */
inline constexpr uint64_t INDEX_MIN{1'000'000'000ULL};

/** "Activation block": bit 31 of the header version, which the block at
 *  ACTIVATION_HEIGHT must set and no other block can. */
inline constexpr uint32_t ACTIVATION_VERSION_BIT{0x80000000U};

/** "Block timestamps" (BIP 54): the first block of a difficulty adjustment
 *  period may be at most this many seconds earlier than its parent. */
inline constexpr int64_t MAX_TIMEWARP_SECONDS{7200};

/** COMMITMENT_HEADER: the first four bytes of SHA256("BIP462"). */
inline constexpr std::array<uint8_t, 4> COMMITMENT_HEADER{0x99, 0x96, 0xb0, 0xb3};

/** Minimum size of the scriptPubKey that holds a demurrage commitment:
 *  OP_RETURN, a push of 36 bytes, COMMITMENT_HEADER and the commitment. */
inline constexpr size_t MINIMUM_COMMITMENT_SCRIPT_SIZE{38};

/** True if BIP 462 rules apply to the block at @p height. */
bool IsActive(int height, const Consensus::Params& params);

/**
 * Rate r(h) of a block:
 *   target    = floor(U * TARGET_NUM / TARGET_DEN)
 *   shortfall = max(0, target - subsidy)
 *   r         = floor(shortfall * INDEX_ONE / U)
 * @param[in] utxo_value U(h - 1), the effective value of the UTXO set after the block's parent.
 * @param[in] subsidy    block_subsidy(h), the amount the halving schedule entitles the block to.
 * @param[in] prev_index I(h - 1)
 * Returns 0 when U is 0 or when I(h - 1) <= INDEX_MIN. The result never
 * exceeds the target rate.
 */
uint64_t ComputeRate(CAmount utxo_value, CAmount subsidy, uint64_t prev_index, const Consensus::Params& params);

/** I(h) = floor(I(h-1) * (INDEX_ONE - r) / INDEX_ONE). */
uint64_t NextIndex(uint64_t prev_index, uint64_t rate);

/** floor(value * index_at / index_created): the value of an output created
 *  at index_created, measured at index_at (index_at <= index_created). Also
 *  used for fee_effective = floor(fee * I(h) / I(ref_height)). */
CAmount EffectiveValue(CAmount nominal, uint64_t index_created, uint64_t index_at);

/** floor(value * to_index / from_index): an amount expressed at from_index,
 *  re-expressed at to_index, in either direction (used by wallets to convert
 *  amounts between reference heights). Returns nullopt on overflow. */
std::optional<CAmount> ConvertValue(CAmount value, uint64_t from_index, uint64_t to_index);

/** floor(nominal * INDEX_ONE^2 / index_created): an output's contribution to N. */
arith_uint256 NormalizedValue(CAmount nominal, uint64_t index_created);

/** U = floor(N * index / INDEX_ONE^2). */
CAmount UtxoValue(const arith_uint256& normalized_total, uint64_t index);

/** demurrage_dividend = floor(r * U(h-1) / INDEX_ONE). */
CAmount Dividend(uint64_t rate, CAmount utxo_value);

/**
 * Demurrage state after a block at or above ACTIVATION_HEIGHT - 1. Every field
 * is a deterministic function of the chain up to and including that block,
 * so it can be cached per block index entry, just like nChainWork.
 */
struct BlockState {
    //! I(h), the demurrage index after this block.
    uint64_t index{INDEX_ONE};
    //! r(h), the rate of this block.
    uint64_t rate{0};
    //! N(h), the normalized value of the UTXO set after this block.
    arith_uint256 normalized_utxo{};

    //! U(h), the effective value of the UTXO set after this block.
    CAmount UtxoValue() const { return demurrage::UtxoValue(normalized_utxo, index); }

    friend bool operator==(const BlockState&, const BlockState&) = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << index << rate << ArithToUint256(normalized_utxo);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint256 n;
        s >> index >> rate >> n;
        normalized_utxo = UintToArith256(n);
    }
};

/** State after ACTIVATION_HEIGHT - 1, whose UTXO set has total value
 *  @p utxo_value and in which every output has I_created = INDEX_ONE. */
BlockState BaselineState(CAmount utxo_value);

/** Values fixed before a post-activation block's transactions are validated. */
struct BlockContext {
    //! I(h)
    uint64_t index{INDEX_ONE};
    //! r(h)
    uint64_t rate{0};
    //! U(h-1)
    CAmount prev_utxo_value{0};
    //! demurrage_dividend(h)
    CAmount dividend{0};
};

/** Compute the context of a post-activation block from the state after its
 *  parent and from @p subsidy, the block's subsidy under the halving schedule. */
BlockContext ComputeBlockContext(const BlockState& prev, CAmount subsidy, const Consensus::Params& params);

/** Normalized values of the outputs a block spends and adds to the UTXO set. */
struct BlockTotals {
    arith_uint256 normalized_spent{};
    arith_uint256 normalized_created{};
};

/** State after a post-activation block, given the state after its parent. */
BlockState ComputeBlockState(const BlockState& prev, const BlockContext& ctx, const BlockTotals& totals);

/** The values of a transaction's inputs, as consensus values them. */
struct InputValues {
    //! The transaction's reference height: the highest among the outputs it spends.
    uint32_t ref_height{0};
    //! Each input's value at the transaction's reference height, in input order.
    std::vector<CAmount> values;
    //! The reference height of the output each input spends, in input order.
    std::vector<uint32_t> ref_heights;
    //! The scriptPubKey of the output each input spends, in input order.
    std::vector<CScript> script_pubkeys;
};

/** A reference height in committed form: every height below ACTIVATION_HEIGHT
 *  is written as ACTIVATION_HEIGHT - 1, since all of them are equivalent. */
uint32_t CommittedRefHeight(uint32_t ref_height, int activation_height);

/** leaf(tx) = SHA256d(txid || reference height in committed form). */
uint256 CommitmentLeaf(const uint256& txid, uint32_t committed_ref_height);

/** The leaf of the coinbase of the block at @p height: 32 zero bytes in place
 *  of its txid, and the block's height as its reference height. */
uint256 CoinbaseCommitmentLeaf(int height);

/**
 * commitment(h) = SHA256d(I(h) || r(h) || N(h - 1) || ref_height_root), where
 * ref_height_root is the Merkle root of @p leaves, computed as the block's
 * transaction Merkle root is.
 * @param[in] prev   state after the block's parent
 * @param[in] ctx    context of the block
 * @param[in] leaves the leaf of each of the block's transactions, in block order
 */
uint256 Commitment(const BlockState& prev, const BlockContext& ctx, std::vector<uint256> leaves);

/** scriptPubKey of the coinbase output that holds @p commitment. */
CScript CommitmentScript(const uint256& commitment);

/** True if @p script has the form of a demurrage commitment: at least 38
 *  bytes, beginning with OP_RETURN, a push of 36 bytes and COMMITMENT_HEADER. */
bool IsCommitmentScript(const CScript& script);

/** Index of the coinbase output that holds the block's demurrage commitment
 *  (the last one that matches), or nullopt if there is none. */
std::optional<size_t> GetCommitmentIndex(const CTransaction& coinbase);

/** The commitment a coinbase carries, or nullopt if it has none. */
std::optional<uint256> GetCommitment(const CTransaction& coinbase);

/** Returns I(h) for a height on the chain being validated, or nullopt if unknown. */
using IndexLookup = std::function<std::optional<uint64_t>(int height)>;

/** What transaction validation needs to apply BIP 462 at a given spend height. */
struct TxContext {
    //! ACTIVATION_HEIGHT
    int activation_height;
    //! Height of the block that includes (or will include) the transaction.
    int spend_height;
    //! I(h) for every h <= spend_height (INDEX_ONE for h < activation_height).
    IndexLookup index_at;
};

} // namespace demurrage

#endif // BITCOIN_CONSENSUS_DEMURRAGE_H
