// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DEMURRAGE_H
#define BITCOIN_CONSENSUS_DEMURRAGE_H

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <optional>

namespace Consensus {
struct Params;
} // namespace Consensus

/**
 * BIP 462: Target-Based Demurrage Security Budget.
 *
 * All arithmetic is fixed-point integer arithmetic, rounding down (towards
 * zero) at every step. No floating point is used.
 *
 * - The demurrage index I(h) and the per-block rate r_k are fixed-point
 *   numbers with scale INDEX_ONE, so that I = INDEX_ONE means 1.0.
 * - The UTXO set's effective value is tracked through its "normalized" total
 *   N = sum(floor(v * INDEX_ONE^2 / I_created)) over all unspent outputs, so
 *   that U(h) = floor(N * I(h) / INDEX_ONE^2). N is held as a 256-bit integer.
 */
namespace demurrage {

/** Fixed-point scale of the demurrage index and of the per-block rate (1e18). */
inline constexpr uint64_t INDEX_ONE{1'000'000'000'000'000'000ULL};

/** True if BIP 462 rules apply to the block at @p height. */
bool IsActive(int height, const Consensus::Params& params);

/** First height whose subsidy and fees are tracked: the start of the period
 *  preceding activation (BIP 462: "the 2,016 blocks preceding activation"). */
int TrackingStartHeight(const Consensus::Params& params);

/** True if @p height begins a rate period (ACTIVATION_HEIGHT + k * RATE_PERIOD). */
bool IsRatePeriodStart(int height, const Consensus::Params& params);

/**
 * Per-block rate r_k for a rate period:
 *   target    = floor(U * RATE_PERIOD * TARGET_NUM / TARGET_DEN)
 *   shortfall = max(0, target - covered)
 *   r         = floor(shortfall * INDEX_ONE / (RATE_PERIOD * U))
 * @param[in] utxo_value U_k, the effective value of the UTXO set at H_k - 1.
 * @param[in] covered    subsidy plus fees of the previous rate period.
 * Returns 0 when U_k is 0. The result never exceeds the target rate.
 */
uint64_t ComputeRate(CAmount utxo_value, CAmount covered, const Consensus::Params& params);

/** I(h) = floor(I(h-1) * (INDEX_ONE - r) / INDEX_ONE). */
uint64_t NextIndex(uint64_t prev_index, uint64_t rate);

/** floor(nominal * index_at / index_created): the value of an output created
 *  at index_created, measured at index_at (index_at <= index_created). Also
 *  used for fee_effective = floor(fee * I(h) / I(ref_height)). */
CAmount EffectiveValue(CAmount nominal, uint64_t index_created, uint64_t index_at);

/** floor(nominal * INDEX_ONE^2 / index_created): an output's contribution to N. */
arith_uint256 NormalizedValue(CAmount nominal, uint64_t index_created);

/** U = floor(N * index / INDEX_ONE^2). */
CAmount UtxoValue(const arith_uint256& normalized_total, uint64_t index);

/** demurrage_dividend = floor(r * U(h-1) / INDEX_ONE). */
CAmount Dividend(uint64_t rate, CAmount utxo_value);

/** pool_payout = floor(pool / FEE_POOL_DIVISOR). */
CAmount PoolPayout(CAmount pool, const Consensus::Params& params);

/**
 * Demurrage state after a block. Every field is a deterministic function of
 * the chain up to and including that block, so it can be cached per block
 * index entry, just like nChainWork.
 */
struct BlockState {
    //! I(h), the demurrage index after this block.
    uint64_t index{INDEX_ONE};
    //! r_k, the per-block rate of the rate period containing this block.
    uint64_t rate{0};
    //! pool(h), the fee pool balance after this block.
    CAmount pool{0};
    //! N(h), the normalized value of the UTXO set after this block.
    //! Only meaningful if has_utxo_total is set.
    arith_uint256 normalized_utxo{};
    bool has_utxo_total{false};
    //! Block subsidy of the rate period containing this block, up to and including it.
    CAmount period_subsidy{0};
    //! fee_effective paid into the pool during the rate period containing this block, up to and including it.
    CAmount period_fees{0};

    //! U(h), the effective value of the UTXO set after this block.
    CAmount UtxoValue() const { return demurrage::UtxoValue(normalized_utxo, index); }

    friend bool operator==(const BlockState&, const BlockState&) = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << index << rate << pool << ArithToUint256(normalized_utxo) << has_utxo_total << period_subsidy << period_fees;
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint256 n;
        s >> index >> rate >> pool >> n >> has_utxo_total >> period_subsidy >> period_fees;
        normalized_utxo = UintToArith256(n);
    }
};

/** Values fixed before a post-activation block's transactions are validated. */
struct BlockContext {
    //! I(h)
    uint64_t index{INDEX_ONE};
    //! r_k
    uint64_t rate{0};
    //! U(h-1)
    CAmount prev_utxo_value{0};
    //! demurrage_dividend(h)
    CAmount dividend{0};
    //! pool_payout(h)
    CAmount pool_payout{0};
    //! True if this block begins a rate period (and @ref rate was recomputed).
    bool period_start{false};
};

/** Compute the context of the post-activation block at @p height from the
 *  state after its parent. Requires prev.has_utxo_total. */
BlockContext ComputeBlockContext(const BlockState& prev, int height, const Consensus::Params& params);

/** Totals accumulated while connecting a block's transactions. */
struct BlockTotals {
    //! Block subsidy at this height (from the halving schedule).
    CAmount subsidy{0};
    //! Sum of fee_effective (post-activation) or of fees (pre-activation).
    CAmount fees{0};
    //! Normalized value of the outputs spent by the block.
    arith_uint256 normalized_spent{};
    //! Normalized value of the outputs added to the UTXO set by the block.
    arith_uint256 normalized_created{};
};

/**
 * State after the block at @p height, given the state after its parent.
 * @param[in] prev  State after the parent, or nullptr if the parent is below
 *                  the tracking start height.
 * @param[in] ctx   Block context; required iff the block is post-activation.
 */
BlockState ComputeBlockState(const BlockState* prev, const BlockContext* ctx, int height, const BlockTotals& totals, const Consensus::Params& params);

/** Returns I(h) for a height on the chain being validated, or nullopt if unknown. */
using IndexLookup = std::function<std::optional<uint64_t>(int height)>;

/** What transaction validation needs to apply BIP 462 at a given spend height. */
struct TxContext {
    //! ACTIVATION_HEIGHT
    int activation_height;
    //! Height of the block that includes (or will include) the transaction.
    int spend_height;
    //! I(h) for activation_height - 1 <= h <= spend_height.
    IndexLookup index_at;
};

/** Minimum reference height of a transaction spending @p coin_height / @p coin_ref_height
 *  (BIP 462 rule 1): ACTIVATION_HEIGHT for outputs created before activation,
 *  otherwise the output's reference height. */
int MinRefHeightForCoin(uint32_t coin_height, uint32_t coin_ref_height, int activation_height);

/** I_created of a coin: 1.0 for outputs created before activation (I(ACTIVATION_HEIGHT - 1)),
 *  otherwise I at the coin's reference height. */
std::optional<uint64_t> CoinIndex(uint32_t coin_height, uint32_t coin_ref_height, const TxContext& ctx);

} // namespace demurrage

#endif // BITCOIN_CONSENSUS_DEMURRAGE_H
