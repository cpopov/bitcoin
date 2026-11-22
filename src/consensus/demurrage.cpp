// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/demurrage.h>

#include <consensus/params.h>
#include <util/check.h>


namespace demurrage {
namespace {
/** floor(a * b / c) for non-negative 64-bit operands, computed exactly in 256 bits. */
uint64_t MulDiv(uint64_t a, uint64_t b, uint64_t c)
{
    Assert(c != 0);
    const arith_uint256 r{(arith_uint256{a} * arith_uint256{b}) / arith_uint256{c}};
    Assert(r.bits() <= 64);
    return r.GetLow64();
}

const arith_uint256 INDEX_ONE_SQUARED{arith_uint256{INDEX_ONE} * arith_uint256{INDEX_ONE}};
} // namespace

bool IsActive(int height, const Consensus::Params& params)
{
    return height >= params.DemurrageHeight;
}

bool IsRatePeriodStart(int height, const Consensus::Params& params)
{
    return IsActive(height, params) && (height - params.DemurrageHeight) % params.nDemurrageRatePeriod == 0;
}

uint64_t ComputeRate(CAmount utxo_value, CAmount covered, const Consensus::Params& params)
{
    Assert(utxo_value >= 0 && covered >= 0);
    Assert(params.nDemurrageTargetRateNum >= 0 && params.nDemurrageTargetRateDen > 0 && params.nDemurrageRatePeriod > 0);
    if (utxo_value == 0) return 0;
    const arith_uint256 period_value{arith_uint256{static_cast<uint64_t>(utxo_value)} * arith_uint256{static_cast<uint64_t>(params.nDemurrageRatePeriod)}};
    // target_k = TARGET_RATE_PER_BLOCK * U_k * RATE_PERIOD
    const arith_uint256 target{(period_value * arith_uint256{static_cast<uint64_t>(params.nDemurrageTargetRateNum)}) / arith_uint256{static_cast<uint64_t>(params.nDemurrageTargetRateDen)}};
    const arith_uint256 covered256{static_cast<uint64_t>(covered)};
    if (target <= covered256) return 0;
    // r_k = shortfall_k / (RATE_PERIOD * U_k)
    const arith_uint256 rate{((target - covered256) * arith_uint256{INDEX_ONE}) / period_value};
    Assert(rate.bits() <= 64);
    return rate.GetLow64();
}

uint64_t NextIndex(uint64_t prev_index, uint64_t rate)
{
    Assert(rate <= INDEX_ONE);
    return MulDiv(prev_index, INDEX_ONE - rate, INDEX_ONE);
}

CAmount EffectiveValue(CAmount nominal, uint64_t index_created, uint64_t index_at)
{
    Assert(nominal >= 0);
    Assert(index_created > 0 && index_at <= index_created);
    return static_cast<CAmount>(MulDiv(static_cast<uint64_t>(nominal), index_at, index_created));
}

std::optional<CAmount> ConvertValue(CAmount value, uint64_t from_index, uint64_t to_index)
{
    Assert(value >= 0 && from_index > 0);
    const arith_uint256 r{(arith_uint256{static_cast<uint64_t>(value)} * arith_uint256{to_index}) / arith_uint256{from_index}};
    if (r.bits() > 63) return std::nullopt;
    return static_cast<CAmount>(r.GetLow64());
}

arith_uint256 NormalizedValue(CAmount nominal, uint64_t index_created)
{
    Assert(nominal >= 0 && index_created > 0);
    return (arith_uint256{static_cast<uint64_t>(nominal)} * INDEX_ONE_SQUARED) / arith_uint256{index_created};
}

CAmount UtxoValue(const arith_uint256& normalized_total, uint64_t index)
{
    const arith_uint256 value{(normalized_total * arith_uint256{index}) / INDEX_ONE_SQUARED};
    Assert(value.bits() <= 63);
    return static_cast<CAmount>(value.GetLow64());
}

CAmount Dividend(uint64_t rate, CAmount utxo_value)
{
    Assert(utxo_value >= 0);
    return static_cast<CAmount>(MulDiv(rate, static_cast<uint64_t>(utxo_value), INDEX_ONE));
}

BlockState BaselineState(CAmount utxo_value)
{
    BlockState state;
    state.normalized_utxo = NormalizedValue(utxo_value, INDEX_ONE);
    return state;
}

BlockContext ComputeBlockContext(const BlockState& prev, int height, CAmount covered, const Consensus::Params& params)
{
    Assert(IsActive(height, params));
    BlockContext ctx;
    ctx.prev_utxo_value = prev.UtxoValue();
    ctx.period_start = IsRatePeriodStart(height, params);
    if (ctx.period_start) {
        // covered_k = subsidy_{k-1} (the schedule); U_k = U(H_k - 1).
        ctx.rate = ComputeRate(ctx.prev_utxo_value, covered, params);
    } else {
        ctx.rate = prev.rate;
    }
    // At activation the parent's index is I(ACTIVATION_HEIGHT - 1) = 1.
    ctx.index = NextIndex(prev.index, ctx.rate);
    ctx.dividend = Dividend(ctx.rate, ctx.prev_utxo_value);
    return ctx;
}

BlockState ComputeBlockState(const BlockState& prev, const BlockContext& ctx, const BlockTotals& totals)
{
    BlockState state;
    state.index = ctx.index;
    state.rate = ctx.rate;
    // Outputs spent by the block may have been created by it, so add before subtracting.
    const arith_uint256 total{prev.normalized_utxo + totals.normalized_created};
    Assert(totals.normalized_spent <= total);
    state.normalized_utxo = total - totals.normalized_spent;
    return state;
}

} // namespace demurrage
