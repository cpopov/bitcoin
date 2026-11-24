// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/demurrage.h>

#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/check.h>

#include <algorithm>
#include <utility>

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

uint64_t ComputeRate(CAmount utxo_value, CAmount subsidy, uint64_t prev_index, const Consensus::Params& params)
{
    Assert(utxo_value >= 0 && subsidy >= 0);
    Assert(params.nDemurrageTargetRateNum >= 0 && params.nDemurrageTargetRateDen > 0);
    // Demurrage stops at INDEX_MIN, so that the index never reaches zero.
    if (utxo_value == 0 || prev_index <= INDEX_MIN) return 0;
    const arith_uint256 value{static_cast<uint64_t>(utxo_value)};
    // target(h) = TARGET_RATE_PER_BLOCK * U(h - 1)
    const arith_uint256 target{(value * arith_uint256{static_cast<uint64_t>(params.nDemurrageTargetRateNum)}) / arith_uint256{static_cast<uint64_t>(params.nDemurrageTargetRateDen)}};
    const arith_uint256 subsidy256{static_cast<uint64_t>(subsidy)};
    if (target <= subsidy256) return 0;
    // r(h) = shortfall(h) / U(h - 1)
    const arith_uint256 rate{((target - subsidy256) * arith_uint256{INDEX_ONE}) / value};
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

BlockContext ComputeBlockContext(const BlockState& prev, CAmount subsidy, const Consensus::Params& params)
{
    BlockContext ctx;
    ctx.prev_utxo_value = prev.UtxoValue();
    ctx.rate = ComputeRate(ctx.prev_utxo_value, subsidy, prev.index, params);
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

uint32_t CommittedRefHeight(uint32_t ref_height, int activation_height)
{
    Assert(activation_height > 0);
    return std::max(ref_height, static_cast<uint32_t>(activation_height - 1));
}

uint256 CommitmentLeaf(const uint256& txid, uint32_t committed_ref_height)
{
    return (HashWriter{} << txid << committed_ref_height).GetHash();
}

uint256 CoinbaseCommitmentLeaf(int height)
{
    Assert(height >= 0);
    return CommitmentLeaf(uint256::ZERO, static_cast<uint32_t>(height));
}

uint256 Commitment(const BlockState& prev, const BlockContext& ctx, std::vector<uint256> leaves)
{
    Assert(!leaves.empty());
    const uint256 ref_height_root{ComputeMerkleRoot(std::move(leaves))};
    // state(h) = I(h) || r(h) || N(h - 1), little-endian.
    return (HashWriter{} << ctx.index << ctx.rate << ArithToUint256(prev.normalized_utxo) << ref_height_root).GetHash();
}

CScript CommitmentScript(const uint256& commitment)
{
    std::vector<unsigned char> data(COMMITMENT_HEADER.begin(), COMMITMENT_HEADER.end());
    data.insert(data.end(), commitment.begin(), commitment.end());
    CScript script{CScript{} << OP_RETURN << data};
    Assert(script.size() == MINIMUM_COMMITMENT_SCRIPT_SIZE);
    return script;
}

bool IsCommitmentScript(const CScript& script)
{
    return script.size() >= MINIMUM_COMMITMENT_SCRIPT_SIZE &&
           script[0] == OP_RETURN &&
           script[1] == 0x24 &&
           std::equal(COMMITMENT_HEADER.begin(), COMMITMENT_HEADER.end(), script.begin() + 2);
}

std::optional<size_t> GetCommitmentIndex(const CTransaction& coinbase)
{
    std::optional<size_t> index;
    for (size_t o{0}; o < coinbase.vout.size(); ++o) {
        if (IsCommitmentScript(coinbase.vout[o].scriptPubKey)) index = o;
    }
    return index;
}

std::optional<uint256> GetCommitment(const CTransaction& coinbase)
{
    const std::optional<size_t> index{GetCommitmentIndex(coinbase)};
    if (!index) return std::nullopt;
    const CScript& script{coinbase.vout[*index].scriptPubKey};
    return uint256{std::span<const unsigned char>{script.data() + 6, 32}};
}

} // namespace demurrage
