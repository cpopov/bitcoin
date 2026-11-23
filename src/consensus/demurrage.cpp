// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/demurrage.h>

#include <consensus/params.h>
#include <primitives/block.h>
#include <util/check.h>

#ifndef __SIZEOF_INT128__
#include <arith_uint256.h>
#endif

#include <algorithm>
#include <array>
#include <limits>

namespace demurrage {
namespace {

// Products such as S_k * RATE_PERIOD * 3 fit in 128 bits but not in 64.
#ifdef __SIZEOF_INT128__
using Wide = unsigned __int128;
uint64_t Narrow(Wide value)
{
    Assert(value <= std::numeric_limits<uint64_t>::max());
    return static_cast<uint64_t>(value);
}
#else
using Wide = arith_uint256;
uint64_t Narrow(const Wide& value)
{
    Assert(value.bits() <= 64);
    return value.GetLow64();
}
#endif

constexpr std::array<unsigned char, 7> POOL_SCRIPT_BYTES{0x04, 'p', 'o', 'o', 'l', 0x75 /* OP_DROP */, 0x51 /* OP_1 */};

/** Sum of block_subsidy(i) for 0 <= i < height. */
CAmount SupplyBefore(int height, int64_t halving_interval)
{
    CAmount supply{0};
    for (int64_t era{0}; era < 64 && era * halving_interval < height; ++era) {
        const int64_t blocks{std::min<int64_t>(height, (era + 1) * halving_interval) - era * halving_interval};
        supply += blocks * ((50 * COIN) >> era);
    }
    return supply;
}

uint64_t RateOfPeriod(int period_start, int halving_interval, int rate_period, uint64_t target_numerator, uint64_t target_denominator)
{
    // S_k, the scheduled supply before the period, and subsidy_k, the scheduled subsidy within it.
    const uint64_t supply{static_cast<uint64_t>(SupplyBefore(period_start, halving_interval))};
    if (supply == 0) return 0;
    const uint64_t subsidy{static_cast<uint64_t>(SupplyBefore(period_start + rate_period, halving_interval)) - supply};
    // target_k = floor(S_k * RATE_PERIOD * TARGET_RATE_PER_BLOCK)
    const uint64_t period{static_cast<uint64_t>(rate_period)};
    const uint64_t target{Narrow(Wide{supply} * Wide{period} * Wide{target_numerator} / Wide{target_denominator})};
    if (target <= subsidy) return 0;
    const uint64_t shortfall{target - subsidy};
    // r_k = floor(shortfall_k * INDEX_ONE / (RATE_PERIOD * S_k))
    return Narrow(Wide{shortfall} * Wide{INDEX_ONE} / (Wide{period} * Wide{supply}));
}

} // namespace

const CScript& PoolScript()
{
    static const CScript script(POOL_SCRIPT_BYTES.begin(), POOL_SCRIPT_BYTES.end());
    return script;
}

bool IsPoolScript(const CScript& script)
{
    return script.size() == POOL_SCRIPT_BYTES.size() && std::equal(script.begin(), script.end(), POOL_SCRIPT_BYTES.begin());
}

CAmount ScheduledSubsidy(int height, const Consensus::Params& params)
{
    const int halvings{height / params.nSubsidyHalvingInterval};
    if (halvings >= 64) return 0;
    return (50 * COIN) >> halvings;
}

CAmount ScheduledSupply(int height, const Consensus::Params& params)
{
    return SupplyBefore(height, params.nSubsidyHalvingInterval);
}

uint64_t PeriodRate(int period_start, const Consensus::Params& params)
{
    return RateOfPeriod(period_start, params.nSubsidyHalvingInterval, params.DemurrageRatePeriod,
                        params.DemurrageTargetNumerator, params.DemurrageTargetDenominator);
}

uint64_t NextIndex(uint64_t index, uint64_t rate)
{
    Assert(rate <= INDEX_ONE);
    return std::max<uint64_t>(1, Narrow(Wide{index} * Wide{INDEX_ONE - rate} / Wide{INDEX_ONE}));
}

CAmount Charge(CAmount value, uint64_t index_created, uint64_t index_spent)
{
    Assert(value >= 0);
    Assert(index_created > 0 && index_spent <= index_created);
    const uint64_t remaining{Narrow(Wide{static_cast<uint64_t>(value)} * Wide{index_spent} / Wide{index_created})};
    return value - static_cast<CAmount>(remaining);
}

CAmount PoolPayout(CAmount pool)
{
    Assert(pool >= 0);
    return pool / POOL_DIVISOR;
}

IndexSchedule::IndexSchedule(const Consensus::Params& params, int activation_height)
    : m_halving_interval{params.nSubsidyHalvingInterval},
      m_rate_period{params.DemurrageRatePeriod},
      m_target_numerator{params.DemurrageTargetNumerator},
      m_target_denominator{params.DemurrageTargetDenominator},
      m_activation_height{activation_height}
{
    Assert(m_rate_period > 0 && m_target_denominator > 0 && activation_height >= 0);
}

uint64_t IndexSchedule::RateAt(int height)
{
    if (height < m_activation_height) return 0;
    const size_t period{static_cast<size_t>((height - m_activation_height) / m_rate_period)};
    while (period >= m_rates.size()) {
        const int period_start{m_activation_height + static_cast<int>(m_rates.size()) * m_rate_period};
        m_rates.push_back(RateOfPeriod(period_start, m_halving_interval, m_rate_period, m_target_numerator, m_target_denominator));
    }
    return m_rates[period];
}

std::optional<int> IndexSchedule::FirstChargeHeight()
{
    // Once the subsidy has ended (by era 64 at the latest), the shortfall is the
    // whole target, so a rate that is still zero then stays zero.
    const int64_t last_start{int64_t{64} * m_halving_interval + m_rate_period};
    for (int64_t start{m_activation_height}; start <= last_start; start += m_rate_period) {
        if (RateAt(static_cast<int>(start)) > 0) return static_cast<int>(start);
    }
    return std::nullopt;
}

uint64_t IndexSchedule::Index(int height)
{
    if (height < m_activation_height) return INDEX_ONE;
    const size_t offset{static_cast<size_t>(height - m_activation_height)};
    while (offset >= m_index.size()) {
        const uint64_t previous{m_index.empty() ? INDEX_ONE : m_index.back()};
        m_index.push_back(NextIndex(previous, RateAt(m_activation_height + static_cast<int>(m_index.size()))));
    }
    return m_index[offset];
}

CAmount IndexSchedule::ChargeFor(CAmount value, int created_height, int spent_height)
{
    if (created_height >= spent_height) return 0;
    return Charge(value, Index(created_height), Index(spent_height));
}

BlockPoolOutputs FindBlockPoolOutputs(const CBlock& block)
{
    BlockPoolOutputs result;
    const CTransaction& coinbase{*Assert(block.vtx.at(0))};
    for (uint32_t i{0}; i < coinbase.vout.size(); ++i) {
        if (IsPoolScript(coinbase.vout[i].scriptPubKey)) {
            result.contribution = COutPoint{coinbase.GetHash(), i};
            break;
        }
    }
    if (block.vtx.size() > 1) {
        const CTransaction& tx{*block.vtx[1]};
        if (tx.vout.size() == 1 && IsPoolScript(tx.vout[0].scriptPubKey)) {
            result.carry = COutPoint{tx.GetHash(), 0};
        }
    }
    return result;
}

CMutableTransaction BuildClaimTransaction(std::span<const COutPoint> pool_inputs, CAmount pool_value)
{
    CMutableTransaction tx;
    tx.version = 2;
    for (const COutPoint& outpoint : pool_inputs) {
        tx.vin.emplace_back(outpoint, CScript{}, CTxIn::SEQUENCE_FINAL);
    }
    tx.vout.emplace_back(pool_value - PoolPayout(pool_value), PoolScript());
    tx.nLockTime = 0;
    return tx;
}

PolicyCharge EvaluatePolicyCharge(IndexSchedule& schedule, std::span<const PolicyInput> inputs, int next_height)
{
    const auto charge_at{[&](int height) {
        CAmount charge{0};
        for (const PolicyInput& input : inputs) {
            // An output of an unconfirmed transaction cannot be created before the next block.
            charge += schedule.ChargeFor(input.value, std::min(input.created_height, next_height), height);
        }
        return charge;
    }};
    const CAmount base{charge_at(next_height)};
    const auto within_tolerance{[&](int height) { return charge_at(height) - base <= CHARGE_TOLERANCE; }};

    // charge_at() does not fall as the height rises, so the heights within the
    // tolerance form a range that starts at next_height.
    int low{next_height};
    int high{next_height + CHARGE_MARGIN};
    if (within_tolerance(high)) {
        low = high;
    } else {
        while (high - low > 1) {
            const int middle{low + (high - low) / 2};
            (within_tolerance(middle) ? low : high) = middle;
        }
    }
    return {.evaluation_height = low, .charge = charge_at(low)};
}

} // namespace demurrage
