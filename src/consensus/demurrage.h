// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DEMURRAGE_H
#define BITCOIN_CONSENSUS_DEMURRAGE_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class CBlock;
namespace Consensus {
struct Params;
} // namespace Consensus

/**
 * BIP 462b: soft-fork demurrage.
 *
 * When a block spends an output, it owes a charge equal to the fall in a
 * demurrage index since the block that created the output. The coinbase pays
 * the block's total charge into a pool output, and the claim transaction at
 * index 1 of every later block draws a fixed fraction of the pool as its fee.
 *
 * All arithmetic is on integers, with 128-bit intermediates, and every
 * division rounds down.
 */
namespace demurrage {

/** Fixed-point scale of the index and the rate: an index of INDEX_ONE means 1.0. */
inline constexpr uint64_t INDEX_ONE{1'000'000'000'000'000'000};
/** Each claim transaction pays floor(P / POOL_DIVISOR) of the pool P as its fee. */
inline constexpr CAmount POOL_DIVISOR{10'000};

/** POOL_SCRIPT: PUSH4 "pool" OP_DROP OP_1 (0x04706f6f6c7551). */
const CScript& PoolScript();
/** Whether a scriptPubKey is exactly POOL_SCRIPT. */
bool IsPoolScript(const CScript& script);

/** block_subsidy(i): the scheduled subsidy at height i, whatever any coinbase claimed. */
CAmount ScheduledSubsidy(int height, const Consensus::Params& params);
/** The scheduled supply: the sum of block_subsidy(i) for 0 <= i < height. */
CAmount ScheduledSupply(int height, const Consensus::Params& params);

/**
 * The rate r_k, scaled by INDEX_ONE, of the rate period that begins at height
 * period_start (H_k). It depends on nothing but H_k.
 */
uint64_t PeriodRate(int period_start, const Consensus::Params& params);

/** One step of the index: max(1, floor(index * (INDEX_ONE - rate) / INDEX_ONE)). */
uint64_t NextIndex(uint64_t index, uint64_t rate);

/** charge(v, c, h) = v - floor(v * I(h) / I(c)), given I(c) and I(h). */
CAmount Charge(CAmount value, uint64_t index_created, uint64_t index_spent);

/** payout = floor(P / POOL_DIVISOR). */
CAmount PoolPayout(CAmount pool);

/**
 * The demurrage index I(h) of a chain whose deployment activated at
 * activation_height. I(h) = INDEX_ONE for every h < activation_height. Values
 * are computed incrementally and cached. Not thread-safe: the owner must
 * serialise access.
 */
class IndexSchedule
{
public:
    IndexSchedule(const Consensus::Params& params, int activation_height);

    int ActivationHeight() const { return m_activation_height; }
    /** I(h). */
    uint64_t Index(int height);
    /** r_k of the rate period containing height (zero before activation). */
    uint64_t RateAt(int height);
    /** charge(v, c, h). A created height above the spent height (an output created
     *  in the same block, or not yet confirmed) has no charge. */
    CAmount ChargeFor(CAmount value, int created_height, int spent_height);

private:
    int m_halving_interval;
    int m_rate_period;
    uint64_t m_target_numerator;
    uint64_t m_target_denominator;
    int m_activation_height;
    /** m_index[i] = I(activation_height + i). */
    std::vector<uint64_t> m_index;
    /** m_rates[k] = r_k. */
    std::vector<uint64_t> m_rates;
};

/** The pool outputs that a connected block created. */
struct BlockPoolOutputs {
    /** Output 0 of the block's claim transaction, if it has one: the next block's carry. */
    std::optional<COutPoint> carry;
    /** The coinbase's pool output, if any: the block's contribution. */
    std::optional<COutPoint> contribution;
};

/**
 * The pool outputs of a block at or above the activation height that has
 * passed validation: its coinbase's pool output, and the output of the
 * transaction at index 1 if that transaction creates one (only a claim
 * transaction can).
 */
BlockPoolOutputs FindBlockPoolOutputs(const CBlock& block);

/**
 * The claim transaction spending pool inputs whose values sum to pool_value:
 * version 2, each input with an empty scriptSig, nSequence 0xFFFFFFFF and an
 * empty witness, one output of pool_value - floor(pool_value / POOL_DIVISOR)
 * to POOL_SCRIPT, nLockTime 0.
 */
CMutableTransaction BuildClaimTransaction(std::span<const COutPoint> pool_inputs, CAmount pool_value);

/**
 * Relay and mining policy: the evaluation height E, the smallest multiple of
 * CHARGE_MARGIN that is at least next_height + CHARGE_MARGIN.
 */
inline constexpr int CHARGE_MARGIN{144};
int EvaluationHeight(int next_height);

} // namespace demurrage

#endif // BITCOIN_CONSENSUS_DEMURRAGE_H
