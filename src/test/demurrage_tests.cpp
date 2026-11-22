// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <kernel/chainparams.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace demurrage;

// Expected values are from an independent implementation of the BIP 462b
// formulas with arbitrary-precision integers.
BOOST_FIXTURE_TEST_SUITE(demurrage_tests, BasicTestingSetup)

static const Consensus::Params& MainParams()
{
    static const auto params{CChainParams::Main({})};
    return params->GetConsensus();
}

static Consensus::Params RegTestParams()
{
    return CChainParams::RegTest({})->GetConsensus();
}

BOOST_AUTO_TEST_CASE(pool_script)
{
    BOOST_CHECK_EQUAL(HexStr(PoolScript()), "04706f6f6c7551");
    BOOST_CHECK(PoolScript() == (CScript{} << std::vector<unsigned char>{'p', 'o', 'o', 'l'} << OP_DROP << OP_1));
    BOOST_CHECK(IsPoolScript(PoolScript()));
    BOOST_CHECK(!IsPoolScript(CScript{} << OP_TRUE));
    CScript longer{PoolScript()};
    longer << OP_NOP;
    BOOST_CHECK(!IsPoolScript(longer));
    BOOST_CHECK(!IsPoolScript(CScript{} << std::vector<unsigned char>{'p', 'o', 'o', 'l'} << OP_DROP << OP_2));

    // A bare script that matches no standard output type...
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(PoolScript(), solutions) == TxoutType::NONSTANDARD);
    // ...and that an empty scriptSig satisfies under every current rule.
    const script_verify_flags flags{STANDARD_SCRIPT_VERIFY_FLAGS};
    ScriptError err;
    BOOST_CHECK(VerifyScript(CScript{}, PoolScript(), nullptr, flags, BaseSignatureChecker{}, &err));
    BOOST_CHECK(err == SCRIPT_ERR_OK);

    // Existing standardness rules refuse to relay a transaction that creates one.
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(10'000, PoolScript());
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, DEFAULT_PERMIT_BAREMULTISIG, CFeeRate{DUST_RELAY_TX_FEE}, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
}

BOOST_AUTO_TEST_CASE(scheduled_supply)
{
    const auto& params{MainParams()};
    BOOST_CHECK_EQUAL(ScheduledSupply(0, params), 0);
    BOOST_CHECK_EQUAL(ScheduledSupply(1, params), 50 * COIN); // includes the genesis block
    BOOST_CHECK_EQUAL(ScheduledSupply(210'000, params), 210'000 * 50 * COIN);
    BOOST_CHECK_EQUAL(ScheduledSupply(210'001, params), 210'000 * 50 * COIN + 25 * COIN);
    BOOST_CHECK_EQUAL(ScheduledSupply(1'260'000, params), 2'067'187'500'000'000);
    BOOST_CHECK_EQUAL(ScheduledSupply(64 * 210'000, params), 2'099'999'997'690'000);
    BOOST_CHECK_EQUAL(ScheduledSupply(100 * 210'000, params), 2'099'999'997'690'000);
    for (int height : {0, 1, 209'999, 210'000, 6'929'999, 6'930'000, 13'440'000}) {
        BOOST_CHECK_EQUAL(ScheduledSupply(height + 1, params) - ScheduledSupply(height, params), ScheduledSubsidy(height, params));
    }
    BOOST_CHECK_EQUAL(ScheduledSubsidy(6'930'000, params), 0);
}

BOOST_AUTO_TEST_CASE(mainnet_rates)
{
    const auto& params{MainParams()};
    // The maximum rate: floor(INDEX_ONE * 3 / 52,560,000).
    constexpr uint64_t MAX_RATE{57'077'625'570};

    // Every rate period below the 2032 halving has a zero rate.
    for (int start{0}; start < 1'260'000; start += 2016) {
        BOOST_CHECK_EQUAL(PeriodRate(start, params), 0);
    }
    // The last zero period, and the first non-zero period (the 2032 halving).
    BOOST_CHECK_EQUAL(PeriodRate(1'257'984, params), 0);
    BOOST_CHECK_EQUAL(PeriodRate(1'260'000, params), 19'284'730'634);
    // The first period wholly within each later halving era.
    BOOST_CHECK_EQUAL(PeriodRate(1'471'680, params), 38'330'559'486);
    BOOST_CHECK_EQUAL(PeriodRate(1'681'344, params), 47'740'674'579);
    BOOST_CHECK_EQUAL(PeriodRate(1'891'008, params), 52'418'249'448);
    // Once the subsidy has ended, the rate is the target. S_k * RATE_PERIOD * 3
    // exceeds 2^63 here, so this needs the 128-bit intermediates. The subsidy
    // ends at 6,930,000, so the period before 6,931,008 still has some.
    BOOST_CHECK_EQUAL(PeriodRate(6'928'992, params), 57'077'625'332);
    BOOST_CHECK_EQUAL(PeriodRate(6'931'008, params), MAX_RATE);
    BOOST_CHECK_EQUAL(PeriodRate(13'440'672, params), MAX_RATE);

    // 0 <= r_k <= MAX_RATE. The rate rises as the subsidy halves, except that
    // rounding can lower it by one unit from one period to the next.
    uint64_t previous{0};
    for (int start{0}; start < 70 * 210'000; start += 2016) {
        const uint64_t rate{PeriodRate(start, params)};
        BOOST_CHECK_LE(rate, MAX_RATE);
        BOOST_CHECK_GE(rate + 1, previous);
        previous = rate;
    }
    // With S_k = 0 (activation at genesis), the rate is zero.
    BOOST_CHECK_EQUAL(PeriodRate(0, params), 0);
}

BOOST_AUTO_TEST_CASE(first_charge_height)
{
    // getblocktemplate requires the rule from the first rate period with a
    // non-zero rate: 1,260,000 on mainnet, or the activation height if later.
    const auto& params{MainParams()};
    for (int activation_height : {0, 2016, 999'936, 1'257'984, 1'260'000}) {
        BOOST_CHECK_EQUAL(IndexSchedule(params, activation_height).FirstChargeHeight().value_or(-1), 1'260'000);
    }
    BOOST_CHECK_EQUAL(IndexSchedule(params, 1'262'016).FirstChargeHeight().value_or(-1), 1'262'016);
    BOOST_CHECK_EQUAL(IndexSchedule(RegTestParams(), 432).FirstChargeHeight().value_or(-1), 576);
    BOOST_CHECK_EQUAL(IndexSchedule(RegTestParams(), 576).FirstChargeHeight().value_or(-1), 576);
    // A zero target never charges.
    Consensus::Params zero_target{params};
    zero_target.DemurrageTargetNumerator = 0;
    BOOST_CHECK(!IndexSchedule(zero_target, 0).FirstChargeHeight());
}

BOOST_AUTO_TEST_CASE(mainnet_index)
{
    const auto& params{MainParams()};
    IndexSchedule schedule{params, 1'257'984};
    BOOST_CHECK_EQUAL(schedule.Index(0), INDEX_ONE);
    BOOST_CHECK_EQUAL(schedule.Index(1'257'983), INDEX_ONE);
    BOOST_CHECK_EQUAL(schedule.Index(1'259'999), INDEX_ONE);
    BOOST_CHECK_EQUAL(schedule.Index(1'260'000), INDEX_ONE - 19'284'730'634);
    BOOST_CHECK_EQUAL(schedule.Index(1'260'000), 999'999'980'715'269'366);
    BOOST_CHECK_EQUAL(schedule.Index(1'260'001), 999'999'961'430'539'103);
    BOOST_CHECK_EQUAL(schedule.Index(1'262'015), 999'961'122'738'406'300);
    BOOST_CHECK_EQUAL(schedule.Index(1'262'016), 999'961'103'451'546'275);
    // The index falls by 0.41% by the 2036 halving, 1.21% by 2040 and 2.19% by 2044.
    BOOST_CHECK_EQUAL(schedule.Index(1'470'000), 995'922'229'831'836'250);
    BOOST_CHECK_EQUAL(schedule.Index(1'680'000), 987'931'417'478'365'928);
    BOOST_CHECK_EQUAL(schedule.Index(1'890'000), 978'076'306'932'324'829);
    BOOST_CHECK_EQUAL(schedule.RateAt(1'260'000), 19'284'730'634);
    BOOST_CHECK_EQUAL(schedule.RateAt(1'259'999), 0);

    // For any activation height at a multiple of 2016 up to 1,260,000, the
    // index is the same.
    for (int activation_height : {0, 2016 * 100, 1'260'000}) {
        IndexSchedule other{params, activation_height};
        BOOST_CHECK_EQUAL(other.Index(1'259'999), INDEX_ONE);
        BOOST_CHECK_EQUAL(other.Index(1'262'016), 999'961'103'451'546'275);
        BOOST_CHECK_EQUAL(other.Index(1'890'000), 978'076'306'932'324'829);
    }
}

BOOST_AUTO_TEST_CASE(index_step)
{
    BOOST_CHECK_EQUAL(NextIndex(INDEX_ONE, 0), INDEX_ONE);
    BOOST_CHECK_EQUAL(NextIndex(INDEX_ONE, 57'077'625'570), INDEX_ONE - 57'077'625'570);
    // Rounding down: once index * rate < INDEX_ONE, the index falls by one per block.
    BOOST_CHECK_EQUAL(NextIndex(1'000'000, 57'077'625'570), 999'999);
    // The lower bound of 1.
    BOOST_CHECK_EQUAL(NextIndex(1, 57'077'625'570), 1);
    BOOST_CHECK_EQUAL(NextIndex(1, INDEX_ONE), 1);
    BOOST_CHECK_EQUAL(NextIndex(INDEX_ONE, INDEX_ONE), 1);
}

BOOST_AUTO_TEST_CASE(charges)
{
    const auto& params{MainParams()};
    IndexSchedule schedule{params, 1'257'984};

    // An output created before activation pays only for decay after activation.
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 100, 1'890'000), 109'618'466);
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 1'259'999, 1'890'000), 109'618'466);
    // No decay yet: no charge.
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 100, 1'259'999), 0);
    // Created and spent in the same block: no charge.
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 1'500'000, 1'500'000), 0);
    // Not yet confirmed (a created height above the spending height): no charge.
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 0x7FFFFFFF, 1'500'000), 0);
    // Rounding the remaining value down rounds the charge up: any non-zero
    // value pays at least one satoshi once the index has fallen.
    BOOST_CHECK_EQUAL(schedule.ChargeFor(1, 1'259'999, 1'260'000), 1);
    BOOST_CHECK_EQUAL(schedule.ChargeFor(COIN, 1'260'000, 1'260'001), 2);
    BOOST_CHECK_EQUAL(schedule.ChargeFor(0, 1'259'999, 1'890'000), 0);
    BOOST_CHECK_EQUAL(schedule.ChargeFor(123'456'789, 1'262'015, 1'470'000), 498'649);
    // The largest possible value.
    BOOST_CHECK_EQUAL(Charge(MAX_MONEY, INDEX_ONE, INDEX_ONE / 2), MAX_MONEY / 2);
    BOOST_CHECK_EQUAL(Charge(MAX_MONEY, INDEX_ONE, 1), MAX_MONEY);
    BOOST_CHECK_EQUAL(Charge(MAX_MONEY, INDEX_ONE, INDEX_ONE), 0);
}

BOOST_AUTO_TEST_CASE(regtest_schedule)
{
    // Regtest: rate periods of 144 blocks and a target of 1/2,000 per block, so
    // that charges are non-zero soon after activation.
    const Consensus::Params params{RegTestParams()};
    BOOST_CHECK_EQUAL(params.DemurrageRatePeriod, 144);
    IndexSchedule schedule{params, 432};
    BOOST_CHECK_EQUAL(schedule.RateAt(432), 0);
    BOOST_CHECK_EQUAL(schedule.RateAt(575), 0);
    BOOST_CHECK_EQUAL(schedule.RateAt(576), 237'945'492'662'473);
    BOOST_CHECK_EQUAL(schedule.RateAt(720), 369'227'994'227'994);
    BOOST_CHECK_EQUAL(schedule.RateAt(864), 433'609'517'739'536);
    BOOST_CHECK_EQUAL(schedule.Index(575), INDEX_ONE);
    BOOST_CHECK_EQUAL(schedule.Index(576), 999'762'054'507'337'527);
    BOOST_CHECK_EQUAL(schedule.Index(719), 966'312'277'776'190'134);
    BOOST_CHECK_EQUAL(schedule.Index(720), 965'955'488'232'068'947);
    BOOST_CHECK_EQUAL(schedule.Index(1000), 863'411'165'250'730'387);
    BOOST_CHECK_EQUAL(schedule.ChargeFor(50 * COIN, 1, 600), 29'658'415);
}

BOOST_AUTO_TEST_CASE(claim_transaction)
{
    const COutPoint carry{Txid::FromUint256(uint256::ONE), 0};
    const COutPoint contribution{Txid::FromUint256(uint256{2}), 1};

    // One input: 67 bytes.
    {
        const std::vector<COutPoint> inputs{contribution};
        const CTransaction claim{BuildClaimTransaction(inputs, 123'456'789)};
        BOOST_CHECK_EQUAL(claim.version, 2);
        BOOST_CHECK_EQUAL(claim.nLockTime, 0U);
        BOOST_REQUIRE_EQUAL(claim.vin.size(), 1U);
        BOOST_CHECK(claim.vin[0].prevout == contribution);
        BOOST_CHECK(claim.vin[0].scriptSig.empty());
        BOOST_CHECK_EQUAL(claim.vin[0].nSequence, 0xFFFFFFFF);
        BOOST_CHECK(claim.vin[0].scriptWitness.IsNull());
        BOOST_REQUIRE_EQUAL(claim.vout.size(), 1U);
        BOOST_CHECK(IsPoolScript(claim.vout[0].scriptPubKey));
        BOOST_CHECK_EQUAL(PoolPayout(123'456'789), 12'345);
        BOOST_CHECK_EQUAL(claim.vout[0].nValue, 123'456'789 - 12'345);
        BOOST_CHECK_EQUAL(::GetSerializeSize(TX_WITH_WITNESS(claim)), 67U);
        BOOST_CHECK(claim.GetHash().ToUint256() == claim.GetWitnessHash().ToUint256());
    }
    // Two inputs, carry first: 108 bytes.
    {
        const std::vector<COutPoint> inputs{carry, contribution};
        const CTransaction claim{BuildClaimTransaction(inputs, 10'000)};
        BOOST_REQUIRE_EQUAL(claim.vin.size(), 2U);
        BOOST_CHECK(claim.vin[0].prevout == carry);
        BOOST_CHECK(claim.vin[1].prevout == contribution);
        BOOST_CHECK_EQUAL(claim.vout[0].nValue, 9'999);
        BOOST_CHECK_EQUAL(::GetSerializeSize(TX_WITH_WITNESS(claim)), 108U);
        // Deterministic: the same inputs give the same txid.
        BOOST_CHECK(claim.GetHash() == CTransaction{BuildClaimTransaction(inputs, 10'000)}.GetHash());
    }
    // A pool below POOL_DIVISOR pays nothing out, and the carry keeps it all.
    BOOST_CHECK_EQUAL(PoolPayout(9'999), 0);
    BOOST_CHECK_EQUAL(PoolPayout(1), 0);
    const std::vector<COutPoint> inputs{carry};
    BOOST_CHECK_EQUAL(BuildClaimTransaction(inputs, 1).vout[0].nValue, 1);
    // The contribution output is 16 bytes.
    BOOST_CHECK_EQUAL(::GetSerializeSize(CTxOut{1, PoolScript()}), 16U);
}

BOOST_AUTO_TEST_CASE(evaluation_height)
{
    // The smallest multiple of 144 that is at least the next block's height plus 144.
    BOOST_CHECK_EQUAL(EvaluationHeight(1), 288);
    BOOST_CHECK_EQUAL(EvaluationHeight(143), 288);
    BOOST_CHECK_EQUAL(EvaluationHeight(144), 288);
    BOOST_CHECK_EQUAL(EvaluationHeight(145), 432);
    BOOST_CHECK_EQUAL(EvaluationHeight(1'260'000), 1'260'144);
    BOOST_CHECK_EQUAL(EvaluationHeight(1'260'001), 1'260'288);
    for (int next_height{1}; next_height < 1000; ++next_height) {
        const int evaluation{EvaluationHeight(next_height)};
        BOOST_CHECK_EQUAL(evaluation % CHARGE_MARGIN, 0);
        BOOST_CHECK_GE(evaluation, next_height + CHARGE_MARGIN);
        BOOST_CHECK_LT(evaluation, next_height + 2 * CHARGE_MARGIN);
    }
}

BOOST_AUTO_TEST_SUITE_END()
