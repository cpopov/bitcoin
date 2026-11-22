// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <kernel/coinstats.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/data/bip462_tests.json.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace demurrage;

namespace {
const UniValue& Vectors()
{
    static const UniValue vectors{[] {
        UniValue v;
        Assert(v.read(json_tests::bip462_tests) && v.isObject());
        return v;
    }()};
    return vectors;
}

Consensus::Params ParamsFrom(const UniValue& p)
{
    Consensus::Params params{};
    params.nDemurrageRatePeriod = p["rate_period"].getInt<int>();
    params.nDemurrageTargetRateNum = p["target_rate_num"].getInt<int64_t>();
    params.nDemurrageTargetRateDen = p["target_rate_den"].getInt<int64_t>();
    if (p.exists("activation_height")) params.DemurrageHeight = p["activation_height"].getInt<int>();
    if (p.exists("halving_interval")) params.nSubsidyHalvingInterval = p["halving_interval"].getInt<int>();
    return params;
}

arith_uint256 ArithFromDecimal(const std::string& s)
{
    arith_uint256 r{0};
    for (const char c : s) {
        r = r * 10;
        r += static_cast<uint64_t>(c - '0');
    }
    return r;
}

uint64_t U64(const UniValue& v) { return v.getInt<uint64_t>(); }
} // namespace

BOOST_FIXTURE_TEST_SUITE(demurrage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_parameters)
{
    // BIP 462 "Parameters": TARGET_RATE_PER_BLOCK = 0.0030 / 52,560, RATE_PERIOD = 2016.
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const Consensus::Params& main{chain_params->GetConsensus()};
    const Consensus::Params expected{ParamsFrom(Vectors()["mainnet_params"])};
    BOOST_CHECK_EQUAL(main.nDemurrageRatePeriod, expected.nDemurrageRatePeriod);
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateNum, expected.nDemurrageTargetRateNum);
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateDen, expected.nDemurrageTargetRateDen);
    // No activation height is set at draft stage.
    BOOST_CHECK_EQUAL(main.DemurrageHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(!IsActive(std::numeric_limits<int>::max() - 1, main));
    BOOST_CHECK_EQUAL(Vectors()["index_scale"].getInt<uint64_t>(), INDEX_ONE);
}

BOOST_AUTO_TEST_CASE(covered_vectors)
{
    // covered_k is the mainnet subsidy schedule over the previous rate period.
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    Consensus::Params params{chain_params->GetConsensus()};
    for (const UniValue& v : Vectors()["covered"].getValues()) {
        BOOST_CHECK_EQUAL(GetDemurrageCoveredSubsidy(v["period_start"].getInt<int>(), params), v["covered"].getInt<CAmount>());
    }
}

BOOST_AUTO_TEST_CASE(rate_vectors)
{
    const Consensus::Params params{ParamsFrom(Vectors()["mainnet_params"])};
    const uint64_t target_rate{INDEX_ONE * 3 / 52'560'000};
    for (const UniValue& v : Vectors()["rate"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        const uint64_t rate{ComputeRate(v["utxo_value"].getInt<CAmount>(), v["covered"].getInt<CAmount>(), params)};
        BOOST_CHECK_EQUAL(rate, U64(v["rate"]));
        // By construction 0 <= r_k <= TARGET_RATE_PER_BLOCK.
        BOOST_CHECK_LE(rate, target_rate);
    }
}

BOOST_AUTO_TEST_CASE(index_vectors)
{
    for (const UniValue& v : Vectors()["index"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        uint64_t index{INDEX_ONE};
        const int period{v["rate_period"].getInt<int>()};
        const auto& rates{v["rates"].getValues()};
        const auto& indexes{v["indexes"].getValues()};
        BOOST_REQUIRE_EQUAL(rates.size(), indexes.size());
        for (size_t k{0}; k < rates.size(); ++k) {
            for (int b{0}; b < period; ++b) {
                const uint64_t next{NextIndex(index, U64(rates[k]))};
                BOOST_CHECK_LE(next, index); // non-increasing
                index = next;
            }
            BOOST_CHECK_EQUAL(index, U64(indexes[k]));
        }
    }
}

BOOST_AUTO_TEST_CASE(value_vectors)
{
    for (const UniValue& v : Vectors()["effective_value"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        BOOST_CHECK_EQUAL(EffectiveValue(v["value"].getInt<CAmount>(), U64(v["index_created"]), U64(v["index_at"])), v["result"].getInt<CAmount>());
    }

    const UniValue& u{Vectors()["utxo_value"]};
    arith_uint256 total{0};
    for (const UniValue& o : u["outputs"].getValues()) {
        const arith_uint256 n{NormalizedValue(o["value"].getInt<CAmount>(), U64(o["index_created"]))};
        BOOST_CHECK(n == ArithFromDecimal(o["normalized"].get_str()));
        total += n;
    }
    BOOST_CHECK(total == ArithFromDecimal(u["normalized_total"].get_str()));
    BOOST_CHECK_EQUAL(UtxoValue(total, U64(u["index"])), u["utxo_value"].getInt<CAmount>());

    // An output created at index 1 has normalized value v * INDEX_ONE, exactly.
    BOOST_CHECK(NormalizedValue(MAX_MONEY, INDEX_ONE) == arith_uint256{static_cast<uint64_t>(MAX_MONEY)} * arith_uint256{INDEX_ONE});
    BOOST_CHECK_EQUAL(UtxoValue(NormalizedValue(MAX_MONEY, INDEX_ONE), INDEX_ONE), MAX_MONEY);

    for (const UniValue& v : Vectors()["dividend"].getValues()) {
        BOOST_CHECK_EQUAL(Dividend(U64(v["rate"]), v["utxo_value"].getInt<CAmount>()), v["dividend"].getInt<CAmount>());
    }
}

BOOST_AUTO_TEST_CASE(chain_vectors)
{
    const UniValue& v{Vectors()["chain"]};
    const Consensus::Params params{ParamsFrom(v["params"])};

    // State after ACTIVATION_HEIGHT - 1: every output has index 1.
    BlockState prev{BaselineState(v["initial"]["utxo_value"].getInt<CAmount>())};
    std::map<int, uint64_t> index;
    for (int h{0}; h < params.DemurrageHeight; ++h) index[h] = INDEX_ONE;

    for (const UniValue& b : v["blocks"].getValues()) {
        const int height{b["height"].getInt<int>()};
        BOOST_TEST_INFO("height " << height);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(height, params), b["subsidy"].getInt<CAmount>());
        const bool period_start{IsRatePeriodStart(height, params)};
        BOOST_CHECK_EQUAL(period_start, b["rate_period_start"].get_bool());
        const CAmount covered{period_start ? GetDemurrageCoveredSubsidy(height, params) : 0};
        BOOST_CHECK_EQUAL(covered, b["covered"].getInt<CAmount>());
        const BlockContext ctx{ComputeBlockContext(prev, height, covered, params)};
        BOOST_CHECK_EQUAL(ctx.period_start, period_start);
        BOOST_CHECK_EQUAL(ctx.rate, U64(b["rate"]));
        BOOST_CHECK_EQUAL(ctx.index, U64(b["index"]));
        BOOST_CHECK_EQUAL(ctx.dividend, b["dividend"].getInt<CAmount>());
        index[height] = ctx.index;

        // Each transaction spends one output entirely as fee. The block
        // producer claims it at the block's index (fee_effective).
        BlockTotals totals;
        CAmount fees{0};
        for (const UniValue& tx : b["txs"].getValues()) {
            const CAmount value{tx["value"].getInt<CAmount>()};
            const uint64_t ref_index{index.at(tx["ref_height"].getInt<int>())};
            const CAmount fee_effective{EffectiveValue(value, ref_index, ctx.index)};
            BOOST_CHECK_EQUAL(fee_effective, tx["fee_effective"].getInt<CAmount>());
            fees += fee_effective;
            totals.normalized_spent += NormalizedValue(value, ref_index);
        }
        BOOST_CHECK_EQUAL(fees, b["fees"].getInt<CAmount>());
        const CAmount limit{GetBlockSubsidy(height, params) + fees + ctx.dividend};
        BOOST_CHECK_EQUAL(limit, b["coinbase_limit"].getInt<CAmount>());

        // The coinbase claims the full limit, created at the block's index.
        totals.normalized_created = NormalizedValue(limit, ctx.index);
        const BlockState state{ComputeBlockState(prev, ctx, totals)};
        BOOST_CHECK_EQUAL(state.index, ctx.index);
        BOOST_CHECK_EQUAL(state.rate, ctx.rate);
        BOOST_CHECK_EQUAL(state.UtxoValue(), b["utxo_value"].getInt<CAmount>());

        // Effective supply changes only by the subsidy, up to rounding down.
        const CAmount supply_delta{state.UtxoValue() - prev.UtxoValue()};
        BOOST_CHECK_LE(supply_delta, GetBlockSubsidy(height, params));
        BOOST_CHECK_GE(supply_delta, GetBlockSubsidy(height, params) - 3);

        // States survive serialization (they are stored in the block index database).
        DataStream ss;
        ss << state;
        BlockState read;
        ss >> read;
        BOOST_CHECK(read == state);
        prev = state;
    }
}

BOOST_AUTO_TEST_CASE(convert_value)
{
    // Wallets re-express amounts between reference heights, in either direction.
    BOOST_CHECK_EQUAL(*ConvertValue(1'000'000, INDEX_ONE, INDEX_ONE / 2), 500'000);
    BOOST_CHECK_EQUAL(*ConvertValue(500'000, INDEX_ONE / 2, INDEX_ONE), 1'000'000);
    BOOST_CHECK_EQUAL(*ConvertValue(MAX_MONEY, INDEX_ONE, INDEX_ONE), MAX_MONEY);
    BOOST_CHECK(!ConvertValue(std::numeric_limits<CAmount>::max(), 1, INDEX_ONE));
}

BOOST_AUTO_TEST_CASE(input_vectors)
{
    const UniValue& v{Vectors()["inputs"]};
    const int activation_height{v["activation_height"].getInt<int>()};
    std::map<int, uint64_t> index;
    for (const UniValue& i : v["index"].getValues()) index[i["height"].getInt<int>()] = U64(i["index"]);

    CCoinsViewCache coins{&CoinsViewEmpty::Get()};
    std::map<std::string, COutPoint> outpoints;
    uint32_t n{0};
    for (const std::string& name : v["coins"].getKeys()) {
        const UniValue& c{v["coins"][name]};
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), n++};
        coins.AddCoin(outpoint, Coin{CTxOut{c["value"].getInt<CAmount>(), CScript{} << OP_TRUE}, c["height"].getInt<int>(), /*fCoinBaseIn=*/false, c["ref_height"].getInt<uint32_t>()}, false);
        outpoints[name] = outpoint;
    }

    for (const UniValue& c : v["cases"].getValues()) {
        BOOST_TEST_INFO(c["comment"].get_str());
        const int spend_height{c["spend_height"].getInt<int>()};
        CMutableTransaction mtx;
        for (const UniValue& in : c["inputs"].getValues()) mtx.vin.emplace_back(outpoints.at(in.get_str()));
        mtx.vout.emplace_back(c["value_out"].getInt<CAmount>(), CScript{} << OP_TRUE);
        const CTransaction tx{mtx};

        const TxContext ctx{
            .activation_height = activation_height,
            .spend_height = spend_height,
            .index_at = [&](int h) -> std::optional<uint64_t> {
                if (h < activation_height) return INDEX_ONE;
                const auto it{index.find(h)};
                return it == index.end() ? std::nullopt : std::optional{it->second};
            },
        };
        TxValidationState state;
        CAmount fee{-1};
        uint32_t ref_height{0};
        const bool valid{Consensus::CheckTxInputs(tx, state, coins, spend_height, fee, &ctx, &ref_height)};
        BOOST_CHECK_EQUAL(valid, c["valid"].get_bool());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), c["reason"].get_str());
        // The reference height is the highest among the coins spent.
        BOOST_CHECK_EQUAL(ref_height, c["ref_height"].getInt<uint32_t>());
        if (valid) BOOST_CHECK_EQUAL(fee, c["fee"].getInt<CAmount>());

        // Without a demurrage context (or before activation), inputs are valued nominally.
        TxValidationState legacy_state;
        CAmount legacy_fee;
        if (Consensus::CheckTxInputs(tx, legacy_state, coins, spend_height, legacy_fee)) {
            CAmount nominal_in{0};
            for (const CTxIn& in : tx.vin) nominal_in += coins.AccessCoin(in.prevout).out.nValue;
            BOOST_CHECK_EQUAL(legacy_fee, nominal_in - tx.GetValueOut());
        }
    }
}

BOOST_AUTO_TEST_CASE(coin_serialization)
{
    const CTxOut txout{50 * COIN, CScript{} << OP_TRUE};
    // Coins whose reference height equals their height serialize as before BIP 462.
    {
        const Coin coin{txout, 800'000, /*fCoinBaseIn=*/true};
        BOOST_CHECK_EQUAL(coin.nRefHeight, 800'000U);
        DataStream ss;
        ss << coin;
        DataStream legacy;
        legacy << VARINT(uint32_t{800'000 * 2 + 1}) << Using<TxOutCompression>(txout);
        BOOST_CHECK_EQUAL(HexStr(ss), HexStr(legacy));
        Coin read;
        ss >> read;
        BOOST_CHECK_EQUAL(read.nHeight, 800'000U);
        BOOST_CHECK_EQUAL(read.nRefHeight, 800'000U);
        BOOST_CHECK(read.fCoinBase);
    }
    // Coins with an earlier reference height round-trip through the UTXO database and undo formats.
    {
        const Coin coin{txout, 900'000, /*fCoinBaseIn=*/false, /*ref_height=*/899'000};
        DataStream ss;
        ss << coin;
        Coin read;
        ss >> read;
        BOOST_CHECK_EQUAL(read.nHeight, 900'000U);
        BOOST_CHECK_EQUAL(read.nRefHeight, 899'000U);
        BOOST_CHECK(read.out == txout);

        DataStream undo;
        undo << Using<TxInUndoFormatter>(coin);
        Coin read_undo;
        undo >> Using<TxInUndoFormatter>(read_undo);
        BOOST_CHECK_EQUAL(read_undo.nHeight, 900'000U);
        BOOST_CHECK_EQUAL(read_undo.nRefHeight, 899'000U);
    }
    // Undo records written by old versions hold a transaction version in the
    // reference height slot; it is ignored when it cannot be a valid delta.
    {
        DataStream undo;
        undo << VARINT(uint32_t{1 * 2}) << VARINT(2U) << Using<TxOutCompression>(txout);
        Coin read_undo;
        undo >> Using<TxInUndoFormatter>(read_undo);
        BOOST_CHECK_EQUAL(read_undo.nHeight, 1U);
        BOOST_CHECK_EQUAL(read_undo.nRefHeight, 1U);
    }
    // A reference height above the coin's height is rejected.
    {
        DataStream ss;
        ss << VARINT(uint64_t{(uint64_t{10} << 1) | Coin::REF_HEIGHT_CODE_FLAG}) << VARINT(11U) << Using<TxOutCompression>(txout);
        Coin read;
        BOOST_CHECK_THROW(ss >> read, std::ios_base::failure);
    }
    // AddCoins assigns outputs the reference height it is given (the inclusion
    // height by default, as for coinbases and before activation).
    {
        CCoinsViewCache cache{&CoinsViewEmpty::Get()};
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        mtx.vout.emplace_back(txout);
        AddCoins(cache, CTransaction{mtx}, 500);
        BOOST_CHECK_EQUAL(cache.AccessCoin(COutPoint{CTransaction{mtx}.GetHash(), 0}).nRefHeight, 500U);
        mtx.nLockTime = 1;
        AddCoins(cache, CTransaction{mtx}, 500, /*check=*/false, /*ref_height=*/450);
        BOOST_CHECK_EQUAL(cache.AccessCoin(COutPoint{CTransaction{mtx}.GetHash(), 0}).nRefHeight, 450U);
    }
}

BOOST_AUTO_TEST_CASE(utxo_hash_commits_to_ref_height)
{
    const COutPoint outpoint{Txid::FromUint256(uint256::ONE), 3};
    const CTxOut txout{50 * COIN, CScript{} << OP_TRUE};
    const auto muhash{[&](const Coin& coin) {
        MuHash3072 hash;
        kernel::ApplyCoinHash(hash, outpoint, coin);
        uint256 out;
        hash.Finalize(out);
        return out;
    }};
    // A coin whose reference height is its height hashes as before BIP 462.
    const Coin same{txout, 900'000, /*fCoinBaseIn=*/false};
    DataStream legacy;
    legacy << outpoint << uint32_t{900'000 * 2} << txout;
    MuHash3072 expected{MakeUCharSpan(legacy)};
    uint256 expected_hash;
    expected.Finalize(expected_hash);
    BOOST_CHECK(muhash(same) == expected_hash);
    // A different reference height changes the hash.
    const Coin earlier{txout, 900'000, /*fCoinBaseIn=*/false, /*ref_height=*/899'000};
    const Coin other{txout, 900'000, /*fCoinBaseIn=*/false, /*ref_height=*/898'000};
    BOOST_CHECK(muhash(earlier) != muhash(same));
    BOOST_CHECK(muhash(earlier) != muhash(other));
}

BOOST_AUTO_TEST_CASE(snapshot_metadata)
{
    const auto magic{CreateChainParams(*m_node.args, ChainType::REGTEST)->MessageStart()};
    // Below activation, the format is unchanged (version 2).
    {
        const node::SnapshotMetadata metadata{magic, uint256::ONE, 7};
        DataStream ss;
        ss << metadata;
        BOOST_CHECK_EQUAL(ss.size(), 51U);
        BOOST_CHECK_EQUAL(uint8_t(ss[5]), 2);
        node::SnapshotMetadata read{magic};
        ss >> read;
        BOOST_CHECK(read.m_base_blockhash == uint256::ONE);
        BOOST_CHECK_EQUAL(read.m_coins_count, 7U);
        BOOST_CHECK(read.m_demurrage_states.empty());
    }
    // Above activation, version 3 carries the demurrage states.
    {
        std::vector<BlockState> states{BaselineState(1000 * COIN)};
        states.push_back(BlockState{.index = NextIndex(INDEX_ONE, 1'000'000), .rate = 1'000'000, .normalized_utxo = states[0].normalized_utxo + 5});
        const node::SnapshotMetadata metadata{magic, uint256::ONE, 7, states};
        DataStream ss;
        ss << metadata;
        BOOST_CHECK_EQUAL(uint8_t(ss[5]), 3);
        node::SnapshotMetadata read{magic};
        ss >> read;
        BOOST_CHECK(read.m_demurrage_states == states);
        BOOST_CHECK(node::DemurrageStatesHash(read.m_demurrage_states) == node::DemurrageStatesHash(states));
        states[1].rate += 1;
        BOOST_CHECK(node::DemurrageStatesHash(read.m_demurrage_states) != node::DemurrageStatesHash(states));
    }
}

BOOST_AUTO_TEST_SUITE_END()
