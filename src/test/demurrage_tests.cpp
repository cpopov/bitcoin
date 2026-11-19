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
#include <core_io.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <test/data/bip462_tests.json.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>

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
    params.nDemurrageFeePoolDivisor = p["fee_pool_divisor"].getInt<int64_t>();
    if (p.exists("activation_height")) params.DemurrageHeight = p["activation_height"].getInt<int>();
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
    // BIP 462 "Parameters": TARGET_RATE_PER_BLOCK = 0.0030 / 52,560, RATE_PERIOD = 2016, FEE_POOL_DIVISOR = 1000.
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const Consensus::Params& main{chain_params->GetConsensus()};
    const Consensus::Params expected{ParamsFrom(Vectors()["mainnet_params"])};
    BOOST_CHECK_EQUAL(main.nDemurrageRatePeriod, expected.nDemurrageRatePeriod);
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateNum, expected.nDemurrageTargetRateNum);
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateDen, expected.nDemurrageTargetRateDen);
    BOOST_CHECK_EQUAL(main.nDemurrageFeePoolDivisor, expected.nDemurrageFeePoolDivisor);
    // No activation height is set at draft stage.
    BOOST_CHECK_EQUAL(main.DemurrageHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(!IsActive(std::numeric_limits<int>::max() - 1, main));
    BOOST_CHECK_EQUAL(Vectors()["index_scale"].getInt<uint64_t>(), INDEX_ONE);
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

BOOST_AUTO_TEST_CASE(fee_pool_vectors)
{
    const UniValue& v{Vectors()["fee_pool"]};
    Consensus::Params params{};
    params.nDemurrageFeePoolDivisor = v["fee_pool_divisor"].getInt<int64_t>();
    CAmount pool{0};
    for (const UniValue& b : v["blocks"].getValues()) {
        const CAmount payout{PoolPayout(pool, params)};
        BOOST_CHECK_EQUAL(payout, b["payout"].getInt<CAmount>());
        pool = pool - payout + b["fees"].getInt<CAmount>();
        BOOST_CHECK_EQUAL(pool, b["pool"].getInt<CAmount>());
    }
}

BOOST_AUTO_TEST_CASE(chain_vectors)
{
    const UniValue& v{Vectors()["chain"]};
    const Consensus::Params params{ParamsFrom(v["params"])};
    BOOST_CHECK_EQUAL(TrackingStartHeight(params), params.DemurrageHeight - params.nDemurrageRatePeriod);

    // State after ACTIVATION_HEIGHT - 1: the UTXO set value and the previous period's totals.
    BlockState prev;
    prev.normalized_utxo = NormalizedValue(v["initial"]["utxo_value"].getInt<CAmount>(), INDEX_ONE);
    prev.has_utxo_total = true;
    prev.period_subsidy = v["initial"]["period_subsidy"].getInt<CAmount>();
    prev.period_fees = v["initial"]["period_fees"].getInt<CAmount>();

    for (const UniValue& b : v["blocks"].getValues()) {
        const int height{b["height"].getInt<int>()};
        BOOST_TEST_INFO("height " << height);
        const BlockContext ctx{ComputeBlockContext(prev, height, params)};
        BOOST_CHECK_EQUAL(ctx.period_start, b["rate_period_start"].get_bool());
        BOOST_CHECK_EQUAL(ctx.rate, U64(b["rate"]));
        BOOST_CHECK_EQUAL(ctx.index, U64(b["index"]));
        BOOST_CHECK_EQUAL(ctx.dividend, b["dividend"].getInt<CAmount>());
        BOOST_CHECK_EQUAL(ctx.pool_payout, b["pool_payout"].getInt<CAmount>());
        const CAmount subsidy{b["subsidy"].getInt<CAmount>()};
        BOOST_CHECK_EQUAL(subsidy + ctx.pool_payout + ctx.dividend, b["coinbase_limit"].getInt<CAmount>());

        // The coinbase claims the full limit; the fees are paid by spending an
        // output worth exactly the fee at the block's index.
        BlockTotals totals;
        totals.subsidy = subsidy;
        totals.fees = b["fees"].getInt<CAmount>();
        totals.normalized_created = NormalizedValue(b["coinbase_limit"].getInt<CAmount>(), ctx.index);
        totals.normalized_spent = NormalizedValue(totals.fees, ctx.index);
        const BlockState state{ComputeBlockState(&prev, &ctx, height, totals, params)};
        BOOST_CHECK_EQUAL(state.index, ctx.index);
        BOOST_CHECK_EQUAL(state.rate, ctx.rate);
        BOOST_CHECK_EQUAL(state.pool, b["pool"].getInt<CAmount>());
        BOOST_CHECK_EQUAL(state.UtxoValue(), b["utxo_value"].getInt<CAmount>());
        BOOST_CHECK_EQUAL(state.period_subsidy, b["period_subsidy"].getInt<CAmount>());
        BOOST_CHECK_EQUAL(state.period_fees, b["period_fees"].getInt<CAmount>());

        // Effective supply (UTXO set plus pool) changes only by the subsidy,
        // up to rounding down.
        const CAmount supply_delta{(state.UtxoValue() + state.pool) - (prev.UtxoValue() + prev.pool)};
        BOOST_CHECK_LE(supply_delta, subsidy);
        BOOST_CHECK_GE(supply_delta, subsidy - 3);

        // States survive serialization (they are stored in the block index database).
        DataStream ss;
        ss << state;
        BlockState read;
        ss >> read;
        BOOST_CHECK(read == state);
        prev = state;
    }
}

BOOST_AUTO_TEST_CASE(tracking_before_activation)
{
    Consensus::Params params{};
    params.DemurrageHeight = 10;
    params.nDemurrageRatePeriod = 4;
    BOOST_CHECK_EQUAL(TrackingStartHeight(params), 6);
    BOOST_CHECK(!IsRatePeriodStart(9, params));
    BOOST_CHECK(IsRatePeriodStart(10, params));
    BOOST_CHECK(!IsRatePeriodStart(13, params));
    BOOST_CHECK(IsRatePeriodStart(14, params));

    // Before activation, only the subsidy and fees of the preceding period are tracked.
    BlockTotals totals{.subsidy = 100, .fees = 7};
    BlockState state{ComputeBlockState(nullptr, nullptr, 6, totals, params)};
    for (int h{7}; h < 10; ++h) state = ComputeBlockState(&state, nullptr, h, totals, params);
    BOOST_CHECK_EQUAL(state.period_subsidy, 400);
    BOOST_CHECK_EQUAL(state.period_fees, 28);
    BOOST_CHECK_EQUAL(state.index, INDEX_ONE);
    BOOST_CHECK_EQUAL(state.rate, 0U);
    BOOST_CHECK_EQUAL(state.pool, 0);
    BOOST_CHECK(!state.has_utxo_total);

    // The activation height may be close to genesis: tracking starts at height 1.
    params.DemurrageHeight = 2;
    BOOST_CHECK_EQUAL(TrackingStartHeight(params), 1);
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
        if (!c["ref_height"].isNull()) {
            mtx.version = CTransaction::REF_HEIGHT_VERSION;
            mtx.ref_height = c["ref_height"].getInt<uint32_t>();
        }
        for (const UniValue& in : c["inputs"].getValues()) mtx.vin.emplace_back(outpoints.at(in.get_str()));
        mtx.vout.emplace_back(c["value_out"].getInt<CAmount>(), CScript{} << OP_TRUE);
        const CTransaction tx{mtx};

        TxValidationState field_state;
        BOOST_CHECK(Consensus::CheckTxRefHeightField(tx, field_state, /*demurrage_active=*/true));

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
        const bool valid{Consensus::CheckTxInputs(tx, state, coins, spend_height, fee, &ctx)};
        BOOST_CHECK_EQUAL(valid, c["valid"].get_bool());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), c["reason"].get_str());
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

BOOST_AUTO_TEST_CASE(ref_height_field_rules)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(1, CScript{} << OP_TRUE);
    const auto check = [](const CMutableTransaction& m, bool active) {
        TxValidationState state;
        (void)Consensus::CheckTxRefHeightField(CTransaction{m}, state, active);
        return state.GetRejectReason();
    };
    mtx.version = 2;
    BOOST_CHECK_EQUAL(check(mtx, false), "");
    BOOST_CHECK_EQUAL(check(mtx, true), "");
    mtx.version = 4; // historical transactions may have any version
    BOOST_CHECK_EQUAL(check(mtx, false), "");
    BOOST_CHECK_EQUAL(check(mtx, true), "bad-txns-refheight-version");
    mtx.ref_height = 1000;
    BOOST_CHECK_EQUAL(check(mtx, false), "bad-txns-refheight-premature");
    BOOST_CHECK_EQUAL(check(mtx, true), "");
    mtx.version = 2;
    BOOST_CHECK_EQUAL(check(mtx, true), "bad-txns-refheight-version");

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(1, CScript{} << OP_TRUE);
    BOOST_CHECK_EQUAL(check(coinbase, true), "");
    coinbase.ref_height = 5;
    BOOST_CHECK_EQUAL(check(coinbase, true), "bad-cb-refheight");
}

BOOST_AUTO_TEST_CASE(transaction_vectors)
{
    const UniValue& v{Vectors()["transaction"]};
    for (const auto& [hex_key, txid_key, wtxid_key] : {std::tuple{"hex", "txid", "wtxid"}, std::tuple{"hex_no_witness", "txid_no_witness", "wtxid_no_witness"}}) {
        CMutableTransaction mtx;
        BOOST_REQUIRE(DecodeHexTx(mtx, v[hex_key].get_str()));
        const CTransaction tx{mtx};
        BOOST_CHECK_EQUAL(tx.ref_height.value_or(0), v["ref_height"].getInt<uint32_t>());
        BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), v[txid_key].get_str());
        BOOST_CHECK_EQUAL(tx.GetWitnessHash().GetHex(), v[wtxid_key].get_str());
        BOOST_CHECK_EQUAL(EncodeHexTx(tx), v[hex_key].get_str());
    }

    CMutableTransaction mtx;
    BOOST_REQUIRE(DecodeHexTx(mtx, v["hex"].get_str()));
    const CTransaction tx{mtx};
    std::vector<CTxOut> spent;
    for (const UniValue& o : v["spent_outputs"].getValues()) {
        const auto script{ParseHex(o["script_pubkey"].get_str())};
        spent.emplace_back(o["value"].getInt<CAmount>(), CScript(script.begin(), script.end()));
    }
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);

    for (const UniValue& s : v["sighashes"].getValues()) {
        const std::string sigversion{s["sigversion"].get_str()};
        const unsigned int in{s["input"].getInt<unsigned int>()};
        const int32_t hash_type{s["hash_type"].getInt<int32_t>()};
        uint256 hash;
        if (sigversion == "taproot") {
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            BOOST_REQUIRE(SignatureHashSchnorr(hash, execdata, tx, in, static_cast<uint8_t>(hash_type), SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
        } else {
            const auto script{ParseHex(s["script_code"].get_str())};
            const CScript script_code(script.begin(), script.end());
            const bool v0{sigversion == "witness_v0"};
            hash = SignatureHash(script_code, tx, in, hash_type, v0 ? s["amount"].getInt<CAmount>() : 0, v0 ? SigVersion::WITNESS_V0 : SigVersion::BASE);
        }
        BOOST_TEST_INFO(sigversion << " hash_type " << hash_type);
        BOOST_CHECK_EQUAL(HexStr(hash), s["sighash"].get_str());

        // The digest commits to the reference height.
        CMutableTransaction mutated{tx};
        *mutated.ref_height += 1;
        const CTransaction mutated_tx{mutated};
        uint256 mutated_hash;
        if (sigversion == "taproot") {
            PrecomputedTransactionData mutated_data;
            mutated_data.Init(mutated_tx, std::vector<CTxOut>{spent}, /*force=*/true);
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            BOOST_REQUIRE(SignatureHashSchnorr(mutated_hash, execdata, mutated_tx, in, static_cast<uint8_t>(hash_type), SigVersion::TAPROOT, mutated_data, MissingDataBehavior::FAIL));
        } else {
            const auto script{ParseHex(s["script_code"].get_str())};
            const bool v0{sigversion == "witness_v0"};
            mutated_hash = SignatureHash(CScript(script.begin(), script.end()), mutated_tx, in, hash_type, v0 ? s["amount"].getInt<CAmount>() : 0, v0 ? SigVersion::WITNESS_V0 : SigVersion::BASE);
        }
        BOOST_CHECK(mutated_hash != hash);
    }
}

BOOST_AUTO_TEST_CASE(transaction_serialization)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 7});
    mtx.vout.emplace_back(1234, CScript{} << OP_TRUE);
    const std::string legacy_hex{EncodeHexTx(CTransaction{mtx})};

    // A legacy transaction serializes exactly as before.
    BOOST_CHECK_EQUAL(legacy_hex.substr(8, 2), "01"); // input count, no marker

    mtx.version = CTransaction::REF_HEIGHT_VERSION;
    mtx.ref_height = 0x01020304;
    const CTransaction tx{mtx};
    // marker 0x00, flag 0x02, ..., nLockTime, ref_height (little endian)
    const std::string hex{EncodeHexTx(tx)};
    BOOST_CHECK_EQUAL(hex.substr(8, 4), "0002");
    BOOST_CHECK_EQUAL(hex.substr(hex.size() - 8), "04030201");
    // The txid commits to the reference height; without witnesses, wtxid == txid.
    DataStream no_witness;
    no_witness << TX_NO_WITNESS(tx);
    BOOST_CHECK_EQUAL(HexStr(no_witness), hex);
    BOOST_CHECK(tx.GetHash().ToUint256() == tx.GetWitnessHash().ToUint256());
    CMutableTransaction other{mtx};
    other.ref_height = 0x01020305;
    BOOST_CHECK(CTransaction{other}.GetHash() != tx.GetHash());

    // With a witness, both flags are set, and the txid is unchanged by the witness.
    mtx.vin[0].scriptWitness.stack = {{0xaa}};
    const CTransaction witness_tx{mtx};
    const std::string witness_hex{EncodeHexTx(witness_tx)};
    BOOST_CHECK_EQUAL(witness_hex.substr(8, 4), "0003");
    BOOST_CHECK(witness_tx.GetHash() == tx.GetHash());
    BOOST_CHECK(witness_tx.GetWitnessHash().ToUint256() != tx.GetWitnessHash().ToUint256());
    for (const std::string& h : {hex, witness_hex}) {
        CMutableTransaction decoded;
        BOOST_REQUIRE(DecodeHexTx(decoded, h));
        BOOST_CHECK(decoded.ref_height == mtx.ref_height);
        BOOST_CHECK_EQUAL(EncodeHexTx(CTransaction{decoded}), h);
    }

    // A truncated reference height fails to deserialize.
    DataStream truncated{ParseHex(hex.substr(0, hex.size() - 2))};
    CMutableTransaction out;
    BOOST_CHECK_THROW(truncated >> TX_WITH_WITNESS(out), std::ios_base::failure);
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
    // AddCoins assigns outputs the reference height of their transaction.
    {
        CCoinsViewCache cache{&CoinsViewEmpty::Get()};
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
        mtx.vout.emplace_back(txout);
        AddCoins(cache, CTransaction{mtx}, 500);
        BOOST_CHECK_EQUAL(cache.AccessCoin(COutPoint{CTransaction{mtx}.GetHash(), 0}).nRefHeight, 500U);
        mtx.version = CTransaction::REF_HEIGHT_VERSION;
        mtx.ref_height = 450;
        AddCoins(cache, CTransaction{mtx}, 500);
        BOOST_CHECK_EQUAL(cache.AccessCoin(COutPoint{CTransaction{mtx}.GetHash(), 0}).nRefHeight, 450U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
