// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <chain.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/muhash.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <kernel/coinstats.h>
#include <flatfile.h>
#include <node/blockstorage.h>
#include <node/utxo_snapshot.h>
#include <policy/policy.h>
#include <psbt.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <sync.h>
#include <test/data/bip462_tests.json.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
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
    // BIP 462 "Parameters": TARGET_RATE_PER_BLOCK = 0.0030 / 52,560, INDEX_MIN = 10^9.
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const Consensus::Params& main{chain_params->GetConsensus()};
    const Consensus::Params expected{ParamsFrom(Vectors()["mainnet_params"])};
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateNum, expected.nDemurrageTargetRateNum);
    BOOST_CHECK_EQUAL(main.nDemurrageTargetRateDen, expected.nDemurrageTargetRateDen);
    // No activation height is set at draft stage.
    BOOST_CHECK_EQUAL(main.DemurrageHeight, std::numeric_limits<int>::max());
    BOOST_CHECK(!IsActive(std::numeric_limits<int>::max() - 1, main));
    BOOST_CHECK_EQUAL(Vectors()["index_scale"].getInt<uint64_t>(), INDEX_ONE);
    BOOST_CHECK_EQUAL(Vectors()["index_min"].getInt<uint64_t>(), INDEX_MIN);
}

BOOST_AUTO_TEST_CASE(rate_vectors)
{
    const Consensus::Params params{ParamsFrom(Vectors()["mainnet_params"])};
    const uint64_t target_rate{INDEX_ONE * 3 / 52'560'000};
    for (const UniValue& v : Vectors()["rate"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        const uint64_t rate{ComputeRate(v["utxo_value"].getInt<CAmount>(), v["subsidy"].getInt<CAmount>(), U64(v["prev_index"]), params)};
        BOOST_CHECK_EQUAL(rate, U64(v["rate"]));
        // By construction 0 <= r(h) <= TARGET_RATE_PER_BLOCK.
        BOOST_CHECK_LE(rate, target_rate);
    }
}

BOOST_AUTO_TEST_CASE(index_floor_vectors)
{
    // Once the index is at or below INDEX_MIN the rate is zero: the index
    // stops falling, and so never reaches zero.
    const Consensus::Params params{ParamsFrom(Vectors()["mainnet_params"])};
    const UniValue& v{Vectors()["index_floor"]};
    const CAmount utxo_value{v["utxo_value"].getInt<CAmount>()};
    const CAmount subsidy{v["subsidy"].getInt<CAmount>()};
    uint64_t index{U64(v["blocks"][0]["prev_index"])};
    bool stopped{false};
    for (const UniValue& b : v["blocks"].getValues()) {
        BOOST_CHECK_EQUAL(index, U64(b["prev_index"]));
        const uint64_t rate{ComputeRate(utxo_value, subsidy, index, params)};
        const uint64_t next{NextIndex(index, rate)};
        BOOST_CHECK_EQUAL(rate, U64(b["rate"]));
        BOOST_CHECK_EQUAL(next, U64(b["index"]));
        BOOST_CHECK_GT(next, 0U);
        if (index <= INDEX_MIN) {
            stopped = true;
            BOOST_CHECK_EQUAL(rate, 0U);
            BOOST_CHECK_EQUAL(next, index);
        }
        index = next;
    }

    // The same through the block context: no dividend once demurrage has stopped.
    BlockState at_floor{.index = INDEX_MIN};
    at_floor.normalized_utxo = NormalizedValue(utxo_value, INDEX_MIN);
    const BlockContext ctx{ComputeBlockContext(at_floor, subsidy, params)};
    BOOST_CHECK_EQUAL(ctx.rate, 0U);
    BOOST_CHECK_EQUAL(ctx.index, INDEX_MIN);
    BOOST_CHECK_EQUAL(ctx.dividend, 0);
    at_floor.index = INDEX_MIN + 1;
    BOOST_CHECK_GT(ComputeBlockContext(at_floor, subsidy, params).rate, 0U);
    BOOST_CHECK(stopped);
}

BOOST_AUTO_TEST_CASE(index_vectors)
{
    for (const UniValue& v : Vectors()["index"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        uint64_t index{INDEX_ONE};
        const int blocks{v["blocks"].getInt<int>()};
        const auto& rates{v["rates"].getValues()};
        const auto& indexes{v["indexes"].getValues()};
        BOOST_REQUIRE_EQUAL(rates.size(), indexes.size());
        for (size_t k{0}; k < rates.size(); ++k) {
            for (int b{0}; b < blocks; ++b) {
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
        const BlockContext ctx{ComputeBlockContext(prev, GetBlockSubsidy(height, params), params)};
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

BOOST_AUTO_TEST_CASE(commitment_vectors)
{
    // COMMITMENT_HEADER is the first four bytes of SHA256("BIP462").
    uint256 header_hash;
    CSHA256{}.Write(UCharCast("BIP462"), 6).Finalize(header_hash.begin());
    BOOST_CHECK(std::equal(COMMITMENT_HEADER.begin(), COMMITMENT_HEADER.end(), header_hash.begin()));

    for (const UniValue& v : Vectors()["commitment"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        const int activation_height{v["activation_height"].getInt<int>()};
        const int height{v["height"].getInt<int>()};
        BlockState prev;
        prev.normalized_utxo = ArithFromDecimal(v["prev_normalized"].get_str());
        const BlockContext ctx{.index = U64(v["index"]), .rate = U64(v["rate"])};

        // One leaf per transaction, in block order; the coinbase's comes first.
        std::vector<uint256> leaves{CoinbaseCommitmentLeaf(height)};
        for (const UniValue& tx : v["txs"].getValues()) {
            const uint32_t committed{CommittedRefHeight(tx["ref_height"].getInt<uint32_t>(), activation_height)};
            BOOST_CHECK_EQUAL(committed, tx["committed_ref_height"].getInt<uint32_t>());
            leaves.push_back(CommitmentLeaf(*Assert(uint256::FromHex(tx["txid"].get_str())), committed));
        }
        BOOST_CHECK_EQUAL(HexStr(ComputeMerkleRoot(leaves)), v["ref_height_root"].get_str());
        const uint256 commitment{Commitment(prev, ctx, leaves)};
        BOOST_CHECK_EQUAL(HexStr(commitment), v["commitment"].get_str());
        const CScript script{CommitmentScript(commitment)};
        BOOST_CHECK_EQUAL(HexStr(script), v["script"].get_str());
        BOOST_CHECK(IsCommitmentScript(script));

        // A coinbase's commitment is in the last output that has its form.
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vout.emplace_back(50 * COIN, CScript{} << OP_TRUE);
        BOOST_CHECK(!GetCommitment(CTransaction{coinbase}));
        coinbase.vout.emplace_back(0, script);
        BOOST_CHECK(GetCommitment(CTransaction{coinbase}) == commitment);
        BOOST_CHECK_EQUAL(*GetCommitmentIndex(CTransaction{coinbase}), 1U);
        const CScript other{CommitmentScript(uint256::ONE)};
        coinbase.vout.emplace_back(0, other);
        BOOST_CHECK(GetCommitment(CTransaction{coinbase}) == uint256::ONE);
        coinbase.vout.emplace_back(0, script);
        // Shorter scripts, and scripts with another header, do not count.
        coinbase.vout.emplace_back(0, CScript{other.begin(), other.end() - 1});
        CScript other_header{other};
        other_header[5] ^= 1;
        coinbase.vout.emplace_back(0, other_header);
        BOOST_CHECK(GetCommitment(CTransaction{coinbase}) == commitment);
        BOOST_CHECK_EQUAL(*GetCommitmentIndex(CTransaction{coinbase}), 3U);
        // Longer scripts that begin with a commitment do.
        coinbase.vout.emplace_back(0, CScript{other} << OP_TRUE);
        BOOST_CHECK(GetCommitment(CTransaction{coinbase}) == uint256::ONE);
    }
}

BOOST_AUTO_TEST_CASE(sighash_vectors)
{
    for (const UniValue& v : Vectors()["sighash"].getValues()) {
        BOOST_TEST_INFO(v["comment"].get_str());
        const int activation_height{v["activation_height"].getInt<int>()};
        std::map<int, uint64_t> index;
        for (const UniValue& i : v["index"].getValues()) index[i["height"].getInt<int>()] = U64(i["index"]);
        const auto index_at{[&](uint32_t height) { return index.at(static_cast<int>(CommittedRefHeight(height, activation_height))); }};

        CMutableTransaction mtx;
        mtx.version = v["version"].getInt<uint32_t>();
        mtx.nLockTime = v["locktime"].getInt<uint32_t>();
        std::vector<CTxOut> spent;
        uint32_t ref_height{0};
        for (const UniValue& in : v["inputs"].getValues()) {
            mtx.vin.emplace_back(COutPoint{*Assert(Txid::FromHex(in["txid"].get_str())), in["vout"].getInt<uint32_t>()}, CScript{}, in["sequence"].getInt<uint32_t>());
            const std::vector<unsigned char> script{ParseHex(in["script_pubkey"].get_str())};
            spent.emplace_back(in["amount"].getInt<CAmount>(), CScript{script.begin(), script.end()});
            ref_height = std::max(ref_height, in["ref_height"].getInt<uint32_t>());
        }
        for (const UniValue& out : v["outputs"].getValues()) {
            const std::vector<unsigned char> script{ParseHex(out["script_pubkey"].get_str())};
            mtx.vout.emplace_back(out["amount"].getInt<CAmount>(), CScript{script.begin(), script.end()});
        }
        BOOST_CHECK_EQUAL(ref_height, v["ref_height"].getInt<uint32_t>());
        const uint32_t committed{CommittedRefHeight(ref_height, activation_height)};
        BOOST_CHECK_EQUAL(committed, v["committed_ref_height"].getInt<uint32_t>());

        // Each input is valued at the index of the transaction's reference height.
        std::vector<CAmount> values;
        for (const UniValue& in : v["inputs"].getValues()) {
            values.push_back(EffectiveValue(in["amount"].getInt<CAmount>(), index_at(in["ref_height"].getInt<uint32_t>()), index_at(ref_height)));
            BOOST_CHECK_EQUAL(values.back(), in["value"].getInt<CAmount>());
        }

        PrecomputedTransactionData without;
        without.Init(mtx, std::vector<CTxOut>{spent}, /*force=*/true);
        PrecomputedTransactionData txdata;
        txdata.Init(mtx, std::vector<CTxOut>{spent}, /*force=*/true);
        txdata.SetDemurrage(values, committed);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_demurrage_input_values_single_hash), v["sha_input_values"].get_str());

        for (const UniValue& c : v["cases"].getValues()) {
            const uint8_t hash_type{c["hash_type"].getInt<uint8_t>()};
            const uint32_t in_pos{c["input_index"].getInt<uint32_t>()};
            BOOST_TEST_INFO("hash_type " << int{hash_type} << ", input " << in_pos);
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            SigVersion sigversion{SigVersion::TAPROOT};
            if (c.exists("tapleaf_hash")) {
                sigversion = SigVersion::TAPSCRIPT;
                execdata.m_tapleaf_hash_init = true;
                execdata.m_tapleaf_hash = uint256{ParseHex(c["tapleaf_hash"].get_str())};
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = 0xFFFFFFFF;
            }
            uint256 sighash;
            // The hash types are valid only where the BIP 462 data is known.
            BOOST_CHECK(!SignatureHashSchnorr(sighash, execdata, mtx, in_pos, hash_type, sigversion, without, MissingDataBehavior::FAIL));
            BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, mtx, in_pos, hash_type, sigversion, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), c["sighash"].get_str());
            // SigMsg is at most 242 bytes.
            BOOST_CHECK_LE(c["sig_msg"].get_str().size(), 2 * 242U);

            // The other hash types do not commit to the BIP 462 data.
            uint256 plain, plain_without;
            BOOST_REQUIRE(SignatureHashSchnorr(plain, execdata, mtx, in_pos, hash_type & 0x3f, sigversion, txdata, MissingDataBehavior::FAIL));
            BOOST_REQUIRE(SignatureHashSchnorr(plain_without, execdata, mtx, in_pos, hash_type & 0x3f, sigversion, without, MissingDataBehavior::FAIL));
            BOOST_CHECK(plain == plain_without);
            BOOST_CHECK(plain != sighash);

            // A different input value or reference height gives a different hash.
            for (const bool change_value : {true, false}) {
                std::vector<CAmount> other_values{values};
                if (change_value) other_values.back() += 1;
                PrecomputedTransactionData other;
                other.Init(mtx, std::vector<CTxOut>{spent}, /*force=*/true);
                other.SetDemurrage(other_values, change_value ? committed : committed + 1);
                uint256 other_hash;
                BOOST_REQUIRE(SignatureHashSchnorr(other_hash, execdata, mtx, in_pos, hash_type, sigversion, other, MissingDataBehavior::FAIL));
                BOOST_CHECK(other_hash != sighash);
            }

            // SIGHASH_DEMURRAGE cannot be used alone, nor with SIGHASH_ANYONECANPAY.
            for (const uint8_t invalid : {uint8_t{0x40}, uint8_t{0x44}, uint8_t{0xc0}, uint8_t(hash_type | 0x80)}) {
                BOOST_CHECK(!SignatureHashSchnorr(sighash, execdata, mtx, in_pos, invalid, sigversion, txdata, MissingDataBehavior::FAIL));
            }
        }
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

namespace {
/** A signing provider for the descriptor @p desc (with private keys), and its scriptPubKey. */
std::pair<FlatSigningProvider, CScript> ProviderFor(const std::string& desc)
{
    FlatSigningProvider keys;
    std::string error;
    const auto descs{Parse(desc, keys, error)};
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, error);
    std::vector<CScript> scripts;
    FlatSigningProvider provider;
    BOOST_REQUIRE(descs[0]->Expand(0, keys, scripts, provider));
    provider.Merge(std::move(keys));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    return {std::move(provider), scripts[0]};
}

/** Verify every input of @p tx, with @p demurrage as the BIP 462 data, if set. */
std::vector<ScriptError> VerifyInputs(const CTransaction& tx, const std::vector<CTxOut>& spent, const std::optional<DemurrageSigningData>& demurrage)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent});
    if (demurrage) txdata.SetDemurrage(demurrage->input_values, demurrage->committed_ref_height);
    std::vector<ScriptError> errors;
    for (unsigned int i{0}; i < tx.vin.size(); ++i) {
        ScriptError error{SCRIPT_ERR_OK};
        VerifyScript(tx.vin[i].scriptSig, spent[i].scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                     TransactionSignatureChecker{&tx, i, spent[i].nValue, txdata, MissingDataBehavior::FAIL}, &error);
        errors.push_back(error);
    }
    return errors;
}
} // namespace

BOOST_AUTO_TEST_CASE(psbt_fields)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
    mtx.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);
    PartiallySignedTransaction psbt{mtx, /*version=*/0};
    const CScript spk{CScript{} << OP_1 << std::vector<unsigned char>(32, 0x55)};
    psbt.inputs[0].witness_utxo = CTxOut{2 * COIN, spk};
    psbt.inputs[1].witness_utxo = CTxOut{3 * COIN, spk};
    BOOST_CHECK(!GetDemurrageSigningData(psbt));
    BOOST_CHECK(!Assert(PrecomputePSBTData(psbt))->m_demurrage_ready);

    // The first input spends a coin from before activation, worth less at the
    // transaction's reference height than its nominal value.
    SetDemurrageFields(psbt.inputs[0], 431, 2 * COIN - 1234);
    BOOST_CHECK(!GetDemurrageSigningData(psbt));
    SetDemurrageFields(psbt.inputs[1], 500, 3 * COIN);
    // The fields are proprietary keys with identifier "bip462" and no key data.
    BOOST_REQUIRE_EQUAL(psbt.inputs[0].m_proprietary.size(), 2U);
    const std::vector<unsigned char> value_key{0xfc, 0x06, 'b', 'i', 'p', '4', '6', '2', 0x01};
    BOOST_CHECK(std::ranges::any_of(psbt.inputs[0].m_proprietary, [&](const PSBTProprietary& p) { return p.key == value_key && p.subtype == 1; }));

    // They survive serialization.
    DataStream ss;
    ss << psbt;
    PartiallySignedTransaction read{deserialize, ss};
    BOOST_CHECK_EQUAL(*GetDemurrageRefHeight(read.inputs[0]), 431U);
    BOOST_CHECK_EQUAL(*GetDemurrageValue(read.inputs[0]), 2 * COIN - 1234);
    BOOST_CHECK_EQUAL(*GetDemurrageRefHeight(read.inputs[1]), 500U);
    const std::optional<DemurrageSigningData> data{GetDemurrageSigningData(read)};
    BOOST_REQUIRE(data);
    BOOST_CHECK_EQUAL(data->committed_ref_height, 500U);
    BOOST_CHECK(data->input_values == (std::vector<CAmount>{2 * COIN - 1234, 3 * COIN}));
    const PrecomputedTransactionData txdata{*Assert(PrecomputePSBTData(read))};
    BOOST_CHECK(txdata.m_demurrage_ready);
    PrecomputedTransactionData expected;
    expected.SetDemurrage(data->input_values, 500);
    BOOST_CHECK(txdata.m_demurrage_input_values_single_hash == expected.m_demurrage_input_values_single_hash);
    BOOST_CHECK_EQUAL(txdata.m_demurrage_ref_height, 500U);

    // Setting the fields again replaces them.
    SetDemurrageFields(psbt.inputs[0], 431, 2 * COIN - 1);
    BOOST_CHECK_EQUAL(psbt.inputs[0].m_proprietary.size(), 2U);
    BOOST_CHECK_EQUAL(*GetDemurrageValue(psbt.inputs[0]), 2 * COIN - 1);

    // Values that cannot be right are not used: an input worth more than its
    // nominal value, or one at the transaction's reference height worth less.
    SetDemurrageFields(psbt.inputs[0], 431, 2 * COIN + 1);
    BOOST_CHECK(!GetDemurrageSigningData(psbt));
    SetDemurrageFields(psbt.inputs[0], 431, 2 * COIN);
    BOOST_CHECK(GetDemurrageSigningData(psbt));
    SetDemurrageFields(psbt.inputs[1], 500, 3 * COIN - 1);
    BOOST_CHECK(!GetDemurrageSigningData(psbt));
    // Two inputs at the transaction's reference height must both be worth their nominal value.
    SetDemurrageFields(psbt.inputs[0], 500, 2 * COIN);
    SetDemurrageFields(psbt.inputs[1], 500, 3 * COIN);
    BOOST_CHECK(GetDemurrageSigningData(psbt));
    // A field of the wrong size is ignored.
    for (const PSBTProprietary& entry : std::set<PSBTProprietary>{psbt.inputs[1].m_proprietary}) {
        PSBTProprietary shorter{entry};
        shorter.value.pop_back();
        psbt.inputs[1].m_proprietary.erase(entry);
        psbt.inputs[1].m_proprietary.insert(shorter);
    }
    BOOST_CHECK(!GetDemurrageRefHeight(psbt.inputs[1]));
    BOOST_CHECK(!GetDemurrageValue(psbt.inputs[1]));
    BOOST_CHECK(!GetDemurrageSigningData(psbt));
}

BOOST_AUTO_TEST_CASE(sign_with_sighash_demurrage)
{
    CKey tr_key, wpkh_key;
    tr_key.MakeNewKey(/*fCompressed=*/true);
    wpkh_key.MakeNewKey(/*fCompressed=*/true);
    auto [provider, tr_spk]{ProviderFor("tr(" + EncodeSecret(tr_key) + ")")};
    auto [wpkh_provider, wpkh_spk]{ProviderFor("wpkh(" + EncodeSecret(wpkh_key) + ")")};
    provider.Merge(std::move(wpkh_provider));

    // Two taproot inputs and a P2WPKH input, with an output for each, so that
    // SIGHASH_SINGLE can be used.
    const std::vector<CTxOut> spent{{2 * COIN, tr_spk}, {3 * COIN, tr_spk}, {1 * COIN, wpkh_spk}};
    CMutableTransaction unsigned_tx;
    std::map<COutPoint, Coin> coins;
    for (uint32_t i{0}; i < spent.size(); ++i) {
        const COutPoint outpoint{Txid::FromUint256(uint256::ONE), i};
        unsigned_tx.vin.emplace_back(outpoint);
        unsigned_tx.vout.emplace_back(COIN / 2, CScript{} << OP_TRUE);
        coins.emplace(outpoint, Coin{spent[i], /*nHeightIn=*/500, /*fCoinBaseIn=*/false});
    }
    const DemurrageSigningData demurrage{.input_values = {2 * COIN - 1234, 3 * COIN, 1 * COIN - 77}, .committed_ref_height = 500};
    DemurrageSigningData other{demurrage};
    other.input_values[2] += 1;

    for (const int hash_type : {SIGHASH_ALL | SIGHASH_DEMURRAGE, SIGHASH_NONE | SIGHASH_DEMURRAGE, SIGHASH_SINGLE | SIGHASH_DEMURRAGE}) {
        BOOST_TEST_INFO("hash type " << hash_type);
        // Without the values, the taproot inputs cannot be signed. The P2WPKH
        // input is signed without SIGHASH_DEMURRAGE.
        {
            CMutableTransaction mtx{unsigned_tx};
            std::map<int, bilingual_str> errors;
            BOOST_CHECK(!SignTransaction(mtx, &provider, coins, {.sighash_type = hash_type}, errors));
            BOOST_REQUIRE_EQUAL(errors.size(), 2U);
            BOOST_CHECK(errors.at(0).original.find("SIGHASH_DEMURRAGE") != std::string::npos);
            BOOST_CHECK(!errors.contains(2));
            BOOST_CHECK_EQUAL(mtx.vin[2].scriptWitness.stack.at(0).back(), hash_type & ~SIGHASH_DEMURRAGE);
        }
        // With them, every input is signed, and the taproot signatures commit to them.
        CMutableTransaction mtx{unsigned_tx};
        std::map<int, bilingual_str> errors;
        BOOST_REQUIRE(SignTransaction(mtx, &provider, coins, {.sighash_type = hash_type, .demurrage = demurrage}, errors));
        for (size_t i : {0, 1}) {
            BOOST_CHECK_EQUAL(mtx.vin[i].scriptWitness.stack.size(), 1U);
            BOOST_CHECK_EQUAL(mtx.vin[i].scriptWitness.stack[0].size(), 65U);
            BOOST_CHECK_EQUAL(mtx.vin[i].scriptWitness.stack[0].back(), hash_type);
        }
        BOOST_CHECK_EQUAL(mtx.vin[2].scriptWitness.stack.at(0).back(), hash_type & ~SIGHASH_DEMURRAGE);
        const CTransaction tx{mtx};
        BOOST_CHECK(VerifyInputs(tx, spent, demurrage) == (std::vector<ScriptError>{SCRIPT_ERR_OK, SCRIPT_ERR_OK, SCRIPT_ERR_OK}));
        BOOST_CHECK(VerifyInputs(tx, spent, other) == (std::vector<ScriptError>{SCRIPT_ERR_SCHNORR_SIG, SCRIPT_ERR_SCHNORR_SIG, SCRIPT_ERR_OK}));
        BOOST_CHECK(VerifyInputs(tx, spent, std::nullopt) == (std::vector<ScriptError>{SCRIPT_ERR_SCHNORR_SIG_HASHTYPE, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE, SCRIPT_ERR_OK}));

        // A PSBT signer uses the values in the PSBT's fields.
        PartiallySignedTransaction psbt{unsigned_tx, /*version=*/0};
        for (size_t i{0}; i < spent.size(); ++i) psbt.inputs[i].witness_utxo = spent[i];
        std::optional<PrecomputedTransactionData> txdata{PrecomputePSBTData(psbt)};
        const auto missing{SignPSBTInput(provider, psbt, 0, &*txdata, {.sighash_type = hash_type})};
        BOOST_CHECK(!missing.has_value() && missing.error() == common::PSBTError::DEMURRAGE_VALUES_MISSING);
        BOOST_CHECK(SignPSBTInput(provider, psbt, 2, &*txdata, {.sighash_type = hash_type}).has_value());
        const std::vector<uint32_t> ref_heights{431, 500, 499};
        for (size_t i{0}; i < spent.size(); ++i) SetDemurrageFields(psbt.inputs[i], ref_heights[i], demurrage.input_values[i]);
        // The input at the transaction's reference height (500) is worth its nominal value.
        BOOST_REQUIRE(GetDemurrageSigningData(psbt));
        txdata = PrecomputePSBTData(psbt);
        for (int i : {0, 1, 2}) BOOST_CHECK(SignPSBTInput(provider, psbt, i, &*txdata, {.sighash_type = hash_type}).has_value());
        // The PSBT records the hash type of the taproot inputs only.
        BOOST_CHECK_EQUAL(*psbt.inputs[0].sighash_type, hash_type);
        BOOST_CHECK_EQUAL(psbt.inputs[2].sighash_type.has_value(), (hash_type & ~SIGHASH_DEMURRAGE) != SIGHASH_ALL);
        CMutableTransaction extracted;
        BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted));
        BOOST_CHECK(VerifyInputs(CTransaction{extracted}, spent, demurrage) == (std::vector<ScriptError>{SCRIPT_ERR_OK, SCRIPT_ERR_OK, SCRIPT_ERR_OK}));
    }
}

namespace {
//! A regtest chain of 100 blocks, on which BIP 462 applies from height 105.
struct DemurrageChainSetup : public TestChain100Setup {
    static constexpr int ACTIVATION_HEIGHT{105};
    DemurrageChainSetup() : TestChain100Setup{ChainType::REGTEST, TestOpts{.extra_args = {"-testactivationheight=demurrage@105"}}} {}
};
} // namespace

BOOST_FIXTURE_TEST_CASE(activation_on_a_chain, DemurrageChainSetup)
{
    const CScript script{GetScriptForRawPubKey(coinbaseKey.GetPubKey())};
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    const Consensus::Params& consensus{chainman.GetConsensus()};
    BOOST_REQUIRE_EQUAL(consensus.DemurrageHeight, ACTIVATION_HEIGHT);

    // A block that spends a coinbase, below activation and above it. The node
    // tracks the value of the UTXO set ahead of activation, so the block
    // before activation has a state without a scan at that block.
    const auto spend{[&](size_t n) {
        return CreateValidTransaction({m_coinbase_txns[n]}, {COutPoint{m_coinbase_txns[n]->GetHash(), 0}}, /*input_height=*/static_cast<int>(n) + 1,
                                      {coinbaseKey}, {CTxOut{49 * COIN, script}}, /*feerate=*/std::nullopt, /*fee_output=*/std::nullopt).first;
    }};
    CreateAndProcessBlock({spend(0)}, script);
    while (WITH_LOCK(cs_main, return chainman.ActiveChain().Height()) < ACTIVATION_HEIGHT + 1) CreateAndProcessBlock({}, script);
    const CBlock block{CreateAndProcessBlock({spend(1)}, script)};

    LOCK(cs_main);
    const CChain& chain{chainman.ActiveChain()};
    node::BlockManager& blockman{chainman.m_blockman};
    BOOST_REQUIRE(chain.Tip()->GetBlockHash() == block.GetHash());
    BOOST_REQUIRE_EQUAL(chain.Height(), ACTIVATION_HEIGHT + 2);

    // The activation block, and no other, sets bit 31 of its version.
    for (int height{1}; height <= chain.Height(); ++height) {
        BOOST_CHECK_EQUAL(chain[height]->nVersion < 0, height == ACTIVATION_HEIGHT);
    }
    // Every coinbase from activation holds a demurrage commitment.
    BOOST_CHECK(GetCommitmentIndex(*block.vtx[0]).has_value());

    // The state before activation is the value of the UTXO set: 50 BTC per
    // block less the fee of the transaction spent below activation.
    const BlockState* baseline{blockman.GetDemurrageState(*chain[ACTIVATION_HEIGHT - 1])};
    BOOST_REQUIRE(baseline);
    BOOST_CHECK_EQUAL(baseline->index, INDEX_ONE);
    BOOST_CHECK_EQUAL(baseline->UtxoValue(), (ACTIVATION_HEIGHT - 1) * 50 * COIN - COIN);

    // Undo data is kept if it is written again unchanged.
    CBlockIndex& tip{*chain.Tip()};
    CBlockUndo undo;
    BOOST_REQUIRE(blockman.ReadBlockUndo(undo, tip));
    BOOST_REQUIRE_EQUAL(undo.vtxundo.size(), 1U);
    const FlatFilePos pos{tip.GetUndoPos()};
    BlockValidationState state;
    BOOST_REQUIRE(blockman.WriteBlockUndo(undo, state, tip));
    BOOST_CHECK(tip.GetUndoPos() == pos);

    // From activation, undo data that differs replaces what is stored: a node
    // without BIP 462 would have written it without reference heights.
    CBlockUndo other{undo};
    Coin& coin{other.vtxundo[0].vprevout[0]};
    BOOST_REQUIRE_EQUAL(coin.nRefHeight, 2U);
    coin.nRefHeight = 1;
    BOOST_REQUIRE(blockman.WriteBlockUndo(other, state, tip));
    BOOST_CHECK(tip.GetUndoPos() != pos);
    CBlockUndo read;
    BOOST_REQUIRE(blockman.ReadBlockUndo(read, tip));
    BOOST_CHECK_EQUAL(read.vtxundo[0].vprevout[0].nRefHeight, 1U);

    // Below activation it is never replaced.
    CBlockIndex& early{*chain[101]};
    BOOST_REQUIRE(blockman.ReadBlockUndo(undo, early));
    BOOST_REQUIRE_EQUAL(undo.vtxundo.size(), 1U);
    const FlatFilePos early_pos{early.GetUndoPos()};
    undo.vtxundo[0].vprevout[0].nRefHeight = 0;
    BOOST_REQUIRE(blockman.WriteBlockUndo(undo, state, early));
    BOOST_CHECK(early.GetUndoPos() == early_pos);
}

BOOST_AUTO_TEST_SUITE_END()
