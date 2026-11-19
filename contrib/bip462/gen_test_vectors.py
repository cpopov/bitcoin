#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate BIP 462 test vectors.

The vectors are computed with an implementation of the BIP's fixed-point
arithmetic that is independent of Bitcoin Core's C++ code, plus the Python
functional test framework's transaction serialization and signature hashing.
They are written to src/test/data/bip462_tests.json, which
src/test/demurrage_tests.cpp checks Bitcoin Core against.

Usage: contrib/bip462/gen_test_vectors.py > src/test/data/bip462_tests.json
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../test/functional"))

from test_framework.messages import (  # noqa: E402
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (  # noqa: E402
    CScript,
    LegacySignatureHash,
    OP_CHECKSIG,
    OP_TRUE,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    SIGHASH_SINGLE,
    SegwitV0SignatureHash,
    TaprootSignatureHash,
)

ONE = 10**18
COIN = 10**8
MAX_MONEY = 21_000_000 * COIN

# Mainnet parameters (BIP 462 "Parameters")
MAINNET = {"rate_period": 2016, "target_rate_num": 3, "target_rate_den": 52_560_000, "fee_pool_divisor": 1000}


def rate(params, utxo_value, covered):
    """r_k = max(0, target_k - covered_k) / (RATE_PERIOD * U_k), with target_k = TARGET_RATE_PER_BLOCK * U_k * RATE_PERIOD."""
    if utxo_value == 0:
        return 0
    period_value = utxo_value * params["rate_period"]
    target = period_value * params["target_rate_num"] // params["target_rate_den"]
    shortfall = max(0, target - covered)
    return shortfall * ONE // period_value


def next_index(index, r):
    return index * (ONE - r) // ONE


def effective(value, index_created, index_at):
    return value * index_at // index_created


def normalized(value, index_created):
    return value * ONE * ONE // index_created


def utxo_value(normalized_total, index):
    return normalized_total * index // (ONE * ONE)


def dividend(r, value):
    return r * value // ONE


def payout(params, pool):
    return pool // params["fee_pool_divisor"]


def rate_vectors():
    U = 20_000_000 * COIN
    target = U * 2016 * 3 // 52_560_000
    cases = [
        ("empty UTXO set", 0, 0),
        ("subsidy above target (2024-2028 subsidy, 3.125 BTC/block)", U, 2016 * 312_500_000),
        ("covered exactly equal to the target", U, target),
        ("covered one satoshi short of the target", U, target - 1),
        ("2032-2036 subsidy (0.78125 BTC/block) plus ~1,000 BTC/year of fees", U, 2016 * 78_125_000 + 1000 * COIN * 2016 // 52_560),
        ("no subsidy, ~1,000 BTC/year of fees", U, 1000 * COIN * 2016 // 52_560),
        ("nothing covered: rate equals the target rate", U, 0),
        ("one-satoshi UTXO set: target rounds down to zero", 1, 0),
        ("maximum UTXO set value, nothing covered", MAX_MONEY, 0),
    ]
    return [{"comment": c, "utxo_value": u, "covered": cov, "rate": rate(MAINNET, u, cov)} for c, u, cov in cases]


def index_vectors():
    max_rate = rate(MAINNET, 20_000_000 * COIN, 0)
    out = []
    for comment, rates in (
        ("zero rate for one period", [0]),
        ("target rate for one period", [max_rate]),
        ("target rate for 26 periods (~one year)", [max_rate] * 26),
        ("a sequence of rate periods", [0, max_rate // 3, max_rate // 2, max_rate]),
    ):
        index = ONE
        indexes = []
        for r in rates:
            for _ in range(MAINNET["rate_period"]):
                index = next_index(index, r)
            indexes.append(index)
        out.append({"comment": comment, "rate_period": MAINNET["rate_period"], "rates": rates, "indexes": indexes})
    return out


def effective_value_vectors():
    i1 = ONE * 997 // 1000
    i2 = next_index(i1, 57_077_625_570)
    cases = [
        ("same index: nominal value", 123_456_789, i1, i1),
        ("pre-activation output, index 1", 50 * COIN, ONE, i1),
        ("later output", 50 * COIN, i1, i2),
        ("rounds down to zero", 1, ONE, ONE - 1),
        ("maximum money at half the index", MAX_MONEY, ONE, ONE // 2),
    ]
    return [{"comment": c, "value": v, "index_created": ic, "index_at": ia, "result": effective(v, ic, ia)} for c, v, ic, ia in cases]


def utxo_vectors():
    """Normalized UTXO totals and the effective value U they represent."""
    outputs = [(50 * COIN, ONE), (12_345_678, ONE * 999 // 1000), (1, ONE // 3), (MAX_MONEY // 2, ONE * 998_123 // 1_000_000)]
    total = 0
    out = []
    for value, index_created in outputs:
        n = normalized(value, index_created)
        total += n
        out.append({"value": value, "index_created": index_created, "normalized": str(n)})
    at = ONE * 997 // 1000
    return {"outputs": out, "normalized_total": str(total), "index": at, "utxo_value": utxo_value(total, at)}


def dividend_vectors():
    max_rate = rate(MAINNET, 20_000_000 * COIN, 0)
    cases = [(0, 20_000_000 * COIN), (max_rate, 20_000_000 * COIN), (max_rate, 1), (ONE // 2, 3)]
    return [{"rate": r, "utxo_value": u, "dividend": dividend(r, u)} for r, u in cases]


def fee_pool_vectors():
    fees = [100 * COIN, 0, 0, 5 * COIN, 0, 1, 0, 999, 1000, 0]
    pool = 0
    blocks = []
    for f in fees:
        p = payout(MAINNET, pool)
        pool = pool - p + f
        blocks.append({"fees": f, "payout": p, "pool": pool})
    return {"fee_pool_divisor": MAINNET["fee_pool_divisor"], "blocks": blocks}


def chain_vectors():
    """A short chain with small parameters. Each block's coinbase claims its
    full limit; a block's fees are paid by spending an output worth exactly
    the fee at the block's index."""
    params = {"activation_height": 8, "rate_period": 4, "target_rate_num": 1, "target_rate_den": 20, "fee_pool_divisor": 10, "halving_interval": 4}

    def subsidy(h):
        return (50 * COIN) >> (h // params["halving_interval"])

    U0 = 10_000 * COIN
    prev = {"index": ONE, "rate": 0, "pool": 0, "normalized": normalized(U0, ONE),
            "period_subsidy": sum(subsidy(h) for h in range(4, 8)), "period_fees": 3 * COIN}
    blocks = []
    fees_by_height = {9: 2 * COIN, 12: 10 * COIN, 13: 1, 18: 50_000}
    for h in range(8, 20):
        period_start = (h - params["activation_height"]) % params["rate_period"] == 0
        U_prev = utxo_value(prev["normalized"], prev["index"])
        r = rate(params, U_prev, prev["period_subsidy"] + prev["period_fees"]) if period_start else prev["rate"]
        index = next_index(prev["index"], r)
        div = dividend(r, U_prev)
        pay = payout(params, prev["pool"])
        limit = subsidy(h) + pay + div
        fee = fees_by_height.get(h, 0)
        n = prev["normalized"] + normalized(limit, index) - normalized(fee, index)
        state = {
            "index": index, "rate": r, "pool": prev["pool"] - pay + fee, "normalized": n,
            "period_subsidy": (0 if period_start else prev["period_subsidy"]) + subsidy(h),
            "period_fees": (0 if period_start else prev["period_fees"]) + fee,
        }
        blocks.append({
            "height": h, "subsidy": subsidy(h), "fees": fee,
            "rate_period_start": period_start, "rate": r, "index": index, "dividend": div,
            "pool_payout": pay, "coinbase_limit": limit, "pool": state["pool"],
            "utxo_value": utxo_value(n, index), "period_subsidy": state["period_subsidy"], "period_fees": state["period_fees"],
        })
        prev = state
    return {"params": params, "initial": {"utxo_value": U0, "period_subsidy": sum(subsidy(h) for h in range(4, 8)), "period_fees": 3 * COIN}, "blocks": blocks}


def input_vectors():
    """Reference height rules and input valuation (BIP 462 'Transaction reference height')."""
    act = 100
    r = 57_077_625_570  # about the mainnet target rate
    index = {99: ONE}
    for h in range(100, 104):
        index[h] = next_index(index[h - 1], r)
    coins = {
        "pre": {"height": 50, "ref_height": 50, "value": COIN},          # created before activation
        "v4": {"height": 102, "ref_height": 100, "value": 50_000_000},   # version 4 tx, ref_height 100, mined at 102
        "legacy": {"height": 102, "ref_height": 102, "value": 20_000_000},  # legacy tx mined at 102
    }

    def coin_index(c):
        return ONE if c["height"] < act else index[c["ref_height"]]

    def min_ref(c):
        return act if c["height"] < act else c["ref_height"]

    def case(comment, spend_height, ref_height, inputs, out_delta):
        ref = spend_height if ref_height is None else ref_height
        value_in = None
        reason = None
        if ref > spend_height:
            reason = "bad-txns-refheight-future"
        elif ref < act or any(ref < min_ref(coins[i]) for i in inputs):
            reason = "bad-txns-refheight-below-input"
        else:
            value_in = sum(effective(coins[i]["value"], coin_index(coins[i]), index[ref]) for i in inputs)
        # Outputs are expressed relative to the (valid-case) input value at the reference height.
        base = value_in if value_in is not None else sum(coins[i]["value"] for i in inputs)
        value_out = base + out_delta
        if reason is None and value_out > value_in:
            reason = "bad-txns-in-belowout"
        return {"comment": comment, "spend_height": spend_height, "ref_height": ref_height, "inputs": inputs,
                "value_out": value_out, "valid": reason is None, "reason": reason or "",
                "fee": (value_in - value_out) if reason is None else 0}

    cases = [
        case("legacy spend of a pre-activation output, valued at the inclusion height", 103, None, ["pre"], -1000),
        case("version 4 spend of all three, valued at its reference height", 103, 102, ["pre", "v4", "legacy"], -5000),
        case("reference height equal to the inclusion height", 103, 103, ["pre"], -1),
        case("rule 2: reference height in the future", 103, 104, ["pre"], -1000),
        case("rule 1: reference height below activation", 103, 99, ["pre"], -1000),
        case("rule 1: reference height below an input's", 103, 101, ["legacy"], -1000),
        case("rule 1: equal to the input's reference height", 103, 100, ["v4"], 0),
        case("rule 5: outputs exceed inputs at the reference height", 103, 102, ["pre", "v4"], 1),
        case("legacy spend paying the nominal value", 103, None, ["pre"], COIN - effective(COIN, ONE, index[103])),
    ]
    return {"activation_height": act, "index": [{"height": h, "index": i} for h, i in sorted(index.items())],
            "coins": coins, "cases": cases}


def tx_vectors():
    """Serialization of a version 4 transaction and its signature hashes."""
    tx = CTransaction()
    tx.version = CTransaction.REF_HEIGHT_VERSION
    tx.nLockTime = 1_000_000
    tx.ref_height = 1_234_567
    tx.vin = [CTxIn(COutPoint(0x1111, 0), nSequence=0xfffffffd), CTxIn(COutPoint(0x2222, 3), nSequence=0xffffffff)]
    tx.vout = [CTxOut(40 * COIN, CScript([OP_TRUE])), CTxOut(9 * COIN, CScript([b"\x02" + b"\x11" * 32, OP_CHECKSIG]))]
    no_witness = CTransaction(tx)
    tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
    tx.wit.vtxinwit[1].scriptWitness.stack = [b"\x01" * 64]

    spent = [CTxOut(30 * COIN, CScript([OP_TRUE])), CTxOut(20 * COIN, bytes.fromhex("5120" + "33" * 32))]
    script_code = CScript([b"\x02" + b"\x22" * 32, OP_CHECKSIG])
    sighashes = []
    for hash_type in (SIGHASH_ALL, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY):
        legacy, err = LegacySignatureHash(script_code, tx, 0, hash_type)
        assert err is None
        sighashes.append({"sigversion": "base", "input": 0, "hash_type": hash_type, "script_code": script_code.hex(), "sighash": legacy.hex()})
        sighashes.append({"sigversion": "witness_v0", "input": 0, "hash_type": hash_type, "script_code": script_code.hex(), "amount": spent[0].nValue,
                          "sighash": SegwitV0SignatureHash(script_code, tx, 0, hash_type, spent[0].nValue).hex()})
    for hash_type in (SIGHASH_DEFAULT, SIGHASH_ALL | SIGHASH_ANYONECANPAY):
        sighashes.append({"sigversion": "taproot", "input": 1, "hash_type": hash_type,
                          "sighash": TaprootSignatureHash(tx, spent, hash_type, 1).hex()})
    return {
        "hex": tx.serialize().hex(), "txid": tx.txid_hex, "wtxid": tx.wtxid_hex,
        "hex_no_witness": no_witness.serialize().hex(), "txid_no_witness": no_witness.txid_hex, "wtxid_no_witness": no_witness.wtxid_hex,
        "ref_height": tx.ref_height,
        "spent_outputs": [{"value": o.nValue, "script_pubkey": o.scriptPubKey.hex()} for o in spent],
        "sighashes": sighashes,
    }


def main():
    vectors = {
        "comment": "BIP 462 test vectors, generated by contrib/bip462/gen_test_vectors.py. Fixed-point values are scaled by index_scale.",
        "index_scale": ONE,
        "mainnet_params": MAINNET,
        "rate": rate_vectors(),
        "index": index_vectors(),
        "effective_value": effective_value_vectors(),
        "utxo_value": utxo_vectors(),
        "dividend": dividend_vectors(),
        "fee_pool": fee_pool_vectors(),
        "chain": chain_vectors(),
        "inputs": input_vectors(),
        "transaction": tx_vectors(),
    }
    json.dump(vectors, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
