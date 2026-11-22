#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate BIP 462 test vectors.

The vectors are computed with an implementation of the BIP's fixed-point
arithmetic that is independent of Bitcoin Core's C++ code. They are written
to src/test/data/bip462_tests.json, which src/test/demurrage_tests.cpp checks
Bitcoin Core against.

Usage: contrib/bip462/gen_test_vectors.py > src/test/data/bip462_tests.json
"""
import json
import sys

ONE = 10**18
COIN = 10**8
MAX_MONEY = 21_000_000 * COIN

# Mainnet parameters (BIP 462 "Parameters")
MAINNET = {"rate_period": 2016, "target_rate_num": 3, "target_rate_den": 52_560_000, "halving_interval": 210_000}


def subsidy(params, height):
    halvings = height // params["halving_interval"]
    return 0 if halvings >= 64 else (50 * COIN) >> halvings


def covered(params, period_start):
    """covered_k: the block subsidy schedule over the RATE_PERIOD blocks before the period."""
    return sum(subsidy(params, h) for h in range(max(0, period_start - params["rate_period"]), period_start))


def rate(params, utxo_value, covered_k):
    """r_k = max(0, target_k - covered_k) / (RATE_PERIOD * U_k), with target_k = TARGET_RATE_PER_BLOCK * U_k * RATE_PERIOD."""
    if utxo_value == 0:
        return 0
    period_value = utxo_value * params["rate_period"]
    target = period_value * params["target_rate_num"] // params["target_rate_den"]
    shortfall = max(0, target - covered_k)
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


def covered_vectors():
    """covered_k for rate periods around the 2032 halving (height 1,050,000)."""
    starts = [1_048_320, 1_050_336, 1_052_352, 13_440_000]
    return [{"period_start": h, "covered": covered(MAINNET, h)} for h in starts]


def rate_vectors():
    U = 20_000_000 * COIN
    target = U * 2016 * 3 // 52_560_000
    cases = [
        ("empty UTXO set", 0, 0),
        ("subsidy above target (2024-2028 subsidy, 3.125 BTC/block)", U, 2016 * 312_500_000),
        ("covered exactly equal to the target", U, target),
        ("covered one satoshi short of the target", U, target - 1),
        ("2032-2036 subsidy (0.78125 BTC/block)", U, 2016 * 78_125_000),
        ("a period spanning the 2032 halving", U, covered(MAINNET, 1_050_336)),
        ("no subsidy: rate equals the target rate", U, 0),
        ("one-satoshi UTXO set: target rounds down to zero", 1, 0),
        ("maximum UTXO set value, no subsidy", MAX_MONEY, 0),
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


def chain_vectors():
    """A short chain with small parameters. Each block's coinbase claims its
    full limit (subsidy + fees as fee_effective + dividend). Each fee-paying
    transaction spends one output entirely as fee: either an output created
    before activation (reference height below activation, index 1) or the
    coinbase output of an earlier block of the chain (its reference height is
    that block's height)."""
    params = {"activation_height": 8, "rate_period": 4, "target_rate_num": 1, "target_rate_den": 20, "halving_interval": 4}
    U0 = 10_000 * COIN
    # height -> list of spends: ("pre", value) or ("coinbase", height of the block whose coinbase output is spent)
    spends = {9: [("pre", 2 * COIN)], 12: [("pre", 10 * COIN), ("pre", 1)], 13: [("coinbase", 9)], 18: [("pre", 50_000), ("coinbase", 12)]}

    index = {h: ONE for h in range(params["activation_height"])}
    coinbase_value = {}
    state = {"index": ONE, "rate": 0, "normalized": normalized(U0, ONE)}
    blocks = []
    for h in range(8, 20):
        period_start = (h - params["activation_height"]) % params["rate_period"] == 0
        U_prev = utxo_value(state["normalized"], state["index"])
        cov = covered(params, h) if period_start else None
        r = rate(params, U_prev, cov) if period_start else state["rate"]
        index[h] = next_index(state["index"], r)
        div = dividend(r, U_prev)
        txs = []
        spent = 0
        for kind, arg in spends.get(h, []):
            ref, value = (5, arg) if kind == "pre" else (arg, coinbase_value[arg])
            fee_effective = effective(value, index[ref], index[h])
            txs.append({"value": value, "ref_height": ref, "fee_effective": fee_effective})
            spent += normalized(value, index[ref])
        fees = sum(t["fee_effective"] for t in txs)
        limit = subsidy(params, h) + fees + div
        coinbase_value[h] = limit
        n = state["normalized"] + normalized(limit, index[h]) - spent
        blocks.append({
            "height": h, "subsidy": subsidy(params, h), "rate_period_start": period_start,
            "covered": cov if period_start else 0, "rate": r, "index": index[h], "dividend": div,
            "txs": txs, "fees": fees, "coinbase_limit": limit, "utxo_value": utxo_value(n, index[h]),
        })
        state = {"index": index[h], "rate": r, "normalized": n}
    return {"params": params, "initial": {"utxo_value": U0}, "blocks": blocks}


def input_vectors():
    """Inherited reference heights and input valuation."""
    act = 100
    r = 57_077_625_570  # about the mainnet target rate
    index = {99: ONE}
    for h in range(100, 104):
        index[h] = next_index(index[h - 1], r)
    coins = {
        "pre": {"height": 50, "ref_height": 50, "value": COIN},                # created before activation
        "inherited": {"height": 102, "ref_height": 100, "value": 50_000_000},  # created at 102 by a tx with reference height 100
        "coinbase": {"height": 102, "ref_height": 102, "value": 20_000_000},   # a coinbase output at 102
    }

    def idx(h):
        return ONE if h < act else index[h]

    def case(comment, inputs, out_delta):
        ref = max(coins[i]["ref_height"] for i in inputs)
        value_in = sum(effective(coins[i]["value"], idx(coins[i]["ref_height"]), idx(ref)) for i in inputs)
        value_out = value_in + out_delta
        valid = value_out <= value_in
        return {"comment": comment, "spend_height": 103, "inputs": inputs, "value_out": value_out,
                "valid": valid, "reason": "" if valid else "bad-txns-in-belowout",
                "ref_height": ref, "fee": value_in - value_out if valid else 0}

    nominal = {k: v["value"] for k, v in coins.items()}
    cases = [
        case("pre-activation output alone: index 1, valued at its nominal value", ["pre"], -1000),
        case("one input alone is always valued at its nominal value", ["inherited"], -5000),
        case("mixed inputs: valued at the highest reference height", ["pre", "coinbase"], -1000),
        case("all three inputs", ["pre", "inherited", "coinbase"], -2500),
        case("outputs one satoshi above the inputs at the reference height", ["pre", "coinbase"], 1),
        case("outputs at the nominal sum of decayed inputs", ["pre", "inherited", "coinbase"],
             sum(nominal.values()) - sum(effective(coins[i]["value"], idx(coins[i]["ref_height"]), idx(102)) for i in coins)),
        case("zero fee", ["inherited", "coinbase"], 0),
    ]
    return {"activation_height": act, "index": [{"height": h, "index": i} for h, i in sorted(index.items())],
            "coins": coins, "cases": cases}


def main():
    vectors = {
        "comment": "BIP 462 test vectors, generated by contrib/bip462/gen_test_vectors.py. Fixed-point values are scaled by index_scale.",
        "index_scale": ONE,
        "mainnet_params": {k: MAINNET[k] for k in ("rate_period", "target_rate_num", "target_rate_den")},
        "covered": covered_vectors(),
        "rate": rate_vectors(),
        "index": index_vectors(),
        "effective_value": effective_value_vectors(),
        "utxo_value": utxo_vectors(),
        "dividend": dividend_vectors(),
        "chain": chain_vectors(),
        "inputs": input_vectors(),
    }
    json.dump(vectors, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
