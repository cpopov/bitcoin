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
import hashlib
import json
import sys

ONE = 10**18
INDEX_MIN = 10**9
COMMITMENT_HEADER = hashlib.sha256(b"BIP462").digest()[:4]
COIN = 10**8
MAX_MONEY = 21_000_000 * COIN

# Mainnet parameters (BIP 462 "Parameters")
MAINNET = {"target_rate_num": 3, "target_rate_den": 52_560_000, "halving_interval": 210_000}


def subsidy(params, height):
    halvings = height // params["halving_interval"]
    return 0 if halvings >= 64 else (50 * COIN) >> halvings


def rate(params, utxo_value, block_subsidy, prev_index=ONE):
    """r(h) = max(0, target(h) - block_subsidy(h)) / U(h - 1), with target(h) = TARGET_RATE_PER_BLOCK * U(h - 1).
    Zero if the UTXO set is empty or I(h - 1) <= INDEX_MIN."""
    if utxo_value == 0 or prev_index <= INDEX_MIN:
        return 0
    target = utxo_value * params["target_rate_num"] // params["target_rate_den"]
    shortfall = max(0, target - block_subsidy)
    return shortfall * ONE // utxo_value


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


def rate_vectors():
    U = 20_000_000 * COIN
    target = U * 3 // 52_560_000
    cases = [
        ("empty UTXO set", 0, 0, ONE),
        ("subsidy above target (2028-2032 subsidy, 1.5625 BTC)", U, 156_250_000, ONE),
        ("subsidy exactly equal to the target", U, target, ONE),
        ("subsidy one satoshi short of the target", U, target - 1, ONE),
        ("the first block after the 2032 halving (0.78125 BTC)", U, subsidy(MAINNET, 1_260_000), ONE),
        ("2036-2040 subsidy (0.390625 BTC)", U, subsidy(MAINNET, 1_470_000), ONE * 99 // 100),
        ("no subsidy: rate equals the target rate", U, 0, ONE),
        ("one-satoshi UTXO set: target rounds down to zero", 1, 0, ONE),
        ("maximum UTXO set value, no subsidy", MAX_MONEY, 0, ONE),
        ("index one unit above INDEX_MIN: demurrage still applies", U, 0, INDEX_MIN + 1),
        ("index at INDEX_MIN: demurrage has stopped", U, 0, INDEX_MIN),
        ("index below INDEX_MIN", U, 0, INDEX_MIN - 57),
    ]
    return [{"comment": c, "utxo_value": u, "subsidy": s, "prev_index": i, "rate": rate(MAINNET, u, s, i)} for c, u, s, i in cases]


def index_vectors():
    max_rate = rate(MAINNET, 20_000_000 * COIN, 0)
    out = []
    blocks = 2016
    for comment, rates in (
        ("zero rate for 2,016 blocks", [0]),
        ("target rate for 2,016 blocks", [max_rate]),
        ("target rate for 26 runs of 2,016 blocks (~one year)", [max_rate] * 26),
        ("a sequence of rates, each for 2,016 blocks", [0, max_rate // 3, max_rate // 2, max_rate]),
    ):
        index = ONE
        indexes = []
        for r in rates:
            for _ in range(blocks):
                index = next_index(index, r)
            indexes.append(index)
        out.append({"comment": comment, "blocks": blocks, "rates": rates, "indexes": indexes})
    return out


def floor_vectors():
    """The last blocks before the index reaches INDEX_MIN, at the full target
    rate with no subsidy, and the blocks after it: the rate is zero and the
    index stops falling."""
    U = 20_000_000 * COIN
    index = INDEX_MIN + 200
    out = []
    for _ in range(8):
        r = rate(MAINNET, U, 0, index)
        nxt = next_index(index, r)
        out.append({"prev_index": index, "rate": r, "index": nxt})
        index = nxt
    return {"utxo_value": U, "subsidy": 0, "blocks": out}


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
    params = {"activation_height": 8, "target_rate_num": 1, "target_rate_den": 20, "halving_interval": 4}
    U0 = 10_000 * COIN
    # height -> list of spends: ("pre", value) or ("coinbase", height of the block whose coinbase output is spent)
    spends = {9: [("pre", 2 * COIN)], 12: [("pre", 10 * COIN), ("pre", 1)], 13: [("coinbase", 9)], 18: [("pre", 50_000), ("coinbase", 12)]}

    index = {h: ONE for h in range(params["activation_height"])}
    coinbase_value = {}
    state = {"index": ONE, "rate": 0, "normalized": normalized(U0, ONE)}
    blocks = []
    for h in range(8, 20):
        U_prev = utxo_value(state["normalized"], state["index"])
        r = rate(params, U_prev, subsidy(params, h), state["index"])
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
            "height": h, "subsidy": subsidy(params, h), "rate": r, "index": index[h], "dividend": div,
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


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(leaves):
    """The Merkle root, computed as a block's transaction Merkle root is."""
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def commitment_vectors():
    """The demurrage commitment of a block. Transaction ids are given as they
    are displayed, and hashed in their serialized (reversed) byte order. The
    first transaction is the coinbase: its leaf uses 32 zero bytes."""
    act = 100
    out = []
    for comment, height, index, r, normalized_prev, txs in (
        ("a block with only a coinbase", 100, ONE, 0, normalized(20_000_000 * COIN, ONE), []),
        ("reference heights below activation are committed as ACTIVATION_HEIGHT - 1", 250,
         ONE * 997 // 1000, 57_077_625_570, normalized(20_000_000 * COIN, ONE) + 12345,
         [("11" * 32, 7), ("22" * 32, 99), ("33" * 32, 100), ("44" * 32, 149)]),
        ("an odd number of leaves", 251, ONE * 996 // 1000, 1, 1, [("ab" * 32, 150), ("cd" * 32, 0)]),
    ):
        leaves = [sha256d(bytes(32) + height.to_bytes(4, "little"))]
        committed = []
        for txid, ref in txs:
            ref_committed = max(ref, act - 1)
            committed.append(ref_committed)
            leaves.append(sha256d(bytes.fromhex(txid)[::-1] + ref_committed.to_bytes(4, "little")))
        root = merkle_root(leaves)
        state = index.to_bytes(8, "little") + r.to_bytes(8, "little") + normalized_prev.to_bytes(32, "little")
        commitment = sha256d(state + root)
        out.append({
            "comment": comment, "activation_height": act, "height": height, "index": index, "rate": r,
            "prev_normalized": str(normalized_prev),
            "txs": [{"txid": txid, "ref_height": ref, "committed_ref_height": c} for (txid, ref), c in zip(txs, committed)],
            "ref_height_root": root.hex(), "commitment": commitment.hex(),
            "script": (bytes([0x6a, 0x24]) + COMMITMENT_HEADER + commitment).hex(),
        })
    return out


def sha256(data):
    return hashlib.sha256(data).digest()


def tagged_hash(tag, data):
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def ser_script(script_hex):
    script = bytes.fromhex(script_hex)
    assert len(script) < 253
    return bytes([len(script)]) + script


def ser_output(output):
    return output["amount"].to_bytes(8, "little") + ser_script(output["script_pubkey"])


def sighash_vectors():
    """The BIP 341 signature message with SIGHASH_DEMURRAGE: computed as for
    hash_type & 0x3f, except that its first byte is the full hash_type and
    that sha_input_values and ref_height follow sha_sequences."""
    act = 1000
    index = {act - 1: ONE, 1200: ONE * 9991 // 10000, 1500: ONE * 9973 // 10000}
    tapleaf_hash = tagged_hash("TapLeaf", bytes([0xc0]) + ser_script("20" + "5b" * 32 + "ac"))
    out = []
    for comment, ref_heights in (
        ("inputs with three reference heights, one of them below activation", [400, 1200, 1500]),
        ("every input below activation: valued nominally, and committed as ACTIVATION_HEIGHT - 1", [400, 77, 999]),
        ("the highest reference height is that of the first input", [1500, 1200, 1200]),
    ):
        inputs = [
            {"txid": "a1" * 32, "vout": 0, "sequence": 0xfffffffd, "amount": 125_000_000, "script_pubkey": "5120" + "c1" * 32},
            {"txid": "b2" * 32, "vout": 3, "sequence": 0xffffffff, "amount": 2_099_999_997_690_000, "script_pubkey": "5120" + "d2" * 32},
            {"txid": "c3" * 32, "vout": 1, "sequence": 144, "amount": 546, "script_pubkey": "0014" + "e3" * 20},
        ]
        outputs = [
            {"amount": 100_000_000, "script_pubkey": "5120" + "f4" * 32},
            {"amount": 20_000, "script_pubkey": "6a04deadbeef"},
        ]
        version, locktime = 2, 1499
        # A transaction's reference height is the highest among the outputs it
        # spends. Each input is valued at its index.
        ref_height = max(ref_heights)
        committed = max(ref_height, act - 1)
        def index_at(h):
            return index[max(h, act - 1)]
        for txin, ref in zip(inputs, ref_heights):
            txin["ref_height"] = ref
            txin["value"] = effective(txin["amount"], index_at(ref), index_at(ref_height))

        sha_prevouts = sha256(b"".join(bytes.fromhex(i["txid"])[::-1] + i["vout"].to_bytes(4, "little") for i in inputs))
        sha_amounts = sha256(b"".join(i["amount"].to_bytes(8, "little") for i in inputs))
        sha_scriptpubkeys = sha256(b"".join(ser_script(i["script_pubkey"]) for i in inputs))
        sha_sequences = sha256(b"".join(i["sequence"].to_bytes(4, "little") for i in inputs))
        sha_input_values = sha256(b"".join(i["value"].to_bytes(8, "little") for i in inputs))
        sha_outputs = sha256(b"".join(ser_output(o) for o in outputs))

        cases = []
        for hash_type in (0x41, 0x42, 0x43):
            for input_index, script_path in ((0, False), (1, True)):
                msg = bytes([hash_type]) + version.to_bytes(4, "little") + locktime.to_bytes(4, "little")
                msg += sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences
                msg += sha_input_values + committed.to_bytes(4, "little")
                if hash_type & 3 == 1:
                    msg += sha_outputs
                msg += bytes([2 if script_path else 0]) + input_index.to_bytes(4, "little")
                if hash_type & 3 == 3:
                    msg += sha256(ser_output(outputs[input_index]))
                assert len(msg) <= 242
                # BIP 342 appends its extension to the common signature message.
                ext = tapleaf_hash + bytes([0]) + (0xffffffff).to_bytes(4, "little") if script_path else b""
                case = {"hash_type": hash_type, "input_index": input_index, "sig_msg": msg.hex()}
                if script_path:
                    case["tapleaf_hash"] = tapleaf_hash.hex()
                    case["ext"] = ext.hex()
                case["sighash"] = tagged_hash("TapSighash", bytes([0]) + msg + ext).hex()
                cases.append(case)
        out.append({
            "comment": comment, "activation_height": act,
            "index": [{"height": h, "index": i} for h, i in sorted(index.items())],
            "version": version, "locktime": locktime, "inputs": inputs, "outputs": outputs,
            "ref_height": ref_height, "committed_ref_height": committed,
            "sha_input_values": sha_input_values.hex(), "cases": cases,
        })
    return out


def main():
    vectors = {
        "comment": "BIP 462 test vectors, generated by contrib/bip462/gen_test_vectors.py. Fixed-point values are scaled by index_scale.",
        "index_scale": ONE,
        "index_min": INDEX_MIN,
        "mainnet_params": {k: MAINNET[k] for k in ("target_rate_num", "target_rate_den")},
        "rate": rate_vectors(),
        "index": index_vectors(),
        "index_floor": floor_vectors(),
        "effective_value": effective_value_vectors(),
        "utxo_value": utxo_vectors(),
        "dividend": dividend_vectors(),
        "chain": chain_vectors(),
        "inputs": input_vectors(),
        "commitment": commitment_vectors(),
        "sighash": sighash_vectors(),
    }
    json.dump(vectors, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
