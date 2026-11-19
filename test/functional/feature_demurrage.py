#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462 (target-based demurrage security budget).

Regtest parameters: RATE_PERIOD = 144 blocks, TARGET_RATE_PER_BLOCK = 1/500
(far above mainnet, so that demurrage is non-zero while regtest's subsidy,
which halves every 150 blocks, still exists), FEE_POOL_DIVISOR = 1000.

The test checks, against an independent Python model of the BIP's fixed-point
arithmetic:
- the reference height field (version 4) is invalid before activation;
- the UTXO set value at activation, the per-period rate, the index and the
  coinbase limit (subsidy + pool payout + dividend);
- the reference height rules (future, below input, version coupling) and
  input valuation at the reference height;
- the fee pool and fee_effective;
- pre-signed transactions stay valid while legacy ones decay;
- effective supply grows only by the subsidy;
- signatures commit to the reference height (legacy, BIP 143 and BIP 341);
- persistence across restarts and reorgs.
"""
from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    SIGHASH_DEFAULT,
    hash160,
    TaprootSignatureHash,
    sign_input_segwitv0,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2wpkh_script,
    keyhash_to_p2pkh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)

ACTIVATION_HEIGHT = 432
ONE = 10**18


def sat(amount):
    return int(Decimal(amount) * COIN)


def subsidy(height):
    halvings = height // 150
    return 0 if halvings >= 64 else (50 * COIN) >> halvings


class DemurrageModel:
    """Independent model of the BIP 462 fixed-point arithmetic."""

    def __init__(self, info):
        self.rate_period = info["rate_period"]
        self.num = info["target_rate_num"]
        self.den = info["target_rate_den"]
        self.divisor = info["fee_pool_divisor"]

    def rate(self, utxo_value, covered):
        if utxo_value == 0:
            return 0
        target = utxo_value * self.rate_period * self.num // self.den
        if target <= covered:
            return 0
        return (target - covered) * ONE // (self.rate_period * utxo_value)

    @staticmethod
    def next_index(index, rate):
        return index * (ONE - rate) // ONE

    @staticmethod
    def dividend(rate, utxo_value):
        return rate * utxo_value // ONE

    def payout(self, pool):
        return pool // self.divisor

    @staticmethod
    def effective(value, index_created, index_at):
        return value * index_at // index_created


class DemurrageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The wallet test runs only if the wallet is compiled.
        self.uses_wallet = None
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"]]

    def index_at(self, height):
        return self.nodes[0].getdemurrageinfo(height)["index"]

    def state(self, height=None):
        info = self.nodes[0].getdemurrageinfo() if height is None else self.nodes[0].getdemurrageinfo(height)
        return info

    def mine(self, n=1, **kwargs):
        return self.generate(self.wallet, n, **kwargs)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        info = node.getdemurrageinfo()
        assert_equal(info["activation_height"], ACTIVATION_HEIGHT)
        assert_equal(info["index_scale"], ONE)
        self.model = DemurrageModel(info)

        self.test_before_activation()
        self.test_activation()
        self.test_reference_height_rules()
        self.test_fee_pool_and_valuation()
        self.test_presigned_and_legacy()
        self.test_signatures_commit_to_ref_height()
        self.test_rate_period_and_supply()
        self.test_wallet()
        self.test_restart_and_reorg()

    def test_before_activation(self):
        node = self.nodes[0]
        self.log.info("Before activation, a reference height is invalid")
        self.mine(ACTIVATION_HEIGHT - 10)
        info = node.getdemurrageinfo()
        assert_equal(info["active"], False)
        assert_equal(info["index"], ONE)
        assert "next_block" not in info

        utxo = self.wallet.get_utxo(confirmed_only=True, mark_as_spent=False)
        tx = self.wallet.create_self_transfer(utxo_to_spend=utxo)["tx"]
        tx.version = CTransaction.REF_HEIGHT_VERSION
        tx.ref_height = node.getblockcount()
        self.wallet.sign_tx(tx)
        decoded = node.decoderawtransaction(tx.serialize().hex())
        assert_equal(decoded["ref_height"], tx.ref_height)
        assert_equal(decoded["txid"], tx.txid_hex)
        assert_raises_rpc_error(-26, "bad-txns-refheight-premature", node.sendrawtransaction, tx.serialize().hex())
        assert_raises_rpc_error(-25, "bad-txns-refheight-premature", self.generateblock, node, self.wallet.get_address(), [tx.serialize().hex()])

        self.log.info("Subsidy and fees are tracked from the period before activation")
        fee = self.wallet.send_self_transfer(from_node=node)["fee"]
        self.mine()
        start = ACTIVATION_HEIGHT - self.model.rate_period
        height = node.getblockcount()
        assert_equal(sat(self.state(height)["period_subsidy"]), sum(subsidy(h) for h in range(start, height + 1)))
        assert_equal(sat(self.state(height)["period_fees"]), sat(fee))
        assert "period_subsidy" not in self.state(start - 1)

        self.log.info("Legacy transactions leave the mempool when the next block activates BIP 462")
        self.mine(ACTIVATION_HEIGHT - 3 - node.getblockcount())
        legacy = self.wallet.send_self_transfer(from_node=node)
        assert legacy["txid"] in node.getrawmempool()
        self.generateblock(node, self.wallet.get_address(), [])  # ACTIVATION_HEIGHT - 2
        assert legacy["txid"] in node.getrawmempool()
        self.generateblock(node, self.wallet.get_address(), [])  # ACTIVATION_HEIGHT - 1
        assert_equal(node.getrawmempool(), [])
        self.wallet.rescan_utxos()
        assert_raises_rpc_error(-26, "demurrage-legacy-version", node.sendrawtransaction, legacy["hex"])

    def test_activation(self):
        node = self.nodes[0]
        self.log.info("The UTXO set value is taken at the block before activation")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        info = node.getdemurrageinfo()
        utxo_value = sat(info["utxo_value"])
        assert_equal(utxo_value, sat(node.gettxoutsetinfo()["total_amount"]))
        covered = sat(info["period_subsidy"]) + sat(info["period_fees"])
        assert_greater_than(sat(info["period_fees"]), 0)

        self.log.info("The first rate covers the shortfall of the previous period's subsidy and fees")
        rate = self.model.rate(utxo_value, covered)
        assert_greater_than(rate, 0)
        assert_greater_than(ONE * self.model.num // self.model.den, rate)
        nb = info["next_block"]
        assert_equal(nb["height"], ACTIVATION_HEIGHT)
        assert_equal(nb["rate_period_start"], True)
        assert_equal(nb["rate"], rate)
        assert_equal(nb["index"], self.model.next_index(ONE, rate))
        assert_equal(sat(nb["dividend"]), self.model.dividend(rate, utxo_value))
        assert_equal(sat(nb["pool_payout"]), 0)
        limit = subsidy(ACTIVATION_HEIGHT) + self.model.dividend(rate, utxo_value)
        assert_equal(sat(nb["coinbase_limit"]), limit)
        assert_equal(node.getblocktemplate({"rules": ["segwit"]})["coinbasevalue"], limit)

        self.log.info("The coinbase may claim subsidy + pool payout + dividend, and no more")
        tip = node.getbestblockhash()
        block_time = node.getblock(tip)["time"] + 1
        for value, result in ((limit + 1, "bad-cb-amount"), (limit, None)):
            coinbase = create_coinbase(ACTIVATION_HEIGHT, script_pubkey=self.wallet.get_output_script())
            coinbase.vout[0].nValue = value
            block = create_block(int(tip, 16), coinbase, ntime=block_time)
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), result)
        self.wallet.rescan_utxos()
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        info = node.getdemurrageinfo()
        assert_equal(info["active"], True)
        assert_equal(info["rate"], rate)
        assert_equal(info["index"], self.model.next_index(ONE, rate))
        assert_equal(sat(info["pool"]), 0)

    def test_reference_height_rules(self):
        node = self.nodes[0]
        tip = node.getblockcount()
        self.log.info("Inputs created before activation are valued at I(ref_height) / 1")
        utxo = self.wallet.get_utxo(confirmed_only=True, mark_as_spent=False)
        txout = node.gettxout(utxo["txid"], utxo["vout"])
        assert_equal(txout["ref_height"], ACTIVATION_HEIGHT)
        expected = self.model.effective(sat(txout["value"]), ONE, self.index_at(tip))
        assert_greater_than(sat(txout["value"]), expected)
        assert_equal(sat(txout["effective_value"]), expected)
        assert_equal(self.wallet.demurrage_effective_value(utxo, tip), expected)

        self.log.info("Legacy-version transactions are not relayed after activation")
        legacy = self.wallet.create_self_transfer(utxo_to_spend=utxo)["hex"]
        assert_raises_rpc_error(-26, "demurrage-legacy-version", node.sendrawtransaction, legacy)

        self.log.info("Version 4 requires a reference height, and only version 4 may carry one")
        tx = self.wallet.create_self_transfer(utxo_to_spend=utxo, ref_height=tip)["tx"]
        bad = CTransaction(tx)
        bad.ref_height = None
        self.wallet.sign_tx(bad)
        assert_raises_rpc_error(-26, "bad-txns-refheight-version", node.sendrawtransaction, bad.serialize().hex())
        bad = CTransaction(tx)
        bad.version = 2
        self.wallet.sign_tx(bad)
        assert_raises_rpc_error(-26, "bad-txns-refheight-version", node.sendrawtransaction, bad.serialize().hex())

        self.log.info("Rule 2: the reference height may not exceed the inclusion height")
        future = self.wallet.create_self_transfer(utxo_to_spend=utxo, ref_height=tip + 1)["tx"]
        future.ref_height = tip + 2
        self.wallet.sign_tx(future)
        assert_raises_rpc_error(-26, "bad-txns-refheight-future", node.sendrawtransaction, future.serialize().hex())

        self.log.info("Rule 1: the reference height may not be below that of an input")
        below = CTransaction(tx)
        below.ref_height = ACTIVATION_HEIGHT - 1
        self.wallet.sign_tx(below)
        assert_raises_rpc_error(-26, "bad-txns-refheight-below-input", node.sendrawtransaction, below.serialize().hex())

        self.log.info("Rule 5: outputs may not exceed the inputs valued at the reference height")
        value = self.wallet.demurrage_effective_value(utxo, tip)
        over = self.wallet.create_self_transfer_multi(utxos_to_spend=[utxo], ref_height=tip, amount_per_output=value + 1)["hex"]
        assert_raises_rpc_error(-26, "bad-txns-in-belowout", node.sendrawtransaction, over)
        nominal = self.wallet.create_self_transfer_multi(utxos_to_spend=[utxo], ref_height=tip, amount_per_output=sat(utxo["value"]) - 1000)["hex"]
        assert_raises_rpc_error(-26, "bad-txns-in-belowout", node.sendrawtransaction, nominal)

        self.log.info("A valid version 4 transaction: fee is measured at the reference height")
        self.wallet.get_utxo(txid=utxo["txid"], vout=utxo["vout"])  # mark as spent
        node.sendrawtransaction(tx.serialize().hex())
        self.wallet.scan_tx(node.decoderawtransaction(tx.serialize().hex()))
        entry = node.getmempoolentry(tx.txid_hex)
        assert_equal(sat(entry["fees"]["base"]), value - tx.vout[0].nValue)

        self.log.info("A child must not use a reference height below its unconfirmed parent's")
        parent = self.wallet.send_self_transfer(from_node=node, ref_height=tip + 1)
        child_utxo = parent["new_utxo"]
        assert_equal(node.gettxout(child_utxo["txid"], child_utxo["vout"])["ref_height"], tip + 1)
        child = self.wallet.create_self_transfer(utxo_to_spend=child_utxo, ref_height=tip + 1)["tx"]
        low = CTransaction(child)
        low.ref_height = tip
        self.wallet.sign_tx(low)
        assert_raises_rpc_error(-26, "bad-txns-refheight-below-input", node.sendrawtransaction, low.serialize().hex())
        self.wallet.sendrawtransaction(from_node=node, tx_hex=child.serialize().hex())
        self.pending = [tx, parent["tx"], child]

    def test_fee_pool_and_valuation(self):
        node = self.nodes[0]
        self.log.info("Fees enter the pool as fee_effective = fee * I(h) / I(ref_height)")
        prev_height = node.getblockcount()
        prev = self.state()
        fees = {t.txid_hex: sat(node.getmempoolentry(t.txid_hex)["fees"]["base"]) for t in self.pending}
        self.mine()
        height = prev_height + 1
        index_h = self.index_at(height)
        expected_fees = sum(self.model.effective(fees[t.txid_hex], self.index_at(t.ref_height), index_h) for t in self.pending)
        info = self.state()
        assert_equal(sat(info["pool"]), sat(prev["pool"]) - self.model.payout(sat(prev["pool"])) + expected_fees)
        assert_equal(sat(info["period_fees"]), sat(prev["period_fees"]) + expected_fees)
        # The tx with ref_height = height - 1 pays slightly less into the pool than its fee
        assert_greater_than(fees[self.pending[0].txid_hex], self.model.effective(fees[self.pending[0].txid_hex], self.index_at(prev_height), index_h))

        self.log.info("Outputs carry the reference height of their transaction and decay from it")
        out = node.gettxout(self.pending[0].txid_hex, 0)
        assert_equal(out["ref_height"], prev_height)
        assert_equal(sat(out["effective_value"]), self.model.effective(self.pending[0].vout[0].nValue, self.index_at(prev_height), index_h))
        out = node.gettxout(self.pending[2].txid_hex, 0)
        assert_equal(out["ref_height"], height)
        assert_equal(sat(out["effective_value"]), self.pending[2].vout[0].nValue)

        self.log.info("The pool pays out 1/FEE_POOL_DIVISOR of its balance per block")
        pool = sat(info["pool"])
        assert_greater_than(pool, 0)
        assert_equal(sat(info["next_block"]["pool_payout"]), self.model.payout(pool))
        limit = sat(info["next_block"]["coinbase_limit"])
        block = self.mine()[0]
        assert_equal(sat(node.getblock(block, 2)["tx"][0]["vout"][0]["value"]), limit)
        assert_equal(sat(self.state()["pool"]), pool - self.model.payout(pool))

    def test_presigned_and_legacy(self):
        node = self.nodes[0]
        self.log.info("A pre-signed version 4 transaction stays valid however long it waits")
        tip = node.getblockcount()
        utxo = self.wallet.get_utxo(confirmed_only=True)
        presigned = self.wallet.create_self_transfer(utxo_to_spend=utxo, ref_height=tip, fee=Decimal("0.00001"))
        self.mine(20)
        node.sendrawtransaction(presigned["hex"])
        self.mine()
        out = node.gettxout(presigned["txid"], 0)
        assert_equal(out["ref_height"], tip)
        assert_equal(sat(out["effective_value"]), self.model.effective(presigned["tx"].vout[0].nValue, self.index_at(tip), self.index_at(node.getblockcount())))

        self.log.info("A legacy transaction is valued at its inclusion height, so its fee margin decays")
        utxo = self.wallet.get_utxo(confirmed_only=True)
        tip = node.getblockcount()
        value = self.wallet.demurrage_effective_value(utxo, tip + 1)
        legacy = self.wallet.create_self_transfer_multi(utxos_to_spend=[utxo], amount_per_output=value - 1000)
        assert_equal(legacy["tx"].ref_height, None)
        # Signed for the next block; one block later its inputs no longer cover its outputs.
        self.generateblock(node, self.wallet.get_address(), [])
        assert_raises_rpc_error(-25, "bad-txns-in-belowout", self.generateblock, node, self.wallet.get_address(), [legacy["hex"]])
        # Mined directly by a miner in the block it was valued for, it is valid.
        self.nodes[0].invalidateblock(node.getbestblockhash())
        assert_equal(node.getblockcount(), tip)
        prev_pool = sat(self.state()["pool"])
        self.generateblock(node, self.wallet.get_address(), [legacy["hex"]])
        assert_equal(sat(self.state()["pool"]), prev_pool - self.model.payout(prev_pool) + 1000)
        self.wallet.rescan_utxos()

    def test_signatures_commit_to_ref_height(self):
        node = self.nodes[0]
        self.log.info("Legacy, BIP 143 and BIP 341 signatures commit to the reference height")
        tip = node.getblockcount()
        p2pk_wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)

        wkey = ECKey()
        wkey.generate()
        wpub = wkey.get_pubkey().get_bytes()
        tpriv = generate_privkey()
        tinfo = taproot_construct(compute_xonly_pubkey(tpriv)[0])
        amount = 10 * COIN
        funding = {}
        for name, spk in (("legacy", p2pk_wallet.get_output_script()), ("p2wpkh", key_to_p2wpkh_script(wpub)), ("p2tr", tinfo.scriptPubKey)):
            funding[name] = self.wallet.send_to(from_node=node, scriptPubKey=spk, amount=amount, ref_height=tip)
        self.mine()
        p2pk_wallet.rescan_utxos()
        ref = node.getblockcount()

        def spend(name):
            fund = funding[name]
            prevout = COutPoint(int(fund["txid"], 16), fund["sent_vout"])
            value = self.model.effective(amount, self.index_at(tip), self.index_at(ref))
            tx = CTransaction()
            tx.version = CTransaction.REF_HEIGHT_VERSION
            tx.ref_height = ref
            tx.vin = [CTxIn(prevout)]
            tx.vout = [CTxOut(value - 2000, self.wallet.get_output_script())]
            return tx

        def sign(name, tx):
            if name == "legacy":
                p2pk_wallet.sign_tx(tx)
            elif name == "p2wpkh":
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = [wpub]
                sign_input_segwitv0(tx, 0, keyhash_to_p2pkh_script(hash160(wpub)), amount, wkey)
            else:
                sighash = TaprootSignatureHash(tx, [CTxOut(amount, tinfo.scriptPubKey)], SIGHASH_DEFAULT, 0)
                tx.wit.vtxinwit = [CTxInWitness()]
                tx.wit.vtxinwit[0].scriptWitness.stack = [sign_schnorr(tweak_add_privkey(tpriv, tinfo.tweak), sighash)]

        for name in funding:
            tx = spend(name)
            sign(name, tx)
            # The same signature with a different reference height is invalid.
            mutated = CTransaction(tx)
            mutated.ref_height = ref - 1
            assert_raises_rpc_error(-26, "script-verify-flag-failed", node.sendrawtransaction, mutated.serialize().hex())
            node.sendrawtransaction(tx.serialize().hex())
        self.mine()
        assert_equal(node.getrawmempool(), [])

    def test_rate_period_and_supply(self):
        node = self.nodes[0]
        self.log.info("Each rate period's rate is set from the previous period's subsidy and fees")
        period_end = ACTIVATION_HEIGHT + self.model.rate_period - 1
        # Keep some fee-paying transactions flowing.
        while node.getblockcount() < period_end:
            self.wallet.send_self_transfer(from_node=node, ref_height=node.getblockcount())
            self.mine()
        info = self.state()
        assert_equal(info["height"], period_end)
        nb = info["next_block"]
        assert_equal(nb["rate_period_start"], True)
        covered = sat(info["period_subsidy"]) + sat(info["period_fees"])
        assert_equal(sat(info["period_subsidy"]), sum(subsidy(h) for h in range(ACTIVATION_HEIGHT, period_end + 1)))
        rate = self.model.rate(sat(info["utxo_value"]), covered)
        assert_equal(nb["rate"], rate)
        assert_equal(nb["index"], self.model.next_index(info["index"], rate))
        self.mine(3)
        assert_equal(self.state()["rate"], rate)

        self.log.info("Effective supply (UTXO set plus pool) grows only by the subsidy")
        for height in range(ACTIVATION_HEIGHT, node.getblockcount() + 1):
            before, after = self.state(height - 1), self.state(height)
            supply_before = sat(before["utxo_value"]) + sat(before["pool"])
            supply_after = sat(after["utxo_value"]) + sat(after["pool"])
            # Up to a few satoshis are lost to rounding down in each block.
            delta = supply_after - supply_before - subsidy(height)
            assert -10 <= delta <= 0, f"height {height}: effective supply changed by {delta} beyond the subsidy"

    def test_wallet(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping wallet test: wallet not compiled")
            return
        node = self.nodes[0]
        self.log.info("The wallet reports effective balances and creates version 4 transactions")
        node.createwallet("w")
        w = node.get_wallet_rpc("w")
        for _ in range(2):
            self.wallet.send_to(from_node=node, scriptPubKey=address_to_scriptpubkey(w.getnewaddress()), amount=5 * COIN, ref_height=node.getblockcount())
            self.mine()

        def effective_balance():
            return sum(node.gettxout(u["txid"], u["vout"])["effective_value"] for u in w.listunspent())

        assert_greater_than(Decimal(10), w.getbalance())
        assert_equal(w.getbalance(), effective_balance())
        assert_equal(w.getbalances()["mine"]["trusted"], effective_balance())

        tip = node.getblockcount()
        txid = w.sendtoaddress(self.wallet.get_address(), 7)  # needs both coins at their effective value
        tx = node.getrawtransaction(txid, True)
        assert_equal(tx["version"], CTransaction.REF_HEIGHT_VERSION)
        assert_equal(tx["ref_height"], tip)
        assert_equal(len(tx["vin"]), 2)
        self.mine()
        assert_equal(w.getbalance(), effective_balance())

        self.log.info("PSBTs (v0 and v2) carry the reference height")
        for psbt_version in (0, 2):
            psbt = w.walletcreatefundedpsbt(inputs=[], outputs=[{self.wallet.get_address(): 1}], psbt_version=psbt_version)["psbt"]
            decoded = node.decodepsbt(psbt)
            ref_height = decoded["tx"]["ref_height"] if psbt_version == 0 else decoded["ref_height"]
            assert_equal(ref_height, node.getblockcount())
            signed = w.walletprocesspsbt(psbt)
            assert_equal(signed["complete"], True)
            assert_equal(node.decoderawtransaction(signed["hex"])["ref_height"], node.getblockcount())
            node.sendrawtransaction(signed["hex"])
            self.mine()
        # Sending the whole effective balance is possible, and leaves nothing.
        w.sendtoaddress(self.wallet.get_address(), w.getbalance(), subtractfeefromamount=True)
        self.mine()
        assert_equal(w.listunspent(), [])
        self.wallet.rescan_utxos()

    def test_restart_and_reorg(self):
        node = self.nodes[0]
        self.log.info("Demurrage state persists across a restart")
        pending = self.wallet.send_self_transfer(from_node=node, ref_height=node.getblockcount())
        before = self.state()
        self.restart_node(0)
        assert_equal(self.state(), before)
        assert pending["txid"] in node.getrawmempool()

        self.log.info("State follows reorgs; mined version 4 transactions return to the mempool")
        self.mine()
        mined = self.state()
        tip = node.getbestblockhash()
        node.invalidateblock(tip)
        assert_equal(self.state(), before)
        assert pending["txid"] in node.getrawmempool()
        node.reconsiderblock(tip)
        assert_equal(self.state(), mined)

        self.log.info("Disconnecting the activation block makes reference heights premature again")
        pending = self.wallet.send_self_transfer(from_node=node, ref_height=node.getblockcount())
        activation_block = node.getblockhash(ACTIVATION_HEIGHT)
        node.invalidateblock(activation_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert pending["txid"] not in node.getrawmempool()
        assert "next_block" in self.state()
        node.reconsiderblock(activation_block)
        assert_equal(self.state(), mined)


if __name__ == '__main__':
    DemurrageTest(__file__).main()
