#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462 (target-based demurrage security budget).

Regtest parameters: RATE_PERIOD = 144 blocks and TARGET_RATE_PER_BLOCK = 1/500,
far above mainnet, so that demurrage is non-zero while regtest's subsidy,
which halves every 150 blocks, still exists.

The test checks, against an independent Python model of the BIP's fixed-point
arithmetic:
- the UTXO set value at activation, the per-period rate (from the subsidy
  schedule only), the index and the coinbase limit (subsidy + fee_effective +
  dividend);
- inherited reference heights: a transaction is valued at the highest
  reference height among its inputs, and its outputs inherit it;
- transactions signed before activation, and pre-signed TRUC packages, stay
  valid however long they wait;
- effective supply grows only by the subsidy;
- the wallet, PSBTs, and effective values in RPC and REST;
- the consensus behaviour BIP 462's Layer 2 section relies on: pre-signed
  commitment and second-stage transactions, and SIGHASH_SINGLE |
  SIGHASH_ANYONECANPAY transactions that add a younger input;
- restarts, reorgs, and a node upgraded after activation.
"""
from decimal import Decimal
import http.client
import json
import urllib.parse

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
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
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE,
    SegwitV0SignatureHash,
    hash160,
)
from test_framework.script_util import (
    PAY_TO_ANCHOR,
    key_to_p2wpkh_script,
    keyhash_to_p2pkh_script,
    keys_to_multisig_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair

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

    def covered(self, period_start):
        return sum(subsidy(h) for h in range(max(0, period_start - self.rate_period), period_start))

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

    @staticmethod
    def effective(value, index_created, index_at):
        return value * index_at // index_created


class DemurrageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # The wallet test runs only if the wallet is compiled.
        self.uses_wallet = None
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}", "-rest"]]

    def index_at(self, height):
        return self.wallet.demurrage_index(height)

    def state(self, height=None):
        return self.nodes[0].getdemurrageinfo() if height is None else self.nodes[0].getdemurrageinfo(height)

    def mine(self, n=1):
        return self.generate(self.wallet, n)

    def ref_height(self, txid, vout=0):
        return self.nodes[0].gettxout(txid, vout)["ref_height"]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        info = node.getdemurrageinfo()
        assert_equal(info["activation_height"], ACTIVATION_HEIGHT)
        assert_equal(info["index_scale"], ONE)
        self.model = DemurrageModel(info)

        self.test_before_activation()
        self.test_activation()
        self.test_presigned_before_activation()
        self.test_inherited_reference_heights()
        self.test_fees_to_producer()
        self.test_truc_commitments()
        self.test_rate_period_and_supply()
        self.test_wallet()
        self.test_effective_value_reporting()
        self.test_layer2()
        self.test_restart_and_reorg()
        self.test_upgrade_after_activation()

    def test_before_activation(self):
        node = self.nodes[0]
        self.log.info("Before activation, nothing changes")
        self.mine(ACTIVATION_HEIGHT - 20)
        info = node.getdemurrageinfo()
        assert_equal(info["active"], False)
        assert_equal(info["index"], ONE)
        assert "next_block" not in info
        assert "ref_height" not in node.gettxout(*self.any_utxo())

        self.log.info("Pre-sign a transaction before activation, with a 1,000 sat fee")
        utxo = self.wallet.get_utxo(confirmed_only=True)
        self.presigned = self.wallet.create_self_transfer(utxo_to_spend=utxo, fee=Decimal("0.00001"))

        self.log.info("Transactions in the mempool stay there across activation")
        self.mine(ACTIVATION_HEIGHT - 3 - node.getblockcount())
        # MiniWallet rescans after mining, so keep the pre-signed input apart.
        presigned_input = self.presigned["tx"].vin[0].prevout
        other = next(u for u in self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
                     if (int(u["txid"], 16), u["vout"]) != (presigned_input.hash, presigned_input.n))
        self.pending = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=other)
        self.generateblock(node, self.wallet.get_address(), [])  # ACTIVATION_HEIGHT - 2
        self.generateblock(node, self.wallet.get_address(), [])  # ACTIVATION_HEIGHT - 1
        assert self.pending["txid"] in node.getrawmempool()

    def any_utxo(self):
        utxo = self.wallet.get_utxo(confirmed_only=True, mark_as_spent=False)
        return utxo["txid"], utxo["vout"]

    def test_activation(self):
        node = self.nodes[0]
        self.log.info("The UTXO set value is taken at the block before activation")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        info = node.getdemurrageinfo()
        utxo_value = sat(info["utxo_value"])
        assert_equal(utxo_value, sat(node.gettxoutsetinfo()["total_amount"]))

        self.log.info("The first rate covers the shortfall of the previous period's subsidy schedule")
        nb = info["next_block"]
        covered = self.model.covered(ACTIVATION_HEIGHT)
        assert_equal(sat(nb["covered"]), covered)
        rate = self.model.rate(utxo_value, covered)
        assert_greater_than(rate, 0)
        assert_greater_than(ONE * self.model.num // self.model.den, rate)
        assert_equal(nb["height"], ACTIVATION_HEIGHT)
        assert_equal(nb["rate_period_start"], True)
        assert_equal(nb["rate"], rate)
        assert_equal(nb["index"], self.model.next_index(ONE, rate))
        dividend = self.model.dividend(rate, utxo_value)
        assert_equal(sat(nb["dividend"]), dividend)
        limit = subsidy(ACTIVATION_HEIGHT) + dividend
        assert_equal(sat(nb["coinbase_limit_before_fees"]), limit)

        self.log.info("The template's coinbase claims the subsidy, the fees at the block's index and the dividend")
        fee = sat(node.getmempoolentry(self.pending["txid"])["fees"]["base"])
        # The pending transaction spends a coin created before activation (index 1).
        fee_effective = self.model.effective(fee, ONE, nb["index"])
        assert_equal(node.getblocktemplate({"rules": ["segwit"]})["coinbasevalue"], limit + fee_effective)

        self.log.info("A coinbase may claim subsidy + fees + dividend, and no more")
        tip = node.getbestblockhash()
        block_time = node.getblock(tip)["time"] + 1
        for value, result in ((limit + 1, "bad-cb-amount"), (limit, None)):
            coinbase = create_coinbase(ACTIVATION_HEIGHT, script_pubkey=self.wallet.get_output_script())
            coinbase.vout[0].nValue = value
            block = create_block(int(tip, 16), coinbase, ntime=block_time)
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), result)
        self.wallet.rescan_utxos()
        info = node.getdemurrageinfo()
        assert_equal(info["height"], ACTIVATION_HEIGHT)
        assert_equal(info["active"], True)
        assert_equal(info["rate"], rate)
        assert_equal(info["index"], self.model.next_index(ONE, rate))
        assert self.pending["txid"] in node.getrawmempool()

    def test_presigned_before_activation(self):
        node = self.nodes[0]
        self.log.info("A transaction signed before activation stays valid after it")
        self.mine(5)
        # Its only input was created before activation (index 1), so it is
        # valued at its nominal value however long the transaction waits.
        node.sendrawtransaction(self.presigned["hex"])
        self.mine()
        out = node.gettxout(self.presigned["txid"], 0)
        assert_greater_than(ACTIVATION_HEIGHT, out["ref_height"])
        assert_equal(sat(out["effective_value"]), self.model.effective(self.presigned["tx"].vout[0].nValue, ONE, self.index_at(node.getblockcount())))

    def test_inherited_reference_heights(self):
        node = self.nodes[0]
        self.log.info("Coinbase outputs take their block's height as reference height")
        self.mine(105)
        coinbase_height = ACTIVATION_HEIGHT + 2
        coinbase_txid = node.getblock(node.getblockhash(coinbase_height))["tx"][0]
        assert_equal(self.ref_height(coinbase_txid), coinbase_height)
        coinbase_utxo = next(u for u in self.wallet.get_utxos(mark_as_spent=False) if u["txid"] == coinbase_txid)
        old_utxo = next(u for u in self.wallet.get_utxos(mark_as_spent=False) if self.ref_height(u["txid"], u["vout"]) < ACTIVATION_HEIGHT)

        self.log.info("A single input is valued at its nominal value, and its output inherits its reference height")
        old_ref = self.ref_height(old_utxo["txid"], old_utxo["vout"])
        single = self.wallet.create_self_transfer(utxo_to_spend=old_utxo)
        node.sendrawtransaction(single["hex"])
        self.wallet.get_utxo(txid=old_utxo["txid"], vout=old_utxo["vout"])
        self.wallet.scan_tx(node.decoderawtransaction(single["hex"]))
        assert_equal(self.ref_height(single["txid"]), old_ref)
        assert_equal(node.getrawtransaction(single["txid"], True)["version"], 2)

        self.log.info("Mixed inputs are valued at the highest reference height among them")
        old_value = sat(old_utxo["value"])
        mixed_inputs = [single["new_utxo"], coinbase_utxo]
        decayed = self.model.effective(old_value - sat(single["fee"]), ONE, self.index_at(coinbase_height)) + sat(coinbase_utxo["value"])
        assert_equal(self.wallet.demurrage_inputs_value(mixed_inputs), decayed)
        nominal = self.wallet.create_self_transfer_multi(utxos_to_spend=mixed_inputs, amount_per_output=sat(single["new_utxo"]["value"]) + sat(coinbase_utxo["value"]) - 1000)
        assert_raises_rpc_error(-26, "bad-txns-in-belowout", node.sendrawtransaction, nominal["hex"])
        mixed = self.wallet.create_self_transfer_multi(utxos_to_spend=mixed_inputs, demurrage=True)
        node.sendrawtransaction(mixed["hex"])
        for u in mixed_inputs:
            self.wallet.get_utxo(txid=u["txid"], vout=u["vout"])
        self.wallet.scan_tx(node.decoderawtransaction(mixed["hex"]))
        assert_equal(self.ref_height(mixed["txid"]), coinbase_height)
        assert_equal(sat(node.getmempoolentry(mixed["txid"])["fees"]["base"]), decayed - mixed["tx"].vout[0].nValue)

        self.log.info("Unconfirmed children inherit their parent's reference height")
        child = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=mixed["new_utxos"][0])
        assert_equal(self.ref_height(child["txid"]), coinbase_height)
        self.fee_txs = [(single, old_ref), (mixed, coinbase_height), (child, coinbase_height)]

    def test_fees_to_producer(self):
        node = self.nodes[0]
        self.log.info("The block producer claims each fee at the block's index")
        height = node.getblockcount() + 1
        index_h = self.state()["next_block"]["index"]
        fees = 0
        for tx, ref in self.fee_txs:
            fee = sat(node.getmempoolentry(tx["txid"])["fees"]["base"])
            fees += self.model.effective(fee, self.index_at(ref), index_h)
        limit = subsidy(height) + fees + sat(self.state()["next_block"]["dividend"])
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["coinbasevalue"], limit)
        assert_equal(sum(t["fee"] for t in tmpl["transactions"]), fees)

        self.log.info("A coinbase claiming one satoshi more than that is invalid")
        txs = [t["data"] for t in tmpl["transactions"]]
        for value, result in ((limit + 1, "bad-cb-amount"), (limit, None)):
            coinbase = create_coinbase(height, script_pubkey=self.wallet.get_output_script())
            coinbase.vout[0].nValue = value
            block = create_block(tmpl=tmpl, coinbase=coinbase, txlist=txs)
            add_witness_commitment(block)
            block.solve()
            assert_equal(node.submitblock(block.serialize().hex()), result)
        assert_equal(node.getrawmempool(), [])
        self.wallet.rescan_utxos()

    def zero_fee_commitment(self, funding):
        """A zero-fee TRUC commitment: no fee, and a 0-value P2A anchor."""
        parent = CTransaction()
        parent.version = 3
        parent.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["vout"]))]
        parent.vout = [CTxOut(sat(funding["value"]), self.wallet.get_output_script()), CTxOut(0, PAY_TO_ANCHOR)]
        self.wallet.sign_tx(parent)
        return parent

    def anchor_child(self, parent, parent_ref, sponsor, fee, pad_vsize=0):
        """A TRUC child sweeping the anchor and paying for the package."""
        sponsor_ref = self.ref_height(sponsor["txid"], sponsor["vout"])
        ref = max(parent_ref, sponsor_ref)
        sponsor_value = self.model.effective(sat(sponsor["value"]), self.index_at(sponsor_ref), self.index_at(ref))
        child = CTransaction()
        child.version = 3
        child.vin = [CTxIn(COutPoint(parent.txid_int, 1)), CTxIn(COutPoint(int(sponsor["txid"], 16), sponsor["vout"]))]
        child.vout = [CTxOut(sponsor_value - fee, self.wallet.get_output_script())]
        if pad_vsize:
            self.wallet._bulk_tx(child, pad_vsize)
        self.wallet.sign_tx(child)
        child.wit.vtxinwit[0] = CTxInWitness()  # P2A is spent with an empty witness
        return child

    def test_truc_commitments(self):
        node = self.nodes[0]
        self.log.info("Zero-fee TRUC commitment packages work after activation")
        funding = self.wallet.get_utxo(confirmed_only=True)
        funding_ref = self.ref_height(funding["txid"], funding["vout"])
        parent = self.zero_fee_commitment(funding)
        sponsor = self.wallet.get_utxo(confirmed_only=True)
        pin = self.anchor_child(parent, funding_ref, sponsor, fee=8_000, pad_vsize=5_000)
        res = node.submitpackage([parent.serialize().hex(), pin.serialize().hex()])
        assert "TRUC-violation" in res["package_msg"] and "is too big" in res["package_msg"], res

        child = self.anchor_child(parent, funding_ref, sponsor, fee=50_000)
        res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()])
        assert_equal(res["package_msg"], "success")
        assert_equal(self.ref_height(parent.txid_hex), funding_ref)
        self.mine()
        self.wallet.rescan_utxos()

        self.log.info("A commitment signed now can be broadcast much later")
        funding = self.wallet.get_utxo(confirmed_only=True)
        funding_ref = self.ref_height(funding["txid"], funding["vout"])
        parent = self.zero_fee_commitment(funding)
        self.mine(30)
        self.wallet.rescan_utxos()
        self.wallet.get_utxo(txid=funding["txid"], vout=funding["vout"])  # keep the funding coin unspent
        sponsor = self.wallet.get_utxo(confirmed_only=True)
        child = self.anchor_child(parent, funding_ref, sponsor, fee=50_000)
        res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()])
        assert_equal(res["package_msg"], "success")
        self.mine()
        assert_equal(node.getrawmempool(), [])
        self.wallet.rescan_utxos()

    def test_rate_period_and_supply(self):
        node = self.nodes[0]
        self.log.info("Each rate period's rate is set from the previous period's subsidy schedule")
        start = node.getblockcount() + 1
        periods = (start - ACTIVATION_HEIGHT) // self.model.rate_period + 1
        period_end = ACTIVATION_HEIGHT + periods * self.model.rate_period - 1
        assert_greater_than(period_end, start)
        while node.getblockcount() < period_end:
            # Keep some fee-paying transactions flowing; they do not affect the rate.
            self.wallet.send_self_transfer(from_node=node)
            self.mine()
        info = self.state()
        nb = info["next_block"]
        assert_equal(nb["rate_period_start"], True)
        covered = self.model.covered(period_end + 1)
        assert_equal(sat(nb["covered"]), covered)
        rate = self.model.rate(sat(info["utxo_value"]), covered)
        assert_equal(nb["rate"], rate)
        assert_equal(nb["index"], self.model.next_index(info["index"], rate))
        self.mine(3)
        assert_equal(self.state()["rate"], rate)

        self.log.info("Effective supply grows only by the subsidy")
        for height in range(start, node.getblockcount() + 1):
            delta = sat(self.state(height)["utxo_value"]) - sat(self.state(height - 1)["utxo_value"]) - subsidy(height)
            # Up to a few satoshis are lost to rounding down in each block.
            assert -10 <= delta <= 0, f"height {height}: effective supply changed by {delta} beyond the subsidy"

    def fund_wallet(self, w):
        """Send 4 BTC to wallet w from a coin created before activation (index
        1) and 4 BTC from a later coin, so that its coins have different
        reference heights."""
        node = self.nodes[0]
        self.wallet.rescan_utxos()
        utxos = [u for u in self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False) if u["value"] > 5]
        old = next(u for u in utxos if self.ref_height(u["txid"], u["vout"]) < ACTIVATION_HEIGHT)
        new = max((u for u in utxos if self.ref_height(u["txid"], u["vout"]) >= ACTIVATION_HEIGHT), key=lambda u: u["height"])
        for utxo in (old, new):
            self.wallet.get_utxo(txid=utxo["txid"], vout=utxo["vout"])
            tx = self.wallet.create_self_transfer(utxo_to_spend=utxo, fee_rate=0)["tx"]
            tx.vout[0].nValue -= 4 * COIN + 1000
            tx.vout.append(CTxOut(4 * COIN, address_to_scriptpubkey(w.getnewaddress())))
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx.serialize().hex())
        self.mine()

    def test_wallet(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping wallet test: wallet not compiled")
            return
        node = self.nodes[0]
        self.log.info("The wallet reports effective balances")
        node.createwallet("w")
        w = node.get_wallet_rpc("w")
        self.fund_wallet(w)
        refs = {self.ref_height(u["txid"], u["vout"]) for u in w.listunspent()}
        assert_equal(len(refs), 2)
        assert_greater_than(max(refs), ACTIVATION_HEIGHT - 1)
        assert_greater_than(ACTIVATION_HEIGHT, min(refs))

        def effective_balance():
            return sum(node.gettxout(u["txid"], u["vout"])["effective_value"] for u in w.listunspent())

        assert_greater_than(Decimal(8), w.getbalance())
        assert_equal(w.getbalance(), effective_balance())
        assert_equal(w.getbalances()["mine"]["trusted"], effective_balance())

        self.log.info("Payments deliver their effective amount, whatever the inputs' reference heights")
        assert_greater_than(w.getbalance(), Decimal(5))
        txid = w.sendtoaddress(self.wallet.get_address(), 5)  # needs both coins
        tx = node.getrawtransaction(txid, True)
        assert_equal(tx["version"], 2)
        assert_equal(len(tx["vin"]), 2)
        assert_equal(self.ref_height(txid), max(refs))
        payment = next(o for o in tx["vout"] if o["scriptPubKey"]["hex"] == self.wallet.get_output_script().hex())
        delivered = sat(node.gettxout(txid, payment["n"])["effective_value"])
        assert 5 * COIN - 3 <= delivered <= 5 * COIN, delivered
        self.mine()
        assert_equal(w.getbalance(), effective_balance())

        self.log.info("PSBTs (v0 and v2) work unchanged")
        for psbt_version in (0, 2):
            psbt = w.walletcreatefundedpsbt(inputs=[], outputs=[{self.wallet.get_address(): Decimal("0.3")}], psbt_version=psbt_version)["psbt"]
            signed = w.walletprocesspsbt(psbt)
            assert_equal(signed["complete"], True)
            node.sendrawtransaction(signed["hex"])
            self.mine()
        w.sendtoaddress(self.wallet.get_address(), w.getbalance(), subtractfeefromamount=True)
        self.mine()
        assert_equal(w.listunspent(), [])

        self.log.info("sendall delivers the effective balance less the fee, whatever the inputs' reference heights")
        fee_rate = 10
        for specify_inputs in (True, False):
            self.fund_wallet(w)
            coins = w.listunspent()
            assert_equal(len({self.ref_height(u["txid"], u["vout"]) for u in coins}), 2)
            balance = sat(w.getbalance())
            inputs = {"inputs": [{"txid": u["txid"], "vout": u["vout"]} for u in coins]} if specify_inputs else {}
            txid = w.sendall(recipients=[self.wallet.get_address()], fee_rate=fee_rate, **inputs)["txid"]
            tx = node.getrawtransaction(txid, True)
            assert_equal(len(tx["vin"]), 2)
            assert_equal(len(tx["vout"]), 1)
            delivered = sat(node.gettxout(txid, 0)["effective_value"])
            # The wallet estimates the signed size, which can exceed the
            # actual size by a few vbytes, and conversions round down.
            shortfall = balance - delivered - fee_rate * tx["vsize"]
            assert 0 <= shortfall <= 100, shortfall
            mempool_fee = node.getmempoolentry(txid)["fees"]["base"]
            self.mine()
            assert_equal(w.listunspent(), [])
            self.log.info("gettransaction and listtransactions report the fee as consensus values the inputs")
            wtx = w.gettransaction(txid)
            assert_equal(wtx["fee"], -mempool_fee)
            assert_equal(wtx["ref_height"], self.ref_height(txid))
            assert_equal(next(t for t in w.listtransactions() if t["txid"] == txid and t["category"] == "send")["fee"], -mempool_fee)

        self.log.info("decodepsbt and analyzepsbt report the fee as consensus values the inputs")
        self.fund_wallet(w)
        coins = w.listunspent()
        nominal_in = sum(Decimal(node.gettxout(u["txid"], u["vout"])["value"]) for u in coins)
        funded = w.walletcreatefundedpsbt(inputs=[{"txid": u["txid"], "vout": u["vout"]} for u in coins],
                                          outputs=[{self.wallet.get_address(): 1}], fee_rate=fee_rate)
        decoded = node.decodepsbt(funded["psbt"])
        nominal_fee = nominal_in - sum(Decimal(o["amount"]) for o in decoded["outputs"])
        analyzed = node.analyzepsbt(funded["psbt"])
        assert_equal(analyzed["fee"], decoded["fee"])
        txid = node.sendrawtransaction(w.walletprocesspsbt(funded["psbt"])["hex"])
        assert_equal(node.getmempoolentry(txid)["fees"]["base"], decoded["fee"])
        # Valuing inputs with different reference heights at their nominal
        # values would overstate the fee.
        assert_greater_than(nominal_fee, decoded["fee"])
        self.mine()
        assert_equal(w.gettransaction(txid)["fee"], -decoded["fee"])

        self.log.info("The wallet values the outputs of its transactions that were never broadcast")
        self.fund_wallet(w)
        self.restart_node(0, extra_args=self.extra_args[0] + ["-walletbroadcast=0"])
        node.loadwallet("w")
        w = node.get_wallet_rpc("w")
        parent = w.sendtoaddress(w.getnewaddress(), 5)  # needs both coins
        assert parent not in node.getrawmempool()
        parent_outputs = [{"txid": parent, "vout": o["n"]} for o in w.gettransaction(parent, verbose=True)["decoded"]["vout"]]
        # Both of the parent's outputs (5 BTC and the change) are needed.
        child = w.send(outputs=[{self.wallet.get_address(): 5}], inputs=parent_outputs, add_inputs=False)["txid"]
        assert child not in node.getrawmempool()
        # Once broadcast, both are valid, and the payment delivers its effective amount.
        self.restart_node(0)
        node.loadwallet("w")
        w = node.get_wallet_rpc("w")
        self.wait_until(lambda: {parent, child} <= set(node.getrawmempool()))
        payment = next(o for o in node.getrawtransaction(child, True)["vout"] if o["scriptPubKey"]["hex"] == self.wallet.get_output_script().hex())
        delivered = sat(node.gettxout(child, payment["n"])["effective_value"])
        assert 5 * COIN - 3 <= delivered <= 5 * COIN, delivered
        self.mine()
        w.sendall(recipients=[self.wallet.get_address()])
        self.mine()
        assert_equal(w.listunspent(), [])
        self.wallet.rescan_utxos()

    def test_effective_value_reporting(self):
        node = self.nodes[0]
        self.log.info("gettxoutsetinfo reports the effective value of the UTXO set")
        self.mine()
        info = node.gettxoutsetinfo("none")
        assert_equal(info["effective_total_amount"], self.state()["utxo_value"])
        assert_greater_than(info["total_amount"], info["effective_total_amount"])

        self.log.info("scantxoutset and REST report reference heights and effective values")
        scan = node.scantxoutset("start", [self.wallet.get_descriptor()])
        assert_greater_than(len(scan["unspents"]), 1)
        for u in scan["unspents"]:
            out = node.gettxout(u["txid"], u["vout"])
            assert_equal(u["ref_height"], out["ref_height"])
            assert_equal(u["effective_value"], out["effective_value"])
        assert_equal(scan["effective_total_amount"], sum(u["effective_value"] for u in scan["unspents"]))
        assert_greater_than(scan["total_amount"], scan["effective_total_amount"])

        u = next(u for u in scan["unspents"] if u["ref_height"] >= ACTIVATION_HEIGHT)
        rest = urllib.parse.urlparse(node.url)
        conn = http.client.HTTPConnection(rest.hostname, rest.port)
        conn.request("GET", f"/rest/getutxos/{u['txid']}-{u['vout']}.json")
        utxo = json.loads(conn.getresponse().read().decode(), parse_float=Decimal)["utxos"][0]
        conn.close()
        assert_equal(utxo["ref_height"], u["ref_height"])
        assert_equal(utxo["effective_value"], u["effective_value"])

    @staticmethod
    def sign_p2wpkh(tx, index, privkey, pubkey, amount, sighash):
        script_code = keyhash_to_p2pkh_script(hash160(pubkey))
        sig = privkey.sign_ecdsa(SegwitV0SignatureHash(script_code, tx, index, sighash, amount)) + bytes([sighash])
        tx.wit.vtxinwit += [CTxInWitness() for _ in range(len(tx.vin) - len(tx.wit.vtxinwit))]
        tx.wit.vtxinwit[index] = CTxInWitness()
        tx.wit.vtxinwit[index].scriptWitness.stack = [sig, pubkey]

    def test_layer2(self):
        node = self.nodes[0]
        self.log.info("Layer 2: transactions pre-signed against a channel stay valid however long they wait")
        # A 2-of-2 funding output, funded by a coin created before activation,
        # so that the channel's reference height is below activation.
        key_a, pub_a = generate_keypair()
        key_b, pub_b = generate_keypair()
        funding_script = keys_to_multisig_script([pub_a, pub_b])
        utxo = next(u for u in self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
                    if u["height"] < ACTIVATION_HEIGHT and u["value"] > 1)
        self.wallet.get_utxo(txid=utxo["txid"], vout=utxo["vout"])
        funding = self.wallet.create_self_transfer(utxo_to_spend=utxo, fee_rate=0)["tx"]
        funding.vout[0].nValue -= 1000
        funding.vout[0].scriptPubKey = script_to_p2wsh_script(funding_script)
        funding_txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=funding.serialize().hex())
        funding_value = funding.vout[0].nValue
        self.mine()
        funding_ref = self.ref_height(funding_txid)
        assert_greater_than(ACTIVATION_HEIGHT, funding_ref)

        # The commitment, signed by both parties now: to_local (A) and to_remote (B).
        to_local = funding_value * 6 // 10
        to_remote = funding_value - to_local - 1000
        commitment = CTransaction()
        commitment.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0))]
        commitment.vout = [CTxOut(to_local, key_to_p2wpkh_script(pub_a)), CTxOut(to_remote, key_to_p2wpkh_script(pub_b))]
        sighash = SegwitV0SignatureHash(funding_script, commitment, 0, SIGHASH_ALL, funding_value)
        commitment.wit.vtxinwit = [CTxInWitness()]
        commitment.wit.vtxinwit[0].scriptWitness.stack = [b"", key_a.sign_ecdsa(sighash) + bytes([SIGHASH_ALL]),
                                                          key_b.sign_ecdsa(sighash) + bytes([SIGHASH_ALL]), funding_script]
        # A second-stage transaction spending to_local, signed now.
        second_stage = CTransaction()
        second_stage.vin = [CTxIn(COutPoint(commitment.txid_int, 0))]
        second_stage.vout = [CTxOut(to_local - 1000, key_to_p2wpkh_script(pub_a))]
        self.sign_p2wpkh(second_stage, 0, key_a, pub_a, to_local, SIGHASH_ALL)
        # A transaction spending to_remote at zero fee, signed with
        # SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, so that fees can be added later.
        single = CTransaction()
        single.vin = [CTxIn(COutPoint(commitment.txid_int, 1))]
        single.vout = [CTxOut(to_remote, key_to_p2wpkh_script(pub_b))]
        self.sign_p2wpkh(single, 0, key_b, pub_b, to_remote, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)

        # Much later, the commitment and the second stage are broadcast. Each
        # spends one input, valued at its nominal value.
        self.mine(50)
        commitment_txid = node.sendrawtransaction(commitment.serialize().hex())
        self.mine()
        for vout in range(2):
            assert_equal(self.ref_height(commitment_txid, vout), funding_ref)
        second_stage_txid = node.sendrawtransaction(second_stage.serialize().hex())
        assert_equal(node.getmempoolentry(second_stage_txid)["fees"]["base"], Decimal(1000) / COIN)
        self.mine()
        assert_equal(self.ref_height(second_stage_txid), funding_ref)

        self.log.info("Layer 2: a younger input added to a pre-signed transaction raises its reference height and pays the decay")
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        sponsor = max((u for u in utxos if u["coinbase"] and u["confirmations"] >= 100), key=lambda u: u["height"])
        self.wallet.get_utxo(txid=sponsor["txid"], vout=sponsor["vout"])
        sponsor_ref = self.ref_height(sponsor["txid"], sponsor["vout"])
        assert_greater_than(sponsor_ref, funding_ref)
        decay = to_remote - self.model.effective(to_remote, self.index_at(funding_ref), self.index_at(sponsor_ref))
        assert_greater_than(decay, 0)
        pre_signed_witness = single.wit.vtxinwit[0]

        def bumped(change):
            tx = CTransaction()
            tx.vin = [single.vin[0], CTxIn(COutPoint(int(sponsor["txid"], 16), sponsor["vout"]))]
            tx.vout = [single.vout[0], CTxOut(change, self.wallet.get_output_script())]
            self.wallet.sign_tx(tx)
            tx.wit.vtxinwit[0] = pre_signed_witness
            return tx.serialize().hex()

        # Valuing the pre-signed input at its nominal value is not enough.
        res = node.testmempoolaccept([bumped(sat(sponsor["value"]) - 1000)])[0]
        assert_equal(res["reject-reason"], "bad-txns-in-belowout")
        txid = node.sendrawtransaction(bumped(sat(sponsor["value"]) - 1000 - decay))
        assert_equal(node.getmempoolentry(txid)["fees"]["base"], Decimal(1000) / COIN)
        self.mine()
        assert_equal(self.ref_height(txid), sponsor_ref)

    def test_restart_and_reorg(self):
        node = self.nodes[0]
        self.log.info("Demurrage state persists across a restart")
        pending = self.wallet.send_self_transfer(from_node=node)
        before = self.state()
        self.restart_node(0)
        assert_equal(self.state(), before)
        assert pending["txid"] in node.getrawmempool()

        self.log.info("State follows reorgs; mined transactions return to the mempool")
        self.mine()
        mined = self.state()
        tip = node.getbestblockhash()
        node.invalidateblock(tip)
        assert_equal(self.state(), before)
        assert pending["txid"] in node.getrawmempool()
        node.reconsiderblock(tip)
        assert_equal(self.state(), mined)

        self.log.info("Disconnecting the activation block restores pre-activation rules")
        activation_block = node.getblockhash(ACTIVATION_HEIGHT)
        node.invalidateblock(activation_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert "next_block" in self.state()
        node.reconsiderblock(activation_block)
        assert_equal(self.state(), mined)

    def test_upgrade_after_activation(self):
        self.log.info("A node upgraded after activation validates the blocks since activation again")
        node = self.nodes[0]
        recorded_height = node.getblockcount()
        recorded = self.state(recorded_height)
        recorded.pop("next_block")  # only reported for the chain tip
        # Restart without BIP 462 rules, as a node that has not been upgraded,
        # and extend the chain with blocks connected without them.
        self.restart_node(0, extra_args=[])
        self.wallet.rescan_utxos()
        first_old = node.getblockcount() + 1
        self.mine(110)
        # A transaction that is valid without BIP 462 but not with it: it values
        # a coin created before activation at its nominal value, alongside a
        # coinbase output of the blocks connected without BIP 462, which sets
        # its reference height.
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        before = next(u for u in utxos if u["height"] < ACTIVATION_HEIGHT)
        after = next(u for u in utxos if u["coinbase"] and u["height"] == first_old)
        for u in (before, after):
            self.wallet.get_utxo(txid=u["txid"], vout=u["vout"])
        nominal = self.wallet.send_self_transfer_multi(from_node=node, utxos_to_spend=[before, after])
        last_valid = node.getblockcount()
        self.mine(3)
        assert nominal["txid"] in node.getblock(node.getblockhash(last_valid + 1))["tx"]
        tip = node.getbestblockhash()

        with node.assert_debug_log([f"BIP 462: blocks from height {ACTIVATION_HEIGHT} to {last_valid + 3} were connected without BIP 462 rules"], timeout=60):
            self.restart_node(0)
        self.wait_until(lambda: node.getblockcount() == last_valid)
        assert_equal(next(t for t in node.getchaintips() if t["hash"] == tip)["status"], "invalid")
        # Validating the blocks again reproduces the state they had, and the
        # blocks connected without BIP 462 now have a state too.
        assert_equal(self.state(recorded_height), recorded)
        assert_equal(self.state()["height"], last_valid)
        assert_greater_than(recorded["index"], self.state()["index"])


if __name__ == '__main__':
    DemurrageTest(__file__).main()
