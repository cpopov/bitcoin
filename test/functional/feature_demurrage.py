#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462 (target-based demurrage security budget).

Regtest parameter: TARGET_RATE_PER_BLOCK = 1/500, far above mainnet, so that
demurrage is non-zero while regtest's subsidy, which halves every 150 blocks,
still exists.

The test checks, against an independent Python model of the BIP's fixed-point
arithmetic:
- the UTXO set value at activation, the per-block rate (from the block's
  subsidy only), the index and the coinbase limit (subsidy + fee_effective +
  dividend);
- the mempool's fees: fee_effective in the next block;
- inherited reference heights: a transaction is valued at the highest
  reference height among its inputs, and its outputs inherit it;
- transactions signed before activation, and pre-signed TRUC packages, stay
  valid however long they wait;
- effective supply grows only by the subsidy;
- the wallet (payments, fee bumps, amounts by address), PSBTs, and effective
  values in RPC and REST;
- the coinstats index, against a scan of the UTXO set;
- the consensus behaviour BIP 462's Layer 2 section relies on: pre-signed
  commitment and second-stage transactions, and SIGHASH_SINGLE |
  SIGHASH_ANYONECANPAY transactions that add a younger input;
- restarts, reorgs, and a node upgraded after activation, which discards the
  blocks it connected without BIP 462.

The rules on blocks (activation block, demurrage commitment, timestamps) are
tested in feature_demurrage_blocks.py, and SIGHASH_DEMURRAGE in
feature_demurrage_sighash.py.
"""
from decimal import Decimal
import http.client
import json
import urllib.parse

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    add_demurrage_commitment,
    add_witness_commitment,
    create_block,
    demurrage_activation_version,
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
INDEX_MIN = 10**9
HALVING_INTERVAL = 150


def sat(amount):
    return int(Decimal(amount) * COIN)


def subsidy(height):
    halvings = height // HALVING_INTERVAL
    return 0 if halvings >= 64 else (50 * COIN) >> halvings


class DemurrageModel:
    """Independent model of the BIP 462 fixed-point arithmetic."""

    def __init__(self, info):
        self.num = info["target_rate_num"]
        self.den = info["target_rate_den"]

    def rate(self, utxo_value, block_subsidy, prev_index):
        """r(h), from U(h - 1), block_subsidy(h) and I(h - 1)."""
        if utxo_value == 0 or prev_index <= INDEX_MIN:
            return 0
        target = utxo_value * self.num // self.den
        if target <= block_subsidy:
            return 0
        return (target - block_subsidy) * ONE // utxo_value

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

    def mempool_fee(self, fee, ref_height):
        """The fee the mempool keeps for a transaction that enters it now, and
        whose fee is fee at ref_height: its fee_effective in the next block."""
        return self.model.effective(fee, self.index_at(ref_height), self.state()["next_block"]["index"])

    def check_mempool_fee(self, txid, fee, ref_height=None):
        if ref_height is None:
            ref_height = self.ref_height(txid)
        assert_equal(sat(self.nodes[0].getmempoolentry(txid)["fees"]["base"]), self.mempool_fee(fee, ref_height))

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        info = node.getdemurrageinfo()
        assert_equal(info["activation_height"], ACTIVATION_HEIGHT)
        assert_equal(info["index_scale"], ONE)
        assert_equal(info["index_min"], INDEX_MIN)
        self.model = DemurrageModel(info)

        self.test_before_activation()
        self.test_activation()
        self.test_presigned_before_activation()
        self.test_inherited_reference_heights()
        self.test_fees_to_producer()
        self.test_truc_commitments()
        self.test_rate_and_supply()
        self.test_wallet()
        self.test_effective_value_reporting()
        self.test_layer2()
        self.test_coinstatsindex()
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

        self.log.info("The first rate covers the shortfall of the activation block's own subsidy")
        nb = info["next_block"]
        assert_equal(sat(nb["subsidy"]), subsidy(ACTIVATION_HEIGHT))
        rate = self.model.rate(utxo_value, subsidy(ACTIVATION_HEIGHT), ONE)
        assert_greater_than(rate, 0)
        assert_greater_than(ONE * self.model.num // self.model.den, rate)
        assert_equal(nb["height"], ACTIVATION_HEIGHT)
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
            # The activation block sets bit 31 of its version, and every block
            # from it on commits to the demurrage state.
            block = create_block(int(tip, 16), coinbase, ntime=block_time, version=demurrage_activation_version())
            add_demurrage_commitment(block, node)
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
        mixed_fee = decayed - mixed["tx"].vout[0].nValue

        self.log.info("The mempool keeps each fee as fee_effective in the next block")
        # The fee of the first transaction is expressed at index 1, and that of
        # the second at a lower index. Their fee_effective can be compared.
        self.check_mempool_fee(single["txid"], sat(single["fee"]), old_ref)
        self.check_mempool_fee(mixed["txid"], mixed_fee, coinbase_height)
        assert_greater_than(sat(single["fee"]), sat(node.getmempoolentry(single["txid"])["fees"]["base"]))

        self.log.info("Unconfirmed children inherit their parent's reference height")
        child = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=mixed["new_utxos"][0])
        assert_equal(self.ref_height(child["txid"]), coinbase_height)
        self.fee_txs = [(single, old_ref, sat(single["fee"])), (mixed, coinbase_height, mixed_fee), (child, coinbase_height, sat(child["fee"]))]

    def test_fees_to_producer(self):
        node = self.nodes[0]
        self.log.info("The block producer claims each fee at the block's index")
        height = node.getblockcount() + 1
        index_h = self.state()["next_block"]["index"]
        fees = 0
        for tx, ref, fee in self.fee_txs:
            fees += self.model.effective(fee, self.index_at(ref), index_h)
            # No block was mined since they entered the mempool.
            assert_equal(sat(node.getmempoolentry(tx["txid"])["fees"]["base"]), self.model.effective(fee, self.index_at(ref), index_h))
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
            add_demurrage_commitment(block, script=tmpl["default_demurrage_commitment"])
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

    def test_rate_and_supply(self):
        node = self.nodes[0]
        self.log.info("Each block's rate is set from its own subsidy and the UTXO set value before it")
        start = node.getblockcount() + 1
        halving = (start // HALVING_INTERVAL + 1) * HALVING_INTERVAL
        while node.getblockcount() < halving - 1:
            # Keep some fee-paying transactions flowing; they do not affect the rate.
            self.wallet.send_self_transfer(from_node=node)
            self.mine()
        info = self.state()
        nb = info["next_block"]
        assert_equal(nb["height"], halving)
        assert_equal(sat(nb["subsidy"]), subsidy(halving))
        rate = self.model.rate(sat(info["utxo_value"]), subsidy(halving), info["index"])
        assert_equal(nb["rate"], rate)
        assert_equal(nb["index"], self.model.next_index(info["index"], rate))

        self.log.info("The first block after a halving already pays for the shortfall")
        # The subsidy halves from this block on, and the dividend makes up for
        # it in the same block: the total of the two does not fall.
        before = subsidy(halving - 1) + self.model.dividend(info["rate"], sat(self.state(halving - 2)["utxo_value"]))
        after = subsidy(halving) + sat(nb["dividend"])
        assert_greater_than(rate, info["rate"])
        assert_greater_than(after, before - 2)
        self.mine(3)
        assert_equal(self.state(halving)["rate"], rate)

        self.log.info("Every block since activation has the rate and index of the model")
        prev = self.state(ACTIVATION_HEIGHT - 1)
        for height in range(ACTIVATION_HEIGHT, node.getblockcount() + 1):
            state = self.state(height)
            expected = self.model.rate(sat(prev["utxo_value"]), subsidy(height), prev["index"])
            assert_equal(state["rate"], expected)
            assert_equal(state["index"], self.model.next_index(prev["index"], expected))
            prev = state

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
            # The mempool measures the fee in the next block, and the wallet
            # pays the fee rate it was asked for, measured in the same way.
            wallet_fee = -w.gettransaction(txid)["fee"]
            self.check_mempool_fee(txid, sat(wallet_fee))
            assert_greater_than(sat(node.getmempoolentry(txid)["fees"]["base"]) + 1, fee_rate * tx["vsize"])
            self.mine()
            assert_equal(w.listunspent(), [])
            self.log.info("gettransaction and listtransactions report the fee as consensus values the inputs")
            wtx = w.gettransaction(txid)
            assert_equal(wtx["fee"], -wallet_fee)
            assert_equal(wtx["ref_height"], self.ref_height(txid))
            assert_equal(next(t for t in w.listtransactions() if t["txid"] == txid and t["category"] == "send")["fee"], -wallet_fee)

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
        self.check_mempool_fee(txid, sat(decoded["fee"]))
        assert_greater_than(sat(node.getmempoolentry(txid)["fees"]["base"]) + 1, fee_rate * node.getmempoolentry(txid)["vsize"])
        # Valuing inputs with different reference heights at their nominal
        # values would overstate the fee.
        assert_greater_than(nominal_fee, decoded["fee"])
        self.mine()
        assert_equal(w.gettransaction(txid)["fee"], -decoded["fee"])

        self.test_wallet_bumpfee(w)

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

    def test_wallet_bumpfee(self, w):
        node = self.nodes[0]
        w.sendall(recipients=[self.wallet.get_address()])
        self.mine()
        assert_equal(w.listunspent(), [])
        node.createwallet("receiver")
        receiver = node.get_wallet_rpc("receiver")
        address = receiver.getnewaddress()

        def payment(txid):
            tx = node.getrawtransaction(txid, True)
            return next(o for o in tx["vout"] if o["scriptPubKey"].get("address") == address)

        def delivered(txid):
            return sat(node.gettxout(txid, payment(txid)["n"])["effective_value"])

        self.log.info("bumpfee keeps the amount of each payment, and values the original fee as consensus does")
        self.fund_wallet(w)
        txid = w.sendtoaddress(address=address, amount=5, replaceable=True)  # needs both coins
        assert_equal(len(node.getrawtransaction(txid, True)["vin"]), 2)
        original = payment(txid)
        # The reference height is below the tip, so the nominal amount exceeds
        # the 5 BTC that the payment delivers.
        assert_greater_than(original["value"], 5)
        ref = self.ref_height(txid)
        fee = -w.gettransaction(txid)["fee"]
        self.check_mempool_fee(txid, sat(fee), ref)
        for _ in range(2):
            bumped = w.bumpfee(txid)
            txid = bumped["txid"]
            assert_equal(bumped["origfee"], fee)
            assert_equal(self.ref_height(txid), ref)
            assert_equal(payment(txid)["value"], original["value"])
            assert_greater_than(bumped["fee"], fee)
            fee = bumped["fee"]
            assert_equal(-w.gettransaction(txid)["fee"], fee)
            self.check_mempool_fee(txid, sat(fee), ref)
        vout = payment(txid)["n"]
        self.mine()

        self.log.info("Amounts by address are effective values, like balances")
        balance = receiver.getbalance()
        assert_equal(balance, node.gettxout(txid, vout)["effective_value"])
        assert_greater_than(original["value"], balance)
        assert_equal(receiver.listaddressgroupings(), [[[address, balance, ""]]])
        assert_equal(receiver.getreceivedbyaddress(address), balance)
        assert_equal(receiver.getreceivedbylabel(""), balance)
        assert_equal(receiver.listreceivedbyaddress()[0]["amount"], balance)
        assert_equal(receiver.listreceivedbylabel()[0]["amount"], balance)
        # Once the output is spent, the amount received is still valued at the
        # wallet's last block, from the transaction's reference height.
        receiver.sendall(recipients=[self.wallet.get_address()])
        self.mine()
        received = self.model.effective(sat(original["value"]), self.index_at(ref), self.state()["index"])
        assert_equal(sat(receiver.getreceivedbyaddress(address)), received)
        assert_equal(sat(receiver.listreceivedbyaddress()[0]["amount"]), received)
        assert_equal(receiver.listaddressgroupings(), [[[address, 0, ""]]])

        self.log.info("A replacement that adds a younger input re-expresses the payment at its reference height")
        w.sendall(recipients=[self.wallet.get_address()])
        self.mine()
        self.fund_wallet(w)
        refs = {self.ref_height(u["txid"], u["vout"]): u for u in w.listunspent()}
        old_ref, new_ref = min(refs), max(refs)
        assert_greater_than(new_ref, old_ref)
        # Spend the older coin alone and in full: without a change output, the
        # replacement can only pay a higher fee by adding the younger coin.
        old_coin = {"txid": refs[old_ref]["txid"], "vout": refs[old_ref]["vout"]}
        txid = w.sendall(recipients=[address], inputs=[old_coin], replaceable=True)["txid"]
        assert_equal(self.ref_height(txid), old_ref)
        original = payment(txid)
        delivered_before = delivered(txid)
        txid = w.bumpfee(txid)["txid"]
        assert_equal(len(node.getrawtransaction(txid, True)["vin"]), 2)
        assert_equal(self.ref_height(txid), new_ref)
        # The same nominal amount, moved from the old index to the new one...
        assert_equal(sat(payment(txid)["value"]), self.model.effective(sat(original["value"]), self.index_at(old_ref), self.index_at(new_ref)))
        assert_greater_than(original["value"], payment(txid)["value"])
        # ...which delivers the same effective value, up to rounding.
        assert 0 <= delivered_before - delivered(txid) <= 2, (delivered_before, delivered(txid))
        self.mine()

        w.sendall(recipients=[self.wallet.get_address()])
        self.mine()
        assert_equal(w.listunspent(), [])
        receiver.unloadwallet()

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
        self.check_mempool_fee(second_stage_txid, 1000, funding_ref)
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
        self.check_mempool_fee(txid, 1000, sponsor_ref)
        self.mine()
        assert_equal(self.ref_height(txid), sponsor_ref)

    def test_coinstatsindex(self):
        node = self.nodes[0]
        self.log.info("The coinstats index hashes the same UTXO set as a scan")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-coinstatsindex"])

        def check():
            node.syncwithvalidationinterfacequeue()
            self.wait_until(lambda: node.getindexinfo()["coinstatsindex"] == {"synced": True, "best_block_height": node.getblockcount()})
            indexed = node.gettxoutsetinfo(hash_type="muhash", use_index=True)
            scanned = node.gettxoutsetinfo(hash_type="muhash", use_index=False)
            for key in ("height", "bestblock", "txouts", "bogosize", "muhash", "total_amount", "effective_total_amount"):
                assert_equal(indexed[key], scanned[key])
            return indexed

        # The chain so far holds dividends, and coins whose reference height
        # differs from their height.
        assert_greater_than(sat(self.state()["next_block"]["dividend"]), 0)
        check()

        self.log.info("Its unclaimed rewards are the coinbase limit less what the coinbase claims")
        self.wallet.send_self_transfer(from_node=node)
        self.mine()
        info = check()
        assert_equal(info["block_info"]["unspendables"]["unclaimed_rewards"], 0)
        # The coinbase claimed the dividend on top of the subsidy.
        assert_greater_than(sat(info["block_info"]["coinbase"]), subsidy(info["height"]))

        self.wallet.send_self_transfer(from_node=node)
        height = node.getblockcount() + 1
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        unclaimed = 12345
        coinbase = create_coinbase(height, script_pubkey=self.wallet.get_output_script())
        coinbase.vout[0].nValue = tmpl["coinbasevalue"] - unclaimed
        block = create_block(tmpl=tmpl, coinbase=coinbase, txlist=[t["data"] for t in tmpl["transactions"]])
        add_demurrage_commitment(block, script=tmpl["default_demurrage_commitment"])
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        info = check()
        assert_equal(sat(info["block_info"]["unspendables"]["unclaimed_rewards"]), unclaimed)

        self.log.info("It follows a reorganisation")
        node.invalidateblock(node.getbestblockhash())
        self.mine()
        assert_equal(node.getrawmempool(), [])
        info = check()
        assert_equal(info["height"], height)
        assert_equal(info["block_info"]["unspendables"]["unclaimed_rewards"], 0)

        self.restart_node(0)
        self.wallet.rescan_utxos()

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
        self.log.info("A node upgraded after activation discards the blocks it connected without BIP 462")
        node = self.nodes[0]
        tip = node.getbestblockhash()
        recorded_height = node.getblockcount()
        recorded = self.state(recorded_height)
        activation_block = node.getblockhash(ACTIVATION_HEIGHT)
        assert_greater_than(0, node.getblockheader(activation_block)["version"])
        # Restart without BIP 462 rules, as a node that has not been upgraded.
        # Such a node rejects the activation block, whose version is negative,
        # and follows the blocks of miners that have not upgraded either.
        self.restart_node(0, extra_args=[])
        node.invalidateblock(activation_block)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        self.wallet.rescan_utxos()
        self.wallet.send_self_transfer(from_node=node)
        self.mine(5)
        old_tip = node.getbestblockhash()
        old_activation_block = node.getblock(node.getblockhash(ACTIVATION_HEIGHT), 2)
        assert_greater_than(old_activation_block["version"], 0)
        assert all(not out["scriptPubKey"]["hex"].startswith("6a249996b0b3") for out in old_activation_block["tx"][0]["vout"])

        with node.assert_debug_log([f"BIP 462: blocks from height {ACTIVATION_HEIGHT} to {ACTIVATION_HEIGHT + 4} were connected without BIP 462 rules"], timeout=60):
            self.restart_node(0)
        # None of them is valid: the first lacks the activation version bit.
        self.wait_until(lambda: next(t for t in node.getchaintips() if t["hash"] == old_tip)["status"] == "invalid")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(self.state()["next_block"]["height"], ACTIVATION_HEIGHT)

        self.log.info("It then follows the chain that applies BIP 462, and computes the same state")
        node.reconsiderblock(activation_block)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(self.state(recorded_height), recorded)


if __name__ == '__main__':
    DemurrageTest(__file__).main()
