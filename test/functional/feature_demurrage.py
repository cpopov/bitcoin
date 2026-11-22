#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462b (soft-fork demurrage).

node0 enforces BIP 462b from ACTIVATION_HEIGHT (-testactivationheight).
node1 does not enforce it, so it validates blocks with the existing rules
only. node1 accepting every block that node0 accepts, including their claim
transactions and contributions, shows that the rules are a soft fork.

The test keeps its own model of the rate, the index, the charges and the
pool, written from the BIP, and checks every block of node0's chain from
activation against it.

On regtest the rate period is 144 blocks and the target 1/2,000 of the
scheduled supply per block, so with activation at 432 the first rate period
has a zero rate and charges begin at 576.

node2 has a chain of its own, on which the deployment activates through
version bits signalling. It tests the getblocktemplate rule while the
deployment is signalling, locked in and active.
"""
from decimal import Decimal

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
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
    tx_from_hex,
)
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

ACTIVATION_HEIGHT = 432
FIRST_CHARGED_HEIGHT = 576
RATE_PERIOD = 144
TARGET_NUMERATOR, TARGET_DENOMINATOR = 1, 2000
HALVING_INTERVAL = 150
INDEX_ONE = 10**18
POOL_DIVISOR = 10_000
CHARGE_MARGIN = 144
COINBASE_MATURITY = 100
POOL_SCRIPT = bytes.fromhex("04706f6f6c7551")
POOL_SCRIPT_HEX = POOL_SCRIPT.hex()
DEMURRAGE_BIT = 4
UNDECLARED = {"rules": ["segwit"]}
DECLARED = {"rules": ["segwit", "demurrage"]}
RULE_REQUIRED_ERROR = "Support for 'demurrage' rule requires explicit client support"
RULE_WARNING = f"Templates will require it from height {FIRST_CHARGED_HEIGHT}"


def to_sat(btc):
    return int(Decimal(btc) * COIN)


def block_subsidy(height):
    halvings = height // HALVING_INTERVAL
    return 0 if halvings >= 64 else (50 * COIN) >> halvings


def scheduled_supply(height):
    supply, era = 0, 0
    while era < 64 and era * HALVING_INTERVAL < height:
        blocks = min(height, (era + 1) * HALVING_INTERVAL) - era * HALVING_INTERVAL
        supply += blocks * ((50 * COIN) >> era)
        era += 1
    return supply


def period_rate(start):
    supply = scheduled_supply(start)
    if supply == 0:
        return 0
    subsidy = scheduled_supply(start + RATE_PERIOD) - supply
    target = supply * RATE_PERIOD * TARGET_NUMERATOR // TARGET_DENOMINATOR
    shortfall = max(0, target - subsidy)
    return shortfall * INDEX_ONE // (RATE_PERIOD * supply)


class IndexSchedule:
    def __init__(self, activation_height):
        self.activation_height = activation_height
        self.index = []
        self.rates = []

    def rate_at(self, height):
        if height < self.activation_height:
            return 0
        k = (height - self.activation_height) // RATE_PERIOD
        while len(self.rates) <= k:
            self.rates.append(period_rate(self.activation_height + len(self.rates) * RATE_PERIOD))
        return self.rates[k]

    def index_at(self, height):
        if height < self.activation_height:
            return INDEX_ONE
        offset = height - self.activation_height
        while len(self.index) <= offset:
            previous = self.index[-1] if self.index else INDEX_ONE
            rate = self.rate_at(self.activation_height + len(self.index))
            self.index.append(max(1, previous * (INDEX_ONE - rate) // INDEX_ONE))
        return self.index[offset]

    def charge(self, value, created, spent):
        if created >= spent:
            return 0
        return value - value * self.index_at(spent) // self.index_at(created)


def evaluation_height(next_height):
    return (next_height + 2 * CHARGE_MARGIN - 1) // CHARGE_MARGIN * CHARGE_MARGIN


def prevout_txid(txin):
    return f"{txin.prevout.hash:064x}"


def build_claim(pool_inputs):
    """pool_inputs: list of ((txid, n), value), carry first."""
    pool_value = sum(value for _, value in pool_inputs)
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(COutPoint(int(txid, 16), n), b"", 0xFFFFFFFF) for (txid, n), _ in pool_inputs]
    tx.vout = [CTxOut(pool_value - pool_value // POOL_DIVISOR, POOL_SCRIPT)]
    tx.nLockTime = 0
    return tx


class DemurrageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"],
            [],  # node1 does not enforce BIP 462b
            ["-vbparams=demurrage:0:9999999999"],  # node2 activates through signalling
        ]

    def setup_network(self):
        # node2 stays on a chain of its own.
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def sync_blocks(self, nodes=None, **kwargs):
        super().sync_blocks(nodes or self.nodes[:2], **kwargs)

    def sync_mempools(self, nodes=None, **kwargs):
        super().sync_mempools(nodes or self.nodes[:2], **kwargs)

    # ---- model ----

    def expected_pool_inputs(self, prev_hash, height):
        """The pool inputs of a block at height on top of prev_hash (on node0's active chain)."""
        inputs = []
        if height - 1 >= ACTIVATION_HEIGHT and self.pool[prev_hash]["carry"]:
            inputs.append(self.pool[prev_hash]["carry"])
        if height - COINBASE_MATURITY >= ACTIVATION_HEIGHT:
            matured = self.pool[self.nodes[0].getblockhash(height - COINBASE_MATURITY)]
            if matured["contribution"]:
                inputs.append(matured["contribution"])
        return inputs

    def verify_block(self, blockhash):
        """Check a block of node0's active chain against the model, and record its pool outputs."""
        block = self.nodes[0].getblock(blockhash, 3)
        height = block["height"]
        if height < ACTIVATION_HEIGHT:
            return
        txs = block["tx"]
        pool_inputs = self.expected_pool_inputs(block["previousblockhash"], height)
        carry = None
        if pool_inputs:
            claim = build_claim(pool_inputs)
            assert_equal(txs[1]["hex"], claim.serialize().hex())
            pool_value = sum(value for _, value in pool_inputs)
            assert_equal(to_sat(txs[1]["fee"]), pool_value // POOL_DIVISOR)
            carry = ((txs[1]["txid"], 0), claim.vout[0].nValue)
            charged = txs[2:]
        else:
            charged = txs[1:]
        charge = 0
        for tx in charged:
            for txout in tx["vout"]:
                assert txout["scriptPubKey"]["hex"] != POOL_SCRIPT_HEX
            for txin in tx["vin"]:
                prevout = txin["prevout"]
                assert not (prevout["scriptPubKey"]["hex"] == POOL_SCRIPT_HEX and prevout["height"] >= ACTIVATION_HEIGHT)
                charge += self.schedule.charge(to_sat(prevout["value"]), prevout["height"], height)
        pool_outputs = [(n, txout) for n, txout in enumerate(txs[0]["vout"]) if txout["scriptPubKey"]["hex"] == POOL_SCRIPT_HEX]
        contribution = None
        if charge > 0:
            assert_equal(len(pool_outputs), 1)
            assert_equal(to_sat(pool_outputs[0][1]["value"]), charge)
            contribution = ((txs[0]["txid"], pool_outputs[0][0]), charge)
        else:
            assert_equal(pool_outputs, [])
        self.pool[blockhash] = {"carry": carry, "contribution": contribution, "charge": charge, "pool_inputs": pool_inputs}

    def verify_chain(self):
        """Check every block of node0's active chain from activation that has not been checked."""
        node = self.nodes[0]
        unchecked = []
        height = node.getblockcount()
        while height >= ACTIVATION_HEIGHT:
            blockhash = node.getblockhash(height)
            if blockhash in self.pool:
                break
            unchecked.append(blockhash)
            height -= 1
        for blockhash in reversed(unchecked):
            self.verify_block(blockhash)
        return self.pool.get(node.getbestblockhash())

    def coin(self, txid, n):
        """(value, height) of a confirmed output on node0."""
        node = self.nodes[0]
        txout = node.gettxout(txid, n, include_mempool=False)
        assert txout is not None
        return to_sat(txout["value"]), node.getblockcount() - txout["confirmations"] + 1

    def mempool_charge(self, coins):
        """The charge at the evaluation height of the next block, for coins [(value, height)].

        A height of None is an output of an unconfirmed transaction, which is
        charged as if it were created in the next block."""
        next_height = self.nodes[0].getblockcount() + 1
        if next_height < ACTIVATION_HEIGHT:
            return 0
        evaluation = evaluation_height(next_height)
        return sum(self.schedule.charge(value, next_height if height is None else height, evaluation) for value, height in coins)

    def assert_net_fee(self, txid, charge):
        entry = self.nodes[0].getmempoolentry(txid)
        assert_equal(to_sat(entry["fees"]["modified"]), to_sat(entry["fees"]["base"]) - charge)

    # ---- transactions and blocks ----

    def send_charged(self, wallet=None, utxo=None, extra_fee=20_000):
        """Send a self-transfer from a confirmed coin that pays its charge at the evaluation height."""
        wallet = wallet or self.wallet
        utxo = utxo or wallet.get_utxo(confirmed_only=True)
        charge = self.mempool_charge([(to_sat(utxo["value"]), utxo["height"])])
        tx = wallet.create_self_transfer(utxo_to_spend=utxo, fee=Decimal(charge + extra_fee) / COIN)
        wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx["hex"])
        self.assert_net_fee(tx["txid"], charge)
        tx["charge_at_evaluation"] = charge
        return tx

    def send_child(self, parent, extra_fee=20_000):
        """Send a child of a mempool transaction that pays its charge at the evaluation height."""
        charge = self.mempool_charge([(to_sat(parent["new_utxo"]["value"]), None)])
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"], fee=Decimal(charge + extra_fee) / COIN)
        self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=child["hex"])
        self.assert_net_fee(child["txid"], charge)
        child["charge_at_evaluation"] = charge
        return child

    def charges_and_fees(self, txs, height, claim):
        """C(h) and the fees of a block's transactions (claim first, if any)."""
        created = {}
        charge, fees = 0, 0
        for tx in ([claim] if claim else []) + list(txs):
            value_in = 0
            for txin in tx.vin:
                txid = prevout_txid(txin)
                if txid in created:
                    value_in += created[txid].vout[txin.prevout.n].nValue
                    continue
                value, coin_height = self.coin(txid, txin.prevout.n)
                value_in += value
                if tx is not claim:
                    charge += self.schedule.charge(value, coin_height, height)
            fees += value_in - sum(txout.nValue for txout in tx.vout)
            created[tx.txid_hex] = tx
        return charge, fees

    def make_block(self, txs=(), *, claim=True, contributions=None):
        """Build a block on node0's tip.

        claim: True for the required claim transaction (if the block has pool
        inputs), False for none, or a transaction to put at index 1 instead.
        contributions: the values of the coinbase's pool outputs; by default
        exactly C(h), or none if C(h) is zero.
        """
        node = self.nodes[0]
        self.verify_chain()
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        pool_inputs = self.expected_pool_inputs(tip, height) if height >= ACTIVATION_HEIGHT else []
        if claim is True:
            claim = build_claim(pool_inputs) if pool_inputs else None
        elif claim is False:
            claim = None
        charge, fees = self.charges_and_fees(txs, height, claim)
        if contributions is None:
            contributions = [charge] if charge > 0 and height >= ACTIVATION_HEIGHT else []
        coinbase = create_coinbase(height, script_pubkey=self.wallet.get_output_script())
        coinbase.vout[0].nValue = block_subsidy(height) + fees - sum(contributions)
        coinbase.vout += [CTxOut(value, POOL_SCRIPT) for value in contributions]
        block = create_block(int(tip, 16), coinbase, ntime=node.getblock(tip)["time"] + 1,
                             txlist=([claim] if claim else []) + list(txs))
        add_witness_commitment(block)
        block.solve()
        self.last_block_charge = charge
        return block

    def isolate(self):
        """Disconnect node1. node0 announces new blocks to high-bandwidth compact
        block peers before validating them fully, so node1 must not see the
        invalid blocks submitted to node0: it would accept them."""
        if self.connected:
            self.disconnect_nodes(0, 1)
            self.connected = False

    def rejoin(self):
        if not self.connected:
            self.connect_nodes(0, 1)
            self.connected = True
            self.sync_blocks()

    def submit(self, block, reason=None, node=None):
        if reason is None:
            self.rejoin()
        else:
            self.isolate()
        node = node or self.nodes[0]
        assert_equal(node.submitblock(block.serialize().hex()), reason)
        if reason is None:
            assert_equal(node.getbestblockhash(), block.hash_hex)

    def pool_script_tx(self, utxo=None):
        """An ordinary transaction with an output to POOL_SCRIPT."""
        tx = self.wallet.create_self_transfer(utxo_to_spend=utxo or self.wallet.get_utxo(confirmed_only=True), fee=Decimal("0.1"))["tx"]
        tx.vout.append(CTxOut(1000, POOL_SCRIPT))
        tx.vout[0].nValue -= 1000
        return tx

    def spend_output(self, txid, n, value, fee=10_000):
        """A transaction spending an anyone-can-spend output (such as a POOL_SCRIPT output) with an empty scriptSig."""
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(txid, 16), n), b"", 0xFFFFFFFF)]
        tx.vout = [CTxOut(value - fee, self.wallet.get_output_script())]
        return tx

    def mine(self, num_blocks=1):
        """Mine with node0's block assembler, and check the new blocks."""
        self.rejoin()
        blocks = self.generate(self.wallet, num_blocks)
        self.verify_chain()
        return blocks

    # ---- getblocktemplate ----

    def check_template(self, tmpl):
        """Check the BIP 462b fields of a node0 template against the model."""
        self.verify_chain()
        height = tmpl["height"]
        entries = tmpl["transactions"]
        pool_inputs = self.expected_pool_inputs(tmpl["previousblockhash"], height)
        if pool_inputs:
            # The claim transaction comes first, with the payout as its fee.
            assert_equal(entries[0]["txid"], build_claim(pool_inputs).txid_hex)
            assert_equal(entries[0]["fee"], sum(value for _, value in pool_inputs) // POOL_DIVISOR)
            assert_equal(entries[0]["charge"], 0)
        created = {entries[0]["txid"]} if pool_inputs else set()
        for entry in entries[1 if pool_inputs else 0:]:
            tx = tx_from_hex(entry["data"])
            charge = 0
            for txin in tx.vin:
                txid = prevout_txid(txin)
                if txid not in created:
                    charge += self.schedule.charge(*self.coin(txid, txin.prevout.n), height)
            assert_equal(entry["charge"], charge)
            created.add(entry["txid"])
        assert_equal(tmpl["demurrage_contribution"], sum(entry["charge"] for entry in entries))
        assert_equal(tmpl["coinbasevalue"], block_subsidy(height) + sum(entry["fee"] for entry in entries) - tmpl["demurrage_contribution"])
        assert "default_witness_commitment" in tmpl

    def block_from_template(self, tmpl):
        """A block built from a template by a client that supports BIP 462b."""
        coinbase = create_coinbase(tmpl["height"], script_pubkey=self.wallet.get_output_script())
        coinbase.vout[0].nValue = tmpl["coinbasevalue"]
        if tmpl["demurrage_contribution"] > 0:
            coinbase.vout.append(CTxOut(tmpl["demurrage_contribution"], POOL_SCRIPT))
        block = create_block(tmpl=tmpl, coinbase=coinbase, txlist=[entry["data"] for entry in tmpl["transactions"]])
        add_witness_commitment(block)
        block.solve()
        return block

    # ---- tests ----

    def run_test(self):
        self.schedule = IndexSchedule(ACTIVATION_HEIGHT)
        self.pool = {}
        self.connected = True
        self.wallet = MiniWallet(self.nodes[0])
        # Coins for pre-signed transactions, kept apart from self.wallet.
        self.presigned_wallet = MiniWallet(self.nodes[0], tag_name="presigned")

        self.test_model()
        self.test_gbt_signalling()
        self.test_pre_activation()
        self.test_zero_rate_period()
        self.test_charges()
        self.test_claims()
        self.test_presigned()
        self.test_reorg()
        self.test_soft_fork()

    def test_model(self):
        self.log.info("Check the regtest rates and the model against the BIP's formulas")
        assert_equal(period_rate(ACTIVATION_HEIGHT), 0)
        assert_equal(period_rate(FIRST_CHARGED_HEIGHT), 237945492662473)
        assert_equal(self.schedule.index_at(FIRST_CHARGED_HEIGHT - 1), INDEX_ONE)
        assert_equal(self.schedule.index_at(FIRST_CHARGED_HEIGHT), 999762054507337527)
        assert_equal(evaluation_height(577), 864)

    def test_gbt_signalling(self):
        node2 = self.nodes[2]

        def status_next():
            return node2.getdeploymentinfo()["deployments"]["demurrage"]["bip9"]["status_next"]

        def mine_to(height):
            self.generatetoaddress(node2, height - node2.getblockcount(), ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)

        self.log.info("getblocktemplate: nodes signal for the deployment whether or not the client declares the rule")
        mine_to(RATE_PERIOD - 1)
        for status in ("started", "locked_in"):
            assert_equal(status_next(), status)
            for request in (UNDECLARED, DECLARED):
                tmpl = node2.getblocktemplate(request)
                assert tmpl["version"] & (1 << DEMURRAGE_BIT)
                assert_equal(tmpl["vbavailable"]["demurrage"], DEMURRAGE_BIT)
                assert "demurrage" not in tmpl["rules"]
                assert "demurrage_contribution" not in tmpl
            # node2's own blocks signal, so the deployment locks in, then activates.
            mine_to(node2.getblockcount() + RATE_PERIOD)
        assert_equal(status_next(), "active")
        assert_equal(node2.getblockcount() + 1, ACTIVATION_HEIGHT)

        self.log.info("From activation the rule is optional, and undeclared clients are warned at most once an hour")
        with node2.assert_debug_log([RULE_WARNING]):
            tmpl = node2.getblocktemplate(UNDECLARED)
        assert "demurrage" in tmpl["rules"] and "!demurrage" not in tmpl["rules"]
        assert not tmpl["version"] & (1 << DEMURRAGE_BIT)
        assert_equal(tmpl["demurrage_contribution"], 0)
        with node2.assert_debug_log([], unexpected_msgs=[RULE_WARNING]):
            node2.getblocktemplate(UNDECLARED)
            node2.getblocktemplate(DECLARED)
        mine_to(FIRST_CHARGED_HEIGHT - 2)
        assert "demurrage" in node2.getblocktemplate(UNDECLARED)["rules"]

        self.log.info("From the first rate period with a non-zero rate, the rule is required")
        mine_to(FIRST_CHARGED_HEIGHT - 1)
        assert_raises_rpc_error(-8, RULE_REQUIRED_ERROR, node2.getblocktemplate, UNDECLARED)
        assert "!demurrage" in node2.getblocktemplate(DECLARED)["rules"]

    def test_pre_activation(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Before activation, POOL_SCRIPT outputs are ordinary outputs")
        self.generate(self.wallet, 200)
        info = node0.getdeploymentinfo()["deployments"]["demurrage"]
        assert_equal(info, {"type": "buried", "active": False, "height": ACTIVATION_HEIGHT})
        assert "demurrage" not in node1.getdeploymentinfo()["deployments"]

        # Policy refuses transactions that create POOL_SCRIPT outputs.
        tx = self.pool_script_tx()
        for node in self.nodes:
            assert_equal(node.testmempoolaccept([tx.serialize().hex()])[0]["reject-reason"], "demurrage-pool-output")

        # Coins for the pre-signed transactions: two 10 BTC outputs.
        funding_info = self.wallet.create_self_transfer_multi(num_outputs=3, fee_per_output=1000)
        funding = funding_info["tx"]
        value_in = sum(txout.nValue for txout in funding.vout) + to_sat(funding_info["fee"])
        funding.vout[0] = CTxOut(10 * COIN, self.presigned_wallet.get_output_script())
        funding.vout[1] = CTxOut(10 * COIN, self.presigned_wallet.get_output_script())
        funding.vout[2].nValue = value_in - 20 * COIN - 10_000

        # Consensus allows them before activation, in a transaction and in the coinbase.
        block = self.make_block([tx, funding], contributions=[5000])
        self.submit(block)
        self.preactivation_pool_output = (tx.txid_hex, 1)
        self.sync_blocks()
        self.wallet.rescan_utxos()
        self.presigned_wallet.rescan_utxos()

        # Pre-signed transactions that pay a small fee. They are not broadcast yet.
        self.presigned = [self.presigned_wallet.create_self_transfer(fee=Decimal("0.00001")) for _ in range(2)]

        self.generate(self.wallet, ACTIVATION_HEIGHT - 1 - node0.getblockcount())
        assert_equal(node0.getdeploymentinfo()["deployments"]["demurrage"]["active"], True)

    def test_zero_rate_period(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Activation: the first rate period has a zero rate, so no block owes a charge")
        # The mempool already evaluates charges at a height in the next rate period.
        tx = self.send_charged()
        assert_greater_than(tx["charge_at_evaluation"], 0)
        self.mine()
        assert_equal(node0.getblockcount(), ACTIVATION_HEIGHT)
        assert_equal(self.pool[node0.getbestblockhash()]["charge"], 0)

        self.log.info("getblocktemplate: the rule is optional until charges begin, and templates give charges")
        tmpl = node0.getblocktemplate(UNDECLARED)
        assert "demurrage" in tmpl["rules"] and "!demurrage" not in tmpl["rules"]
        self.check_template(tmpl)
        assert_equal(tmpl["demurrage_contribution"], 0)
        # node1 does not enforce BIP 462b, so its templates have no BIP 462b fields.
        tmpl = node1.getblocktemplate(UNDECLARED)
        assert "demurrage" not in tmpl["rules"] and "demurrage_contribution" not in tmpl

        self.log.info("Invalid: a pool output in the coinbase when C(h) = 0, or two of them")
        self.submit(self.make_block(contributions=[1000]), "bad-cb-demurrage-unexpected")
        self.submit(self.make_block(contributions=[1000, 1000]), "bad-cb-demurrage-multiple")

        self.log.info("Invalid: a pool output created by an ordinary transaction")
        self.submit(self.make_block([self.pool_script_tx()]), "bad-demurrage-pool-create")
        self.wallet.rescan_utxos()

        self.log.info("A POOL_SCRIPT output created before activation is not a pool output")
        spend = self.spend_output(*self.preactivation_pool_output, 1000, fee=500)
        # Policy refuses it as a non-standard spend, as it does today.
        assert_equal(node0.testmempoolaccept([spend.serialize().hex()])[0]["reject-reason"], "bad-txns-nonstandard-inputs")
        self.submit(self.make_block([spend]))
        self.sync_blocks()
        self.verify_chain()

        self.mine(FIRST_CHARGED_HEIGHT - 1 - node0.getblockcount())
        assert all(entry["charge"] == 0 for entry in self.pool.values())

    def test_charges(self):
        node0 = self.nodes[0]
        self.log.info("Charges: the mempool ranks by net fee at the evaluation height")
        assert_equal(node0.getblockcount(), FIRST_CHARGED_HEIGHT - 1)
        # Its fee also covers the larger charge at the next evaluation height.
        tx = self.send_charged(extra_fee=5 * COIN)
        coin = self.coin(prevout_txid(tx["tx"].vin[0]), tx["tx"].vin[0].prevout.n)
        assert_equal(evaluation_height(FIRST_CHARGED_HEIGHT), 720)
        self.assert_net_fee(tx["txid"], self.schedule.charge(*coin, 720))

        self.log.info("getblocktemplate: from the first rate period with a non-zero rate, the rule is required")
        assert_raises_rpc_error(-8, RULE_REQUIRED_ERROR, node0.getblocktemplate, UNDECLARED)
        tmpl = node0.getblocktemplate(DECLARED)
        assert "!demurrage" in tmpl["rules"]
        assert_equal(tmpl["height"], FIRST_CHARGED_HEIGHT)
        self.check_template(tmpl)
        assert_greater_than(tmpl["demurrage_contribution"], 0)

        # The evaluation height moves in steps of CHARGE_MARGIN, and charges are recomputed then.
        self.rejoin()
        self.generateblock(node0, self.wallet.get_descriptor(), [])
        self.assert_net_fee(tx["txid"], self.schedule.charge(*coin, 864))
        self.generateblock(node0, self.wallet.get_descriptor(), [])
        self.assert_net_fee(tx["txid"], self.schedule.charge(*coin, 864))
        self.verify_chain()

        self.log.info("Block assembly pays C(h) into the coinbase contribution")
        self.mine()
        entry = self.pool[node0.getbestblockhash()]
        assert_greater_than(entry["charge"], 0)
        self.first_contribution_height = node0.getblockcount()

        self.log.info("An input from an unconfirmed parent is charged as if the parent confirms in the next block")
        self.wallet.rescan_utxos()
        parent = self.send_charged()
        next_height = node0.getblockcount() + 1
        # The evaluation height stays the same for the next two blocks.
        assert_equal(evaluation_height(next_height + 2), evaluation_height(next_height))
        child = self.send_child(parent)
        assert_greater_than(child["charge_at_evaluation"], 0)
        self.rejoin()
        # A block without the parent leaves the child's charge as it was.
        self.generateblock(node0, self.wallet.get_descriptor(), [])
        self.assert_net_fee(child["txid"], child["charge_at_evaluation"])

        self.log.info("When the parent confirms later than that, the child's charge falls")
        self.generateblock(node0, self.wallet.get_descriptor(), [parent["txid"]])
        self.verify_chain()
        assert_greater_than(self.pool[node0.getbestblockhash()]["charge"], 0)
        child_coin = self.coin(parent["txid"], 0)
        assert_equal(child_coin[1], next_height + 1)
        self.assert_net_fee(child["txid"], self.mempool_charge([child_coin]))
        assert_greater_than(child["charge_at_evaluation"], self.mempool_charge([child_coin]))
        self.mine()
        assert child["txid"] in node0.getblock(node0.getbestblockhash())["tx"]
        self.wallet.rescan_utxos()

        self.log.info("When the parent confirms in the next block, the child's charge stays the same")
        parent = self.send_charged()
        child = self.send_child(parent)
        self.generateblock(node0, self.wallet.get_descriptor(), [parent["txid"]])
        self.assert_net_fee(child["txid"], child["charge_at_evaluation"])
        self.mine()
        assert child["txid"] in node0.getblock(node0.getbestblockhash())["tx"]
        self.wallet.rescan_utxos()

        self.log.info("Invalid: a missing contribution, or one that differs from C(h)")
        parent = self.wallet.create_self_transfer(fee=Decimal("1"))
        parent_utxo = parent["new_utxo"]
        txs = [parent["tx"]]
        self.make_block(txs)
        charge = self.last_block_charge
        assert_greater_than(charge, 0)
        self.submit(self.make_block(txs, contributions=[]), "bad-cb-demurrage-missing")
        self.submit(self.make_block(txs, contributions=[charge + 1]), "bad-cb-demurrage-amount")
        self.submit(self.make_block(txs, contributions=[charge - 1]), "bad-cb-demurrage-amount")
        self.submit(self.make_block(txs, contributions=[charge - 1, 1]), "bad-cb-demurrage-multiple")
        self.submit(self.make_block(txs, contributions=[charge, 1]), "bad-cb-demurrage-multiple")

        self.log.info("An output created and spent in the same block has no charge")
        child = self.wallet.create_self_transfer(utxo_to_spend=parent_utxo, fee=Decimal("0.001"))["tx"]
        block = self.make_block(txs + [child])
        assert_equal(self.last_block_charge, charge)
        self.submit(block)
        self.sync_blocks()
        self.verify_chain()
        self.wallet.rescan_utxos()

        self.log.info("Blocks with and without charges")
        for i in range(12):
            if i % 3 != 2:
                self.send_charged()
            self.mine()
        self.wallet.rescan_utxos()

    def test_claims(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Claims: the first claim spends the first matured contribution")
        self.mine(self.first_contribution_height + COINBASE_MATURITY - 1 - node0.getblockcount())
        assert_equal(self.pool[node0.getbestblockhash()]["carry"], None)
        self.mine()
        entry = self.pool[node0.getbestblockhash()]
        assert_equal(len(entry["pool_inputs"]), 1)
        first_contribution = self.pool[node0.getblockhash(self.first_contribution_height)]["contribution"]
        assert_equal(entry["pool_inputs"], [first_contribution])
        claim_block = node0.getblock(node0.getbestblockhash(), 2)
        claim = claim_block["tx"][1]
        assert_equal(claim["size"], 67)
        payout = first_contribution[1] // POOL_DIVISOR
        assert_equal(to_sat(claim["vout"][0]["value"]), first_contribution[1] - payout)

        self.log.info("generateblock adds the claim transaction and the contribution for the given transactions")
        self.wallet.rescan_utxos()
        tx = self.wallet.create_self_transfer(fee=Decimal("1"))
        self.rejoin()
        blockhash = self.generateblock(node0, self.wallet.get_descriptor(), [tx["hex"]], sync_fun=self.no_op)["hash"]
        self.verify_chain()
        entry = self.pool[blockhash]
        assert entry["carry"] is not None and entry["charge"] > 0
        assert_equal(node0.getblock(blockhash)["tx"][2], tx["txid"])

        self.log.info("A block built from getblocktemplate, with its claim, charges and contribution, is valid")
        self.wallet.rescan_utxos()
        self.send_charged()
        parent = self.send_charged()
        child = self.send_child(parent)
        tmpl = node0.getblocktemplate(DECLARED)
        self.check_template(tmpl)
        entries = {entry["txid"]: entry for entry in tmpl["transactions"]}
        # The child spends an output of an earlier transaction in the template,
        # so in the block its input has no charge, unlike in the mempool.
        assert_greater_than(child["charge_at_evaluation"], 0)
        assert_equal(entries[child["txid"]]["charge"], 0)
        assert_greater_than(entries[parent["txid"]]["charge"], 0)
        self.submit(self.block_from_template(tmpl))
        self.verify_chain()
        self.wallet.rescan_utxos()

        self.log.info("Every later block has a claim, with two inputs when the matured block has a contribution")
        # Mine until both kinds have been seen, and the next block has both a
        # carry and a matured contribution.
        num_inputs = set()
        while num_inputs != {1, 2} or len(self.expected_pool_inputs(node0.getbestblockhash(), node0.getblockcount() + 1)) < 2:
            assert node0.getblockcount() < self.first_contribution_height + COINBASE_MATURITY + 20
            self.mine()
            entry = self.pool[node0.getbestblockhash()]
            assert entry["carry"] is not None
            num_inputs.add(len(entry["pool_inputs"]))
        sizes = {len(e["pool_inputs"]): node0.getblock(h, 2)["tx"][1]["size"] for h, e in self.pool.items() if e["pool_inputs"]}
        assert_equal(sizes, {1: 67, 2: 108})

        # node1 saw the same claim transactions and contributions, and accepted them.
        self.sync_blocks()
        assert_equal(node1.getblock(node0.getbestblockhash(), 2)["tx"][1]["txid"], node0.getblock(node0.getbestblockhash(), 2)["tx"][1]["txid"])

        self.log.info("Policy refuses to spend a pool output; non-enforcing nodes refuse it as non-standard")
        carry = self.pool[node0.getbestblockhash()]["carry"]
        spend = self.spend_output(*carry[0], carry[1]).serialize().hex()
        assert_equal(node0.testmempoolaccept([spend])[0]["reject-reason"], "demurrage-pool-spend")
        assert_equal(node1.testmempoolaccept([spend])[0]["reject-reason"], "bad-txns-nonstandard-inputs")

        self.log.info("Invalid: a missing or misplaced claim transaction")
        self.wallet.rescan_utxos()
        tx = self.wallet.create_self_transfer(fee=Decimal("1"))["tx"]
        self.submit(self.make_block(claim=False), "bad-demurrage-claim-missing")
        self.submit(self.make_block([tx], claim=False), "bad-demurrage-claim-missing")
        valid = self.make_block([tx])
        claim = valid.vtx[1]
        self.submit(self.make_block([tx, claim], claim=False), "bad-demurrage-claim-missing")

        self.log.info("Invalid: an altered claim transaction")
        pool_inputs = self.expected_pool_inputs(node0.getbestblockhash(), node0.getblockcount() + 1)
        assert_equal(len(pool_inputs), 2)

        def altered(change):
            tx = build_claim(pool_inputs)
            change(tx)
            return tx

        def set_attr(name, value):
            return lambda tx: setattr(tx, name, value)

        def add_witness(tx):
            tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]

        def set_input(i, name, value):
            return lambda tx: setattr(tx.vin[i], name, value)

        utxo = self.wallet.get_utxo(confirmed_only=True)
        alterations = {
            "a higher payout": lambda tx: setattr(tx.vout[0], "nValue", tx.vout[0].nValue - 1),
            "a lower payout": lambda tx: setattr(tx.vout[0], "nValue", tx.vout[0].nValue + 1),
            "an output to another script": lambda tx: setattr(tx.vout[0], "scriptPubKey", CScript([OP_TRUE])),
            "a second output": lambda tx: tx.vout.append(CTxOut(0, CScript([OP_TRUE]))),
            "version 1": set_attr("version", 1),
            "version 3": set_attr("version", 3),
            "a non-zero nLockTime": set_attr("nLockTime", 1),
            "a non-final nSequence": set_input(0, "nSequence", 0xFFFFFFFE),
            "a non-empty scriptSig": set_input(1, "scriptSig", CScript([OP_TRUE])),
            "a witness": add_witness,
            "its inputs swapped": lambda tx: tx.vin.reverse(),
            "a missing input": lambda tx: tx.vin.pop(),
            "an extra input": lambda tx: tx.vin.append(CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))),
        }
        for description, change in alterations.items():
            self.log.debug(f"Claim transaction with {description}")
            self.submit(self.make_block([tx], claim=altered(change)), "bad-demurrage-claim")

        self.log.info("Invalid: a pool output spent, or created, by an ordinary transaction")
        carry_spend = self.spend_output(claim.txid_hex, 0, claim.vout[0].nValue)
        self.submit(self.make_block([tx, carry_spend]), "bad-demurrage-pool-spend")
        self.submit(self.make_block([tx, self.pool_script_tx(utxo)]), "bad-demurrage-pool-create")

        self.log.info("Invalid: contributions when the block with a claim owes no charge")
        self.submit(self.make_block(contributions=[1]), "bad-cb-demurrage-unexpected")

        self.log.info("A block built outside the node, with its claim and contribution, is valid")
        self.submit(valid)
        self.sync_blocks()
        self.verify_chain()
        self.wallet.rescan_utxos()

    def test_presigned(self):
        node0 = self.nodes[0]
        self.log.info("A pre-signed transaction whose fee is below its charge stays valid")
        mined_at_a_loss, rescued = self.presigned
        mined_at_a_loss_tx = mined_at_a_loss["tx"]
        block = self.make_block([mined_at_a_loss_tx])
        assert_greater_than(self.last_block_charge, to_sat(mined_at_a_loss["fee"]))
        self.submit(block)
        self.sync_blocks()
        self.verify_chain()

        self.log.info("Its net fee is negative, so it is not relayed alone")
        assert_raises_rpc_error(-26, "min relay fee not met", node0.sendrawtransaction, rescued["hex"])

        self.log.info("A child rescues it by paying its charge (CPFP)")
        parent_input = rescued["tx"].vin[0]
        parent_charge = self.mempool_charge([self.coin(prevout_txid(parent_input), parent_input.prevout.n)])
        deficit = parent_charge - to_sat(rescued["fee"])
        assert_greater_than(deficit, 0)
        # The child also pays its own input's charge, as if its parent confirmed in the next block.
        child_charge = self.mempool_charge([(to_sat(rescued["new_utxo"]["value"]), None)])
        child = self.presigned_wallet.create_self_transfer(utxo_to_spend=rescued["new_utxo"], fee=Decimal(deficit + child_charge + 100_000) / COIN)
        result = node0.submitpackage([rescued["hex"], child["hex"]], maxfeerate=0)
        assert_equal(result["package_msg"], "success")
        self.assert_net_fee(rescued["txid"], parent_charge)
        self.assert_net_fee(child["txid"], child_charge)
        assert_greater_than(0, to_sat(node0.getmempoolentry(rescued["txid"])["fees"]["modified"]))
        self.mine()
        block = node0.getblock(node0.getbestblockhash())
        assert rescued["txid"] in block["tx"] and child["txid"] in block["tx"]
        assert_equal(node0.getrawmempool(), [])

    def test_reorg(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Reorgs: claim transactions do not return to the mempool")
        self.rejoin()
        self.wallet.rescan_utxos()
        fork_height = node0.getblockcount()
        sent = []
        for _ in range(3):
            sent.append(self.send_charged())
            self.mine()
        disconnected = [node0.getblockhash(h) for h in range(fork_height + 1, fork_height + 4)]
        claims = [node0.getblock(h)["tx"][1] for h in disconnected]
        node0.invalidateblock(disconnected[0])
        mempool = node0.getrawmempool()
        assert_equal(sorted(mempool), sorted(tx["txid"] for tx in sent))
        assert not set(claims) & set(mempool)
        # Charges are recomputed for the new tip.
        for tx in sent:
            txin = tx["tx"].vin[0]
            self.assert_net_fee(tx["txid"], self.mempool_charge([self.coin(prevout_txid(txin), txin.prevout.n)]))

        self.log.info("The new branch has its own contributions and claims, which node1 follows")
        self.generate(self.wallet, 4, sync_fun=self.no_op)
        self.verify_chain()
        # The claim transaction depends only on the chain: the same pool inputs give the same txid.
        assert_equal(node0.getblock(node0.getblockhash(fork_height + 1))["tx"][1], claims[0])
        self.sync_blocks()
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        node0.reconsiderblock(disconnected[0])
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        self.wallet.rescan_utxos()
        self.mine()

    def test_soft_fork(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Soft fork: node1 accepted every block, and accepts blocks that node0 rejects")
        self.sync_blocks()
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())
        assert_greater_than(sum(1 for e in self.pool.values() if e["pool_inputs"]), 0)
        assert_greater_than(sum(1 for e in self.pool.values() if e["contribution"]), 0)
        self.isolate()
        block = self.make_block(claim=False)
        self.submit(block, "bad-demurrage-claim-missing")
        assert_equal(node1.submitblock(block.serialize().hex()), None)
        assert_equal(node1.getbestblockhash(), block.hash_hex)


if __name__ == '__main__':
    DemurrageTest(__file__).main()
