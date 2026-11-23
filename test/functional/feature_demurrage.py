#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462b (soft-fork demurrage).

node0 enforces BIP 462b. Its two deployments are forced with
-testactivationheight: demurrage gives ACTIVATION_HEIGHT, from which the rules
are enforced, and demurrage_charges gives CHARGE_HEIGHT, at which the index
starts.
node1 does not enforce it, so it validates blocks with the existing rules
only. node1 accepting every block that node0 accepts, including their claim
transactions and contributions, shows that the rules are a soft fork.

The test keeps its own model of the rate, the index, the charges, the pool and
the policy charge, written from the BIP, and checks every block of node0's
chain from activation, and node0's mempool entries, against it.

On regtest the rate period is 144 blocks and the target 1/2,000 of the
scheduled supply per block, so with CHARGE_HEIGHT at 432 the first rate period
has a zero rate and charges begin at 576.

node2 has a chain of its own, on which the deployments activate through
version bits signalling, at different heights. It tests the getblocktemplate
rules while each deployment is signalling, locked in and active.

node3 is a pruned node that enforces BIP 462b. It syncs node0's chain late in
the test.
"""
from decimal import Decimal

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COIN,
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    HeaderAndShortIDs,
    MSG_CMPCT_BLOCK,
    msg_getdata,
    msg_getheaders,
    msg_sendcmpct,
    tx_from_hex,
)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

ACTIVATION_HEIGHT = 288
CHARGE_HEIGHT = 432
FIRST_CHARGED_HEIGHT = 576
RATE_PERIOD = 144
TARGET_NUMERATOR, TARGET_DENOMINATOR = 1, 2000
HALVING_INTERVAL = 150
INDEX_ONE = 10**18
POOL_DIVISOR = 10_000
CHARGE_MARGIN = 144
CHARGE_TOLERANCE = 1000
COINBASE_MATURITY = 100
MIN_BLOCKS_TO_KEEP = 288
POOL_SCRIPT = bytes.fromhex("04706f6f6c7551")
POOL_SCRIPT_HEX = POOL_SCRIPT.hex()
DEMURRAGE_BIT = 4
CHARGES_BIT = 3
UNDECLARED = {"rules": ["segwit"]}
DECLARED = {"rules": ["segwit", "demurrage", "demurrage_charges"]}
RULE_REQUIRED_ERROR = "Support for 'demurrage_charges' rule requires explicit client support"
RULE_WARNING = f"Templates will require it from height {FIRST_CHARGED_HEIGHT}"
# Outputs whose charge grows slowly enough for the policy charge to be evaluated ahead.
SMALL_COINS = {
    "full_margin": 20_000,
    "medium_margin": 100_000,
    "short_margin": 1_000_000,
    "parent": 1_000_000,
    "replaced": 1_000_000,
    "restart": 100_000,
}


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
    def __init__(self, charge_height):
        self.charge_height = charge_height
        self.index = []
        self.rates = []

    def rate_at(self, height):
        if height < self.charge_height:
            return 0
        k = (height - self.charge_height) // RATE_PERIOD
        while len(self.rates) <= k:
            self.rates.append(period_rate(self.charge_height + len(self.rates) * RATE_PERIOD))
        return self.rates[k]

    def index_at(self, height):
        if height < self.charge_height:
            return INDEX_ONE
        offset = height - self.charge_height
        while len(self.index) <= offset:
            previous = self.index[-1] if self.index else INDEX_ONE
            rate = self.rate_at(self.charge_height + len(self.index))
            self.index.append(max(1, previous * (INDEX_ONE - rate) // INDEX_ONE))
        return self.index[offset]

    def charge(self, value, created, spent):
        if created >= spent:
            return 0
        return value - value * self.index_at(spent) // self.index_at(created)


def policy_charge(schedule, coins, next_height):
    """(E_tx, charge_at(E_tx)) of a transaction that spends coins [(value, height)].

    A height of None is an output of an unconfirmed transaction, which is
    charged as if it were created in the next block."""
    def charge_at(height):
        return sum(schedule.charge(value, next_height if created is None else created, height) for value, created in coins)

    base = charge_at(next_height)
    evaluation = next_height
    while evaluation < next_height + CHARGE_MARGIN and charge_at(evaluation + 1) - base <= CHARGE_TOLERANCE:
        evaluation += 1
    return evaluation, charge_at(evaluation)


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


class CompactBlockPeer(P2PInterface):
    """A peer that records the blocks announced to it with a compact block."""
    def __init__(self):
        super().__init__()
        self.compact_blocks = {}

    def on_cmpctblock(self, message):
        self.compact_blocks[message.header_and_shortids.header.hash_int] = HeaderAndShortIDs(message.header_and_shortids)


class DemurrageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        enforcing = [
            f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}",
            f"-testactivationheight=demurrage_charges@{CHARGE_HEIGHT}",
        ]
        self.extra_args = [
            enforcing,
            [],  # node1 does not enforce BIP 462b
            ["-vbparams=demurrage:0:9999999999", "-vbparams=demurrage_charges:0:9999999999"],  # node2 activates through signalling
            enforcing + ["-prune=1", "-fastprune"],
        ]

    def setup_network(self):
        # node2 stays on a chain of its own, and node3 joins later.
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

    def next_height(self):
        return self.nodes[0].getblockcount() + 1

    def coin(self, txid, n):
        """(value, height) of a confirmed output on node0."""
        node = self.nodes[0]
        txout = node.gettxout(txid, n, include_mempool=False)
        assert txout is not None
        return to_sat(txout["value"]), node.getblockcount() - txout["confirmations"] + 1

    def policy(self, coins, next_height=None):
        """(E_tx, policy charge) of a transaction that node0 evaluates for the next block."""
        return policy_charge(self.schedule, coins, next_height or self.next_height())

    def assert_policy(self, txid, evaluation, charge, *, fee_delta=0, node=None):
        entry = (node or self.nodes[0]).getmempoolentry(txid)
        fees = entry["fees"]
        assert_equal(entry["chargeheight"], evaluation)
        assert_equal(to_sat(fees["charge"]), charge)
        assert_equal(to_sat(fees["net"]), to_sat(fees["base"]) - charge)
        assert_equal(to_sat(fees["modified"]), to_sat(fees["base"]) - charge + fee_delta)

    def small_utxo(self, name):
        return self.wallet.get_utxo(txid=self.small_coins[name][0], vout=self.small_coins[name][1])

    # ---- transactions and blocks ----

    def send_charged(self, wallet=None, utxo=None, extra_fee=20_000):
        """Send a self-transfer from a confirmed coin that pays its policy charge."""
        wallet = wallet or self.wallet
        utxo = utxo or wallet.get_utxo(confirmed_only=True)
        coin = (to_sat(utxo["value"]), utxo["height"])
        evaluation, charge = self.policy([coin])
        tx = wallet.create_self_transfer(utxo_to_spend=utxo, fee=Decimal(charge + extra_fee) / COIN)
        wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=tx["hex"])
        self.assert_policy(tx["txid"], evaluation, charge)
        tx["coin"] = coin
        tx["policy"] = (evaluation, charge)
        return tx

    def send_child(self, parent, extra_fee=20_000):
        """Send a child of a mempool transaction that pays its policy charge."""
        coin = (to_sat(parent["new_utxo"]["value"]), None)
        evaluation, charge = self.policy([coin])
        child = self.wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"], fee=Decimal(charge + extra_fee) / COIN)
        self.wallet.sendrawtransaction(from_node=self.nodes[0], tx_hex=child["hex"])
        self.assert_policy(child["txid"], evaluation, charge)
        child["policy"] = (evaluation, charge)
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
        block peers before validating them fully. It first checks the claim
        transaction, but not the contribution, so node1 must not see the invalid
        blocks submitted to node0: it would accept them."""
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

    def mine_without(self, txids=()):
        """Mine a block on node0 that has only the given mempool transactions."""
        self.rejoin()
        blockhash = self.generateblock(self.nodes[0], self.wallet.get_descriptor(), list(txids))["hash"]
        self.verify_chain()
        return blockhash

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
        self.schedule = IndexSchedule(CHARGE_HEIGHT)
        self.pool = {}
        self.connected = True
        self.wallet = MiniWallet(self.nodes[0])
        # Coins for pre-signed transactions, kept apart from self.wallet.
        self.presigned_wallet = MiniWallet(self.nodes[0], tag_name="presigned")

        self.test_model()
        self.test_gbt_signalling()
        self.test_pre_activation()
        self.test_enforcement_before_charges()
        self.test_zero_rate_period()
        self.test_charges()
        self.test_evaluation_heights()
        self.test_unconfirmed_inputs()
        self.test_contributions()
        self.test_claims()
        self.test_presigned()
        self.test_replacement()
        self.test_unfunded_transaction()
        self.test_restart()
        self.test_compact_blocks()
        self.test_reorg()
        self.test_pruned()
        self.test_soft_fork()

    def test_model(self):
        self.log.info("Check the regtest rates and the model against the BIP's formulas")
        assert_equal(period_rate(CHARGE_HEIGHT), 0)
        assert_equal(period_rate(FIRST_CHARGED_HEIGHT), 237945492662473)
        assert_equal(self.schedule.index_at(FIRST_CHARGED_HEIGHT - 1), INDEX_ONE)
        assert_equal(self.schedule.index_at(FIRST_CHARGED_HEIGHT), 999762054507337527)
        # A large input's charge grows by more than CHARGE_TOLERANCE each block,
        # so it is evaluated no further ahead than charges allow.
        assert_equal(policy_charge(self.schedule, [(50 * COIN, 1)], CHARGE_HEIGHT), (FIRST_CHARGED_HEIGHT - 1, 0))
        assert_equal(policy_charge(self.schedule, [(50 * COIN, 1)], FIRST_CHARGED_HEIGHT), (FIRST_CHARGED_HEIGHT, 1_189_728))
        assert_equal(policy_charge(self.schedule, [(50 * COIN, None)], FIRST_CHARGED_HEIGHT), (FIRST_CHARGED_HEIGHT, 0))
        # A small one is evaluated CHARGE_MARGIN blocks ahead.
        assert_equal(policy_charge(self.schedule, [(1_000_000, 1)], CHARGE_HEIGHT), (FIRST_CHARGED_HEIGHT, 238))
        evaluation, charge = policy_charge(self.schedule, [(20_000, 1)], FIRST_CHARGED_HEIGHT)
        assert_equal(evaluation, FIRST_CHARGED_HEIGHT + CHARGE_MARGIN)
        assert_greater_than(CHARGE_TOLERANCE, charge)

    def test_gbt_signalling(self):
        node2 = self.nodes[2]
        wallet2 = MiniWallet(node2)
        # On node2's chain, demurrage_charges activates one period after demurrage.
        activation_height, charge_height = 3 * RATE_PERIOD, 4 * RATE_PERIOD
        assert_equal(charge_height, FIRST_CHARGED_HEIGHT)
        schedule2 = IndexSchedule(charge_height)

        def status_next(name):
            return node2.getdeploymentinfo()["deployments"][name]["bip9"]["status_next"]

        def mine_to(height):
            self.generatetoaddress(node2, height - node2.getblockcount(), wallet2.get_address(), sync_fun=self.no_op)

        def mine_undeclared_to(height):
            """Mine blocks as a client that does not declare demurrage_charges."""
            while node2.getblockcount() < height:
                tmpl = node2.getblocktemplate(UNDECLARED)
                block = create_block(tmpl=tmpl, coinbase=create_coinbase(tmpl["height"], script_pubkey=wallet2.get_output_script()))
                block.solve()
                assert_equal(node2.submitblock(block.serialize().hex()), None)

        def mine_empty():
            self.generateblock(node2, wallet2.get_descriptor(), [], sync_fun=self.no_op)

        def send(fee):
            wallet2.rescan_utxos()
            utxo = wallet2.get_utxo(confirmed_only=True)
            assert_equal(utxo["value"], 50)
            tx = wallet2.send_self_transfer(from_node=node2, utxo_to_spend=utxo, fee=fee)
            tx["coin"] = (to_sat(utxo["value"]), utxo["height"])
            return tx

        def assert_policy(tx):
            evaluation, charge = policy_charge(schedule2, [tx["coin"]], node2.getblockcount() + 1)
            self.assert_policy(tx["txid"], evaluation, charge, node=node2)
            return evaluation, charge

        self.log.info("getblocktemplate: nodes signal for demurrage for every client, and for demurrage_charges only for clients that declare it")
        mine_to(RATE_PERIOD - 1)
        assert_equal(status_next("demurrage"), "started")
        assert_equal(status_next("demurrage_charges"), "started")
        for request, charges_bit in ((UNDECLARED, 0), (DECLARED, 1 << CHARGES_BIT)):
            tmpl = node2.getblocktemplate(request)
            assert tmpl["version"] & (1 << DEMURRAGE_BIT)
            assert_equal(tmpl["version"] & (1 << CHARGES_BIT), charges_bit)
            assert_equal(tmpl["vbavailable"]["demurrage"], DEMURRAGE_BIT)
            assert_equal(tmpl["vbavailable"]["!demurrage_charges"], CHARGES_BIT)
            assert not {"demurrage", "!demurrage", "demurrage_charges", "!demurrage_charges"} & set(tmpl["rules"])
            assert "demurrage_contribution" not in tmpl

        self.log.info("Blocks built by clients that do not declare demurrage_charges lock in demurrage alone")
        mine_undeclared_to(2 * RATE_PERIOD - 1)
        assert_equal(status_next("demurrage"), "locked_in")
        assert_equal(status_next("demurrage_charges"), "started")
        # ACTIVATION_HEIGHT is known, CHARGE_HEIGHT is not: there are no policy charges yet.
        tx = send(Decimal("0.0001"))
        entry = node2.getmempoolentry(tx["txid"])
        assert "chargeheight" not in entry and "charge" not in entry["fees"] and "net" not in entry["fees"]
        assert "charge" not in node2.gettxout(tx["txid"], 0)
        tmpl = node2.getblocktemplate(UNDECLARED)
        assert tmpl["version"] & (1 << DEMURRAGE_BIT) and not tmpl["version"] & (1 << CHARGES_BIT)

        self.log.info("Blocks built by clients that declare it lock in demurrage_charges a period later")
        mine_to(activation_height - 1)
        assert_equal(status_next("demurrage"), "active")
        assert_equal(status_next("demurrage_charges"), "locked_in")

        self.log.info("From ACTIVATION_HEIGHT demurrage is an optional rule, and undeclared clients are warned at most once an hour")
        with node2.assert_debug_log([RULE_WARNING]):
            tmpl = node2.getblocktemplate(UNDECLARED)
        assert "demurrage" in tmpl["rules"] and "!demurrage" not in tmpl["rules"]
        assert not {"demurrage_charges", "!demurrage_charges"} & set(tmpl["rules"])
        assert_equal(tmpl["vbavailable"], {"!demurrage_charges": CHARGES_BIT})
        assert not tmpl["version"] & ((1 << DEMURRAGE_BIT) | (1 << CHARGES_BIT))
        assert_equal(tmpl["demurrage_contribution"], 0)
        with node2.assert_debug_log([], unexpected_msgs=[RULE_WARNING]):
            node2.getblocktemplate(UNDECLARED)
            assert node2.getblocktemplate(DECLARED)["version"] & (1 << CHARGES_BIT)

        self.log.info("From the lock-in of both, CHARGE_HEIGHT is known, and the mempool computes policy charges")
        tx = send(Decimal("0.0001"))
        # No evaluation height reaches CHARGE_HEIGHT, at which this input's charge exceeds the tolerance.
        assert_equal(assert_policy(tx), (charge_height - 1, 0))
        txout = node2.gettxout(tx["txid"], 0)
        assert_equal(txout["charge"], 0)
        assert_equal(txout["effective_value"], txout["value"])
        mine_to(charge_height - 2)

        tx = send(Decimal("0.02"))
        assert_equal(assert_policy(tx), (charge_height - 1, 0))
        tmpl = node2.getblocktemplate(UNDECLARED)
        assert not {"demurrage_charges", "!demurrage_charges"} & set(tmpl["rules"])
        mine_empty()

        self.log.info("At CHARGE_HEIGHT the rate is not zero here, so demurrage_charges is required at once")
        assert_equal(node2.getblockcount() + 1, charge_height)
        assert_equal(status_next("demurrage_charges"), "active")
        # The policy charge was evaluated again, because the next block's height exceeds E_tx.
        evaluation, charge = assert_policy(tx)
        assert_equal(evaluation, charge_height)
        assert_equal(charge, schedule2.charge(*tx["coin"], charge_height))
        assert_greater_than(charge, 0)
        assert_raises_rpc_error(-8, RULE_REQUIRED_ERROR, node2.getblocktemplate, UNDECLARED)
        tmpl = node2.getblocktemplate(DECLARED)
        assert "!demurrage_charges" in tmpl["rules"] and "demurrage" in tmpl["rules"]
        assert_equal(tmpl["vbavailable"], {})
        assert_equal(tmpl["demurrage_contribution"], charge)
        mine_to(charge_height)
        block = node2.getblock(node2.getbestblockhash(), 2)
        assert_equal([tx["txid"]], [t["txid"] for t in block["tx"][1:]])
        assert_equal([to_sat(txout["value"]) for txout in block["tx"][0]["vout"] if txout["scriptPubKey"]["hex"] == POOL_SCRIPT_HEX], [charge])

    def test_pre_activation(self):
        node0, node1 = self.nodes[:2]
        self.log.info("Before activation, POOL_SCRIPT outputs are ordinary outputs")
        self.generate(self.wallet, 200)
        deployments = node0.getdeploymentinfo()["deployments"]
        assert_equal(deployments["demurrage"], {"type": "buried", "active": False, "height": ACTIVATION_HEIGHT})
        assert_equal(deployments["demurrage_charges"], {"type": "buried", "active": False, "height": CHARGE_HEIGHT})
        assert not {"demurrage", "demurrage_charges"} & set(node1.getdeploymentinfo()["deployments"])

        # Policy refuses transactions that create POOL_SCRIPT outputs.
        tx = self.pool_script_tx()
        for node in self.nodes[:3]:
            assert_equal(node.testmempoolaccept([tx.serialize().hex()])[0]["reject-reason"], "demurrage-pool-output")

        # Coins for the pre-signed transactions (two 10 BTC outputs), and small coins.
        funding_info = self.wallet.create_self_transfer_multi(num_outputs=3 + len(SMALL_COINS), fee_per_output=1000)
        funding = funding_info["tx"]
        value_in = sum(txout.nValue for txout in funding.vout) + to_sat(funding_info["fee"])
        funding.vout[0] = CTxOut(10 * COIN, self.presigned_wallet.get_output_script())
        funding.vout[1] = CTxOut(10 * COIN, self.presigned_wallet.get_output_script())
        for n, value in enumerate(SMALL_COINS.values(), start=2):
            funding.vout[n].nValue = value
        funding.vout[-1].nValue = value_in - 20 * COIN - sum(SMALL_COINS.values()) - 10_000
        self.small_coins = {name: (funding.txid_hex, n) for n, name in enumerate(SMALL_COINS, start=2)}

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
        deployments = node0.getdeploymentinfo()["deployments"]
        assert_equal(deployments["demurrage"]["active"], True)
        assert_equal(deployments["demurrage_charges"]["active"], False)

    def test_enforcement_before_charges(self):
        node0, node1 = self.nodes[:2]
        self.log.info("From ACTIVATION_HEIGHT the rules are enforced, and until CHARGE_HEIGHT no block owes a charge")
        assert_equal(self.next_height(), ACTIVATION_HEIGHT)
        # node0's CHARGE_HEIGHT is forced, so it is known, and policy charges are
        # computed, at any height. Here no evaluation height passes CHARGE_HEIGHT.
        tx = self.send_charged()
        assert_equal(tx["policy"], (ACTIVATION_HEIGHT + CHARGE_MARGIN, 0))
        self.mine()
        assert_equal(node0.getblockcount(), ACTIVATION_HEIGHT)
        assert_equal(self.pool[node0.getbestblockhash()]["charge"], 0)

        self.log.info("getblocktemplate: demurrage is an optional rule, and templates give charges")
        with node0.assert_debug_log([RULE_WARNING]):
            tmpl = node0.getblocktemplate(UNDECLARED)
        assert "demurrage" in tmpl["rules"] and "!demurrage" not in tmpl["rules"]
        assert not {"demurrage_charges", "!demurrage_charges"} & set(tmpl["rules"])
        self.check_template(tmpl)
        assert_equal(tmpl["demurrage_contribution"], 0)
        with node0.assert_debug_log([], unexpected_msgs=[RULE_WARNING]):
            node0.getblocktemplate(UNDECLARED)
            node0.getblocktemplate(DECLARED)
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

        self.mine(CHARGE_HEIGHT - 1 - node0.getblockcount())
        assert all(entry["charge"] == 0 for entry in self.pool.values())
        assert_equal(node0.getdeploymentinfo()["deployments"]["demurrage_charges"]["active"], True)

    def test_zero_rate_period(self):
        node0, node1 = self.nodes[:2]
        self.log.info("From CHARGE_HEIGHT the first rate period has a zero rate, so no block owes a charge yet")
        assert_equal(self.next_height(), CHARGE_HEIGHT)
        tmpl = node0.getblocktemplate(UNDECLARED)
        assert "demurrage_charges" in tmpl["rules"] and "!demurrage_charges" not in tmpl["rules"]
        self.check_template(tmpl)

        # A large input is evaluated up to the last block that owes nothing.
        tx = self.send_charged()
        assert_equal(tx["policy"], (FIRST_CHARGED_HEIGHT - 1, 0))
        self.mine()

        self.log.info("gettxout gives an output's charge in the next block, and its effective value")
        utxo = self.wallet.get_utxo(mark_as_spent=False, confirmed_only=True)
        txout = node0.gettxout(utxo["txid"], utxo["vout"])
        assert_equal(txout["charge"], 0)
        assert_equal(txout["effective_value"], utxo["value"])
        assert "charge" not in node1.gettxout(utxo["txid"], utxo["vout"])

        self.mine(FIRST_CHARGED_HEIGHT - 2 - node0.getblockcount())
        assert all(entry["charge"] == 0 for entry in self.pool.values())
        assert "demurrage_charges" in node0.getblocktemplate(UNDECLARED)["rules"]

        # Its fee also covers the charges of the next few blocks.
        self.first_charged = self.send_charged(extra_fee=5 * COIN)
        assert_equal(self.first_charged["policy"], (FIRST_CHARGED_HEIGHT - 1, 0))
        self.mine_without()
        assert_equal(self.pool[node0.getbestblockhash()]["charge"], 0)

        txout = node0.gettxout(utxo["txid"], utxo["vout"], include_mempool=False)
        charge = self.schedule.charge(to_sat(utxo["value"]), utxo["height"], FIRST_CHARGED_HEIGHT)
        assert_greater_than(charge, 0)
        assert_equal(to_sat(txout["charge"]), charge)
        assert_equal(to_sat(txout["effective_value"]), to_sat(utxo["value"]) - charge)

    def test_charges(self):
        node0 = self.nodes[0]
        self.log.info("Charges: the mempool ranks by net fee, the fee less the policy charge")
        assert_equal(self.next_height(), FIRST_CHARGED_HEIGHT)
        tx = self.first_charged
        # It was evaluated again, because the next block's height exceeds its evaluation height.
        charge = self.schedule.charge(*tx["coin"], FIRST_CHARGED_HEIGHT)
        assert_greater_than(charge, 0)
        self.assert_policy(tx["txid"], FIRST_CHARGED_HEIGHT, charge)

        self.log.info("getblocktemplate: from the first rate period with a non-zero rate, demurrage_charges is required")
        assert_raises_rpc_error(-8, RULE_REQUIRED_ERROR, node0.getblocktemplate, UNDECLARED)
        tmpl = node0.getblocktemplate(DECLARED)
        assert "!demurrage_charges" in tmpl["rules"] and "demurrage" in tmpl["rules"]
        assert_equal(tmpl["height"], FIRST_CHARGED_HEIGHT)
        self.check_template(tmpl)
        assert_equal(tmpl["demurrage_contribution"], charge)

        self.log.info("A large input has no margin: its policy charge is evaluated again every block")
        for height in (FIRST_CHARGED_HEIGHT + 1, FIRST_CHARGED_HEIGHT + 2):
            self.mine_without()
            assert_equal(self.next_height(), height)
            self.assert_policy(tx["txid"], height, self.schedule.charge(*tx["coin"], height))

        self.log.info("Block assembly pays C(h) into the coinbase contribution")
        self.mine()
        entry = self.pool[node0.getbestblockhash()]
        assert_equal(entry["charge"], self.schedule.charge(*tx["coin"], node0.getblockcount()))
        assert_equal(node0.getrawmempool(), [])
        self.first_contribution_height = node0.getblockcount()
        self.wallet.rescan_utxos()

    def test_evaluation_heights(self):
        node0 = self.nodes[0]
        self.log.info("Evaluation heights: up to CHARGE_MARGIN blocks ahead, but no further than costs CHARGE_TOLERANCE")
        accepted = self.next_height()
        sent = {name: self.send_charged(utxo=self.small_utxo(name), extra_fee=5000) for name in ("full_margin", "medium_margin", "short_margin")}
        margins = {name: tx["policy"][0] - accepted for name, tx in sent.items()}
        assert_equal(margins["full_margin"], CHARGE_MARGIN)
        assert 1 < margins["short_margin"] < margins["medium_margin"] < CHARGE_MARGIN, margins
        for tx in sent.values():
            evaluation, charge = tx["policy"]
            assert_greater_than(charge, self.schedule.charge(*tx["coin"], accepted))
            assert charge - self.schedule.charge(*tx["coin"], accepted) <= CHARGE_TOLERANCE

        self.log.info("A transaction is evaluated again when the next block's height exceeds its evaluation height")
        short = sent["short_margin"]
        while self.next_height() < short["policy"][0]:
            self.mine_without()
            for tx in sent.values():
                self.assert_policy(tx["txid"], *tx["policy"])
        self.mine_without()
        assert_equal(self.next_height(), short["policy"][0] + 1)
        evaluation, charge = self.policy([short["coin"]])
        assert_greater_than(evaluation, short["policy"][0])
        assert_greater_than(charge, short["policy"][1])
        self.assert_policy(short["txid"], evaluation, charge)
        # The others are not: they depend on when each transaction was accepted.
        for name in ("full_margin", "medium_margin"):
            self.assert_policy(sent[name]["txid"], *sent[name]["policy"])
        self.mine()
        assert_equal(node0.getrawmempool(), [])
        self.wallet.rescan_utxos()

    def test_unconfirmed_inputs(self):
        node0 = self.nodes[0]
        self.log.info("An input from an unconfirmed parent is charged as if the parent confirms in the next block")
        accepted = self.next_height()
        parent = self.send_charged(utxo=self.small_utxo("parent"), extra_fee=5000)
        child = self.send_child(parent)
        evaluation, charge = child["policy"]
        assert_greater_than(evaluation, accepted + 2)
        assert_greater_than(charge, 0)

        self.log.info("Its net fee does not fall when the parent confirms, only when it is evaluated again")
        self.mine_without()
        self.mine_without([parent["txid"]])
        child_coin = self.coin(parent["txid"], 0)
        assert_equal(child_coin, (to_sat(parent["new_utxo"]["value"]), accepted + 1))
        self.assert_policy(child["txid"], evaluation, charge)
        # The parent confirmed later than assumed, so the child owes less than its policy charge.
        assert_greater_than(charge, self.schedule.charge(*child_coin, evaluation))
        while self.next_height() < evaluation:
            self.mine_without()
            self.assert_policy(child["txid"], evaluation, charge)
        self.mine_without()
        # From then on, the input is charged from the height at which its parent confirmed.
        self.assert_policy(child["txid"], *self.policy([child_coin]))
        self.mine()
        assert child["txid"] in node0.getblock(node0.getbestblockhash())["tx"]
        self.wallet.rescan_utxos()

        self.log.info("A large input from an unconfirmed parent has no margin: it is charged once the parent confirms alone")
        accepted = self.next_height()
        parent = self.send_charged()
        child = self.send_child(parent, extra_fee=COIN)
        assert_equal(child["policy"], (accepted, 0))
        self.mine_without([parent["txid"]])
        assert_greater_than(self.pool[node0.getbestblockhash()]["charge"], 0)
        child_coin = self.coin(parent["txid"], 0)
        charge = self.schedule.charge(*child_coin, accepted + 1)
        assert_greater_than(charge, CHARGE_TOLERANCE)
        self.assert_policy(child["txid"], accepted + 1, charge)
        self.mine()
        assert child["txid"] in node0.getblock(node0.getbestblockhash())["tx"]
        self.wallet.rescan_utxos()

    def test_contributions(self):
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
        self.first_claim_height = node0.getblockcount()
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
        # so in the block its input has no charge.
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
            assert node0.getblockcount() < self.first_contribution_height + 2 * COINBASE_MATURITY
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
        parent_coin = self.coin(prevout_txid(parent_input), parent_input.prevout.n)
        parent_policy = self.policy([parent_coin])
        deficit = parent_policy[1] - to_sat(rescued["fee"])
        assert_greater_than(deficit, 0)
        # The child's own input is charged as if its parent confirmed in the next block.
        child_policy = self.policy([(to_sat(rescued["new_utxo"]["value"]), None)])
        child = self.presigned_wallet.create_self_transfer(utxo_to_spend=rescued["new_utxo"], fee=Decimal(deficit + child_policy[1] + 100_000) / COIN)
        result = node0.submitpackage([rescued["hex"], child["hex"]], maxfeerate=0)
        assert_equal(result["package_msg"], "success")
        self.assert_policy(rescued["txid"], *parent_policy)
        self.assert_policy(child["txid"], *child_policy)
        assert_greater_than(0, to_sat(node0.getmempoolentry(rescued["txid"])["fees"]["net"]))
        self.mine()
        block = node0.getblock(node0.getbestblockhash())
        assert rescued["txid"] in block["tx"] and child["txid"] in block["tx"]
        assert_equal(node0.getrawmempool(), [])

    def test_replacement(self):
        node0 = self.nodes[0]
        self.log.info("Replacement: the fee to beat is the greater of a transaction's net fee now and when it was accepted")
        self.wallet.rescan_utxos()
        large = self.wallet.get_utxo(confirmed_only=True)
        small = self.small_utxo("replaced")
        coins = [(to_sat(utxo["value"]), utxo["height"]) for utxo in (large, small)]
        net_fee = 100_000
        evaluation, charge = self.policy(coins)
        original = self.wallet.create_self_transfer_multi(utxos_to_spend=[large, small], fee_per_output=charge + net_fee)
        self.wallet.sendrawtransaction(from_node=node0, tx_hex=original["hex"])
        self.assert_policy(original["txid"], evaluation, charge)

        # A block later its net fee is below zero.
        self.mine_without()
        evaluation, later_charge = self.policy(coins)
        self.assert_policy(original["txid"], evaluation, later_charge)
        assert_greater_than(later_charge - charge, net_fee)

        # A transaction that spends only its small input owes a small charge, and
        # without this rule would only have to beat the original's net fee now.
        small_charge = self.policy([coins[1]])[1]
        too_low = self.wallet.create_self_transfer(utxo_to_spend=small, fee=Decimal(small_charge + net_fee // 2) / COIN)
        assert_raises_rpc_error(-26, "insufficient fee", node0.sendrawtransaction, too_low["hex"], 0)
        replacement = self.wallet.create_self_transfer(utxo_to_spend=small, fee=Decimal(small_charge + net_fee + 10_000) / COIN)
        node0.sendrawtransaction(replacement["hex"], 0)
        assert_equal(node0.getrawmempool(), [replacement["txid"]])
        # node1 compares fees, not net fees, and keeps the original until the block arrives.
        self.mine()
        assert replacement["txid"] in node0.getblock(node0.getbestblockhash())["tx"]
        self.wallet.rescan_utxos()

    def test_unfunded_transaction(self):
        node0 = self.nodes[0]
        self.log.info("Block assembly leaves out a prioritised transaction whose charge the block cannot fund")
        utxos = [self.wallet.get_utxo(confirmed_only=True) for _ in range(6)]
        charge = self.policy([(to_sat(utxo["value"]), utxo["height"]) for utxo in utxos])[1]
        assert_greater_than(charge, 2 * block_subsidy(self.next_height()))
        unfunded = self.wallet.create_self_transfer_multi(utxos_to_spend=utxos, fee_per_output=1000)
        assert_raises_rpc_error(-26, "min relay fee not met", node0.sendrawtransaction, unfunded["hex"], 0)
        node0.prioritisetransaction(txid=unfunded["txid"], fee_delta=charge + COIN)
        self.wallet.sendrawtransaction(from_node=node0, tx_hex=unfunded["hex"])
        child = self.wallet.create_self_transfer(utxo_to_spend=unfunded["new_utxos"][0], fee=Decimal("0.001"))
        self.wallet.sendrawtransaction(from_node=node0, tx_hex=child["hex"])
        funded = self.send_charged()
        assert_equal(sorted(node0.getrawmempool()), sorted([unfunded["txid"], child["txid"], funded["txid"]]))

        with node0.assert_debug_log([f"Leaving transaction {unfunded['txid']} out of the block template"]):
            tmpl = node0.getblocktemplate(DECLARED)
        # The template has the claim transaction and the transaction that pays its charge.
        assert_equal([entry["txid"] for entry in tmpl["transactions"]][1:], [funded["txid"]])
        self.check_template(tmpl)
        self.submit(self.block_from_template(tmpl))
        self.verify_chain()
        self.mine()
        assert_equal(sorted(node0.getrawmempool()), sorted([unfunded["txid"], child["txid"]]))

        # A block with a conflicting transaction removes it from the mempool.
        conflict = self.wallet.create_self_transfer(utxo_to_spend=utxos[0], fee=Decimal("10"))
        self.submit(self.make_block([conflict["tx"]]))
        self.sync_blocks()
        self.verify_chain()
        assert_equal(node0.getrawmempool(), [])
        for txid, prioritised in node0.getprioritisedtransactions().items():
            node0.prioritisetransaction(txid=txid, fee_delta=-prioritised["fee_delta"])
        assert_equal(node0.getprioritisedtransactions(), {})
        self.wallet.rescan_utxos()

    def test_restart(self):
        node0 = self.nodes[0]
        self.log.info("Policy charges and prioritisation survive a restart unchanged")
        large = self.send_charged(extra_fee=COIN)
        small = self.send_charged(utxo=self.small_utxo("restart"), extra_fee=5000)
        prioritised = self.send_charged()
        fee_delta = 12_345
        node0.prioritisetransaction(txid=prioritised["txid"], fee_delta=fee_delta)
        assert_greater_than(large["policy"][1], 0)
        assert_greater_than(small["policy"][0], self.next_height())
        self.assert_policy(prioritised["txid"], *prioritised["policy"], fee_delta=fee_delta)
        self.sync_mempools()

        def mempool_state():
            entries = node0.getrawmempool(verbose=True)
            return {txid: (entry["chargeheight"], entry["fees"]) for txid, entry in entries.items()}, node0.getprioritisedtransactions()

        before = mempool_state()
        assert_equal(sorted(before[0]), sorted(tx["txid"] for tx in (large, small, prioritised)))
        assert_equal(list(before[1]), [prioritised["txid"]])
        assert_equal(before[1][prioritised["txid"]]["fee_delta"], fee_delta)
        for _ in range(2):
            self.restart_node(0)
            self.wait_until(lambda: node0.getmempoolinfo()["loaded"])
            assert_equal(mempool_state(), before)
        self.connected = False
        self.mine()
        assert_equal(node0.getrawmempool(), [])
        self.wallet.rescan_utxos()

    def test_compact_blocks(self):
        node0 = self.nodes[0]
        self.log.info("Compact blocks prefill the claim transaction")
        tx = self.send_charged()
        self.mine()
        tip = node0.getbestblockhash()
        block = node0.getblock(tip)
        assert_equal(block["tx"][2:], [tx["txid"]])
        peer = node0.add_p2p_connection(CompactBlockPeer())
        peer.send_and_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, int(tip, 16))]))
        peer.wait_until(lambda: int(tip, 16) in peer.compact_blocks)
        compact = peer.compact_blocks[int(tip, 16)]
        assert_equal([prefilled.index for prefilled in compact.prefilled_txn], [0, 1])
        assert_equal([prefilled.tx.txid_hex for prefilled in compact.prefilled_txn], block["tx"][:2])
        assert_equal(len(compact.shortids), 1)

        self.log.info("A new block is announced with a compact block before it is validated")
        peer.send_and_ping(msg_sendcmpct(announce=True, version=2))
        # node0 announces a block this way only to a peer that has the block's parent.
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [int(tip, 16)]
        peer.send_and_ping(getheaders)
        self.wallet.rescan_utxos()
        txs = [self.wallet.create_self_transfer(fee=Decimal("1"))["tx"]]
        valid = self.make_block(txs)
        self.submit(valid)
        self.sync_blocks()
        peer.wait_until(lambda: valid.hash_int in peer.compact_blocks)
        assert_equal([prefilled.index for prefilled in peer.compact_blocks[valid.hash_int].prefilled_txn], [0, 1])

        self.log.info("A block without the expected claim transaction is not announced")
        self.wallet.rescan_utxos()
        txs = [self.wallet.create_self_transfer(fee=Decimal("1"))["tx"]]
        missing = self.make_block(txs, claim=False)
        self.submit(missing, "bad-demurrage-claim-missing")
        claim = build_claim(self.expected_pool_inputs(node0.getbestblockhash(), self.next_height()))
        claim.vout[0].nValue -= 1
        altered = self.make_block(txs, claim=claim)
        self.submit(altered, "bad-demurrage-claim")
        node0.syncwithvalidationinterfacequeue()
        peer.sync_with_ping()
        assert missing.hash_int not in peer.compact_blocks and altered.hash_int not in peer.compact_blocks

        self.log.info("The check does not cover the contribution: a block with a wrong one is still announced")
        self.make_block(txs)
        wrong = self.make_block(txs, contributions=[self.last_block_charge + 1])
        self.submit(wrong, "bad-cb-demurrage-amount")
        peer.wait_until(lambda: wrong.hash_int in peer.compact_blocks)
        node0.disconnect_p2ps()
        self.wallet.rescan_utxos()

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
        # Every policy charge is evaluated again for the new tip.
        assert_equal(self.next_height(), fork_height + 1)
        for tx in sent:
            self.assert_policy(tx["txid"], *self.policy([tx["coin"]]))

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

    def test_pruned(self):
        node0, node3 = self.nodes[0], self.nodes[3]
        self.log.info("A pruned node finds a block's pool inputs without the blocks that created them")
        # Extend the chain until blocks with claim transactions can be pruned.
        self.mine(self.first_claim_height + 2 * MIN_BLOCKS_TO_KEEP - node0.getblockcount())
        self.connect_nodes(0, 3)
        self.sync_blocks([node0, node3])
        tip = node3.getblockcount()
        node3.pruneblockchain(tip - MIN_BLOCKS_TO_KEEP)
        prune_height = node3.getblockchaininfo()["pruneheight"]
        assert_greater_than(prune_height, self.first_claim_height + 1)
        assert_raises_rpc_error(-1, "Block not available (pruned data)", node3.getblock, node3.getblockhash(prune_height - 1))
        # A restart empties the cache of pool outputs.
        self.restart_node(3)
        # Connecting the first block that is stored needs the carry of the
        # block below it, and the contribution of the block 100 below it.
        assert_greater_than(len(self.pool[node0.getblockhash(prune_height)]["pool_inputs"]), 0)
        with node3.assert_debug_log([], unexpected_msgs=["to find its demurrage pool outputs"]):
            assert_equal(node3.verifychain(4, tip - prune_height + 1), True)
        self.connect_nodes(0, 3)
        self.send_charged()
        self.mine()
        self.sync_blocks([node0, node3])
        assert_equal(node3.getbestblockhash(), node0.getbestblockhash())
        self.disconnect_nodes(0, 3)

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
