#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462b (soft-fork demurrage) with assumeutxo snapshots.

The pool inputs of a block are the carry, which the claim transaction of the
block before it created, and the contribution of the block COINBASE_MATURITY
below it. A node that loads a snapshot has none of the blocks below the
snapshot's base, so it finds the unspent pool outputs in the snapshot's coins
and records them.

The regtest assumeutxo data at SNAPSHOT_BASE_HEIGHT is for the deterministic
chain built here, on which BIP 462b is enforced from height 288 and the index
starts at height 432. Every block from FIRST_CHARGED_HEIGHT spends an old
coinbase output, so the snapshot holds a carry and COINBASE_MATURITY
contributions.

The test checks that a node that loaded the snapshot:
- connects the blocks after the base, each of which spends pool outputs that
  blocks below the base created;
- still does so after a restart;
- reports the same pool outputs as the node that validated every block;
- completes background validation.
"""
from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

ACTIVATION_HEIGHT = 288
CHARGE_HEIGHT = 432
FIRST_CHARGED_HEIGHT = 576
SNAPSHOT_BASE_HEIGHT = 710
RESTART_HEIGHT = 730
FINAL_HEIGHT = 830
COINBASE_MATURITY = 100
MOCKTIME = 1_700_000_000
POOL_SCRIPT_HEX = "04706f6f6c7551"

# The regtest assumeutxo data for SNAPSHOT_BASE_HEIGHT (src/kernel/chainparams.cpp).
EXPECTED = {
    "base_hash": "111b72d10a0d42d5557452bcbefe92c12e7d311bcb6837967984ea14f7f645e1",
    "txoutset_hash": "95b09e6600281646b2422a0e124b97fa3e834ec8a842824ab87192c1c6a52de8",
    "nchaintx": 881,
}


class DemurrageAssumeutxoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}",
            f"-testactivationheight=demurrage_charges@{CHARGE_HEIGHT}",
        ]] * self.num_nodes

    def setup_network(self):
        # The nodes are connected only once the snapshot is loaded.
        self.add_nodes(self.num_nodes)
        self.start_nodes(extra_args=self.extra_args)

    def extend_chain(self, wallet, height):
        """Mine up to height. From FIRST_CHARGED_HEIGHT each block spends a
        coinbase output, so that it owes a charge and has a contribution."""
        node = self.nodes[0]
        while node.getblockcount() < height:
            if node.getblockcount() + 1 >= FIRST_CHARGED_HEIGHT:
                utxo = wallet.get_utxo(confirmed_only=True)
                charge = node.gettxout(utxo["txid"], utxo["vout"])["charge"]
                tx = wallet.create_self_transfer(utxo_to_spend=utxo, fee=charge + Decimal(20_000) / COIN)
                wallet.sendrawtransaction(from_node=node, tx_hex=tx["hex"])
            self.generate(wallet, 1, sync_fun=self.no_op)

    def pool_outputs(self, node, height):
        """The pool outputs that the block at height created: (carry, contribution)."""
        block = node.getblock(node.getblockhash(height), 2)

        def pool_output(tx):
            for vout in tx["vout"]:
                if vout["scriptPubKey"]["hex"] == POOL_SCRIPT_HEX:
                    return (tx["txid"], vout["n"])
            return None

        carry = pool_output(block["tx"][1]) if len(block["tx"]) > 1 else None
        return carry, pool_output(block["tx"][0])

    def run_test(self):
        n0, n1 = self.nodes
        for node in self.nodes:
            node.setmocktime(MOCKTIME)
        wallet = MiniWallet(n0)
        self.generate(wallet, FIRST_CHARGED_HEIGHT - 1, sync_fun=self.no_op)
        self.extend_chain(wallet, SNAPSHOT_BASE_HEIGHT)

        self.log.info("The snapshot holds the carry and the unspent contributions")
        carry, _ = self.pool_outputs(n0, SNAPSHOT_BASE_HEIGHT)
        assert carry is not None
        contributions = [self.pool_outputs(n0, height)[1] for height in range(SNAPSHOT_BASE_HEIGHT - COINBASE_MATURITY + 1, SNAPSHOT_BASE_HEIGHT + 1)]
        assert all(contribution is not None for contribution in contributions)
        for txid, n in [carry] + contributions:
            assert n0.gettxout(txid, n) is not None
        dump = n0.dumptxoutset("utxos.dat", "latest")
        self.log.info(f"Snapshot: {dump}")
        assert_equal(dump["base_height"], SNAPSHOT_BASE_HEIGHT)
        for key, value in EXPECTED.items():
            assert_equal(dump[key], value)

        self.extend_chain(wallet, FINAL_HEIGHT)
        for height in range(1, FINAL_HEIGHT + 1):
            n1.submitheader(n0.getblock(n0.getblockhash(height), 0)[:160])

        self.log.info("A node that loads the snapshot records the pool outputs of the blocks below its base")
        with n1.assert_debug_log([f"recorded the demurrage pool outputs of {COINBASE_MATURITY} blocks ({COINBASE_MATURITY + 1} outputs)"]):
            loaded = n1.loadtxoutset(dump["path"])
        assert_equal(loaded["base_height"], SNAPSHOT_BASE_HEIGHT)
        for txid, n in [carry] + contributions:
            assert n1.gettxout(txid, n) is not None

        self.log.info("It connects the blocks after the base, whose claim transactions spend those outputs")
        for height in range(SNAPSHOT_BASE_HEIGHT + 1, RESTART_HEIGHT + 1):
            n1.submitblock(n0.getblock(n0.getblockhash(height), 0))
        assert_equal(n1.getblockcount(), RESTART_HEIGHT)
        assert_equal(n1.getbestblockhash(), n0.getblockhash(RESTART_HEIGHT))

        self.log.info("The records survive a restart")
        self.restart_node(1, extra_args=self.extra_args[1])
        n1.setmocktime(MOCKTIME)
        # Blocks up to SNAPSHOT_BASE_HEIGHT + COINBASE_MATURITY spend
        # contributions of blocks at or below the base.
        for height in range(RESTART_HEIGHT + 1, SNAPSHOT_BASE_HEIGHT + COINBASE_MATURITY + 5):
            n1.submitblock(n0.getblock(n0.getblockhash(height), 0))
        assert_equal(n1.getblockcount(), SNAPSHOT_BASE_HEIGHT + COINBASE_MATURITY + 4)

        self.log.info("Background validation connects the blocks below the base and validates the snapshot")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        self.wait_until(lambda: len(n1.getchainstates()["chainstates"]) == 1)
        assert_equal(n1.getchainstates()["chainstates"][0]["blocks"], FINAL_HEIGHT)
        for key in ("hash_serialized_3", "txouts", "total_amount"):
            assert_equal(n1.gettxoutsetinfo("hash_serialized_3")[key], n0.gettxoutsetinfo("hash_serialized_3")[key])

        self.log.info("The node then validates and mines new blocks")
        self.generate(n1, 2)
        assert_equal(n0.getblockcount(), FINAL_HEIGHT + 2)
        n1.verifychain(4, 0)


if __name__ == '__main__':
    DemurrageAssumeutxoTest(__file__).main()
