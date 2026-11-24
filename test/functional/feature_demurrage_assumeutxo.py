#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP 462 (target-based demurrage) with assumeutxo snapshots.

A snapshot whose base is at or above ACTIVATION_HEIGHT carries the demurrage
state after each block from ACTIVATION_HEIGHT - 1 to its base (snapshot
version 3), and the UTXO set hash commits to the reference height of each coin
whose reference height differs from its height. The regtest assumeutxo data at
SNAPSHOT_BASE_HEIGHT commits to both, for the deterministic chain built here
with -testactivationheight=demurrage@ACTIVATION_HEIGHT.

The test checks that:
- snapshots below activation keep the version 2 format (feature_assumeutxo.py);
- a snapshot with missing or altered demurrage states is rejected;
- a loaded snapshot reproduces the demurrage state, and blocks after its base
  are valued with it;
- background validation computes the states again and validates the snapshot.
"""
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

ACTIVATION_HEIGHT = 432
SNAPSHOT_BASE_HEIGHT = 600
FINAL_HEIGHT = 650
MOCKTIME = 1_700_000_000

# The regtest assumeutxo data for SNAPSHOT_BASE_HEIGHT (src/kernel/chainparams.cpp).
EXPECTED = {
    "base_hash": "599b7245b716a63ef11dc2062b2e5a128391c1ce6a54c6fd19942342f06e0c46",
    "txoutset_hash": "f418caab799076e6a9fcbff721b5322a41cd3269466a9a13676594b55d7e6ca9",
    "nchaintx": 1001,
    "demurrage_states_hash": "205495c5730195916cce83a05e93d02cb9b1fc12935dec643ae7acaf332160fd",
}

# Snapshot metadata: magic (5), version (2), network magic (4), base block hash
# (32) and coin count (8), then, from version 3, the demurrage states.
METADATA_SIZE = 51
STATE_SIZE = 8 + 8 + 32
STATE_COUNT = SNAPSHOT_BASE_HEIGHT - ACTIVATION_HEIGHT + 2


class DemurrageAssumeutxoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"]] * self.num_nodes

    def setup_network(self):
        # The nodes are connected only once the snapshot is loaded.
        self.add_nodes(self.num_nodes)
        self.start_nodes(extra_args=self.extra_args)

    def extend_chain(self, wallet, height):
        """Mine up to height. Each block spends a coinbase output, so that its
        outputs inherit a reference height below their own height."""
        node = self.nodes[0]
        while node.getblockcount() < height:
            wallet.send_self_transfer(from_node=node)
            self.generate(wallet, 1, sync_fun=self.no_op)

    def run_test(self):
        n0, n1 = self.nodes
        n0.setmocktime(MOCKTIME)
        wallet = MiniWallet(n0)
        self.generate(wallet, 200, sync_fun=self.no_op)
        self.extend_chain(wallet, SNAPSHOT_BASE_HEIGHT)

        self.log.info("A snapshot above activation carries the demurrage states (version 3)")
        dump = n0.dumptxoutset("utxos.dat", "latest")
        self.log.info(f"Snapshot: {dump}")
        assert_equal(dump["base_height"], SNAPSHOT_BASE_HEIGHT)
        for key, value in EXPECTED.items():
            assert_equal(dump[key], value)
        with open(dump["path"], "rb") as f:
            contents = f.read()
        assert_equal(int.from_bytes(contents[5:7], "little"), 3)
        assert_equal(contents[METADATA_SIZE], STATE_COUNT)

        for height in range(1, SNAPSHOT_BASE_HEIGHT + 1):
            n1.submitheader(n0.getblock(n0.getblockhash(height), 0)[:160])

        self.log.info("A snapshot with altered demurrage states is rejected")
        bad_path = n1.datadir_path / "bad_utxos.dat"
        tampered = bytearray(contents)
        tampered[METADATA_SIZE + 1 + STATE_SIZE * 100] ^= 1  # the index after block ACTIVATION_HEIGHT + 99
        bad_path.write_bytes(bytes(tampered))
        assert_raises_rpc_error(-32603, "Bad snapshot BIP 462 demurrage state hash", n1.loadtxoutset, bad_path)

        self.log.info("A version 2 snapshot above activation is rejected")
        stripped = contents[:5] + (2).to_bytes(2, "little") + contents[7:METADATA_SIZE] + contents[METADATA_SIZE + 1 + STATE_SIZE * STATE_COUNT:]
        bad_path.write_bytes(stripped)
        assert_raises_rpc_error(-32603, f"Bad snapshot - expected {STATE_COUNT} BIP 462 demurrage states, got 0", n1.loadtxoutset, bad_path)

        self.log.info("A loaded snapshot reproduces the demurrage state")
        loaded = n1.loadtxoutset(dump["path"])
        assert_equal(loaded["base_height"], SNAPSHOT_BASE_HEIGHT)
        assert_equal(n1.getdemurrageinfo(), n0.getdemurrageinfo())
        assert_equal(n1.getdemurrageinfo(ACTIVATION_HEIGHT + 50), n0.getdemurrageinfo(ACTIVATION_HEIGHT + 50))
        assert_equal(n1.gettxoutsetinfo("none")["effective_total_amount"], n0.gettxoutsetinfo("none")["effective_total_amount"])
        assert_greater_than(1 * 10**18, n1.getdemurrageinfo()["index"])

        self.log.info("Blocks after the snapshot base are valued with its demurrage states")
        # A transaction spending a coin created before activation alongside a
        # coinbase output created after it, valued at the latter's index.
        utxos = wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        before = next(u for u in utxos if u["height"] < ACTIVATION_HEIGHT)
        after = next(u for u in utxos if u["coinbase"] and ACTIVATION_HEIGHT + 50 < u["height"] <= SNAPSHOT_BASE_HEIGHT - 100)
        for u in (before, after):
            wallet.get_utxo(txid=u["txid"], vout=u["vout"])
        mixed = wallet.send_self_transfer_multi(from_node=n0, utxos_to_spend=[before, after], demurrage=True)
        assert_greater_than(int(before["value"] * COIN) + int(after["value"] * COIN), mixed["tx"].vout[0].nValue)
        self.extend_chain(wallet, FINAL_HEIGHT)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(n1.getdemurrageinfo(), n0.getdemurrageinfo())

        self.log.info("Background validation computes the demurrage states again and validates the snapshot")
        self.wait_until(lambda: len(n1.getchainstates()["chainstates"]) == 1)
        assert_equal(n1.getchainstates()["chainstates"][0]["blocks"], FINAL_HEIGHT)
        assert_equal(n1.getdemurrageinfo(ACTIVATION_HEIGHT + 50), n0.getdemurrageinfo(ACTIVATION_HEIGHT + 50))
        for key in ("hash_serialized_3", "txouts", "total_amount", "effective_total_amount"):
            assert_equal(n1.gettxoutsetinfo("hash_serialized_3")[key], n0.gettxoutsetinfo("hash_serialized_3")[key])


if __name__ == '__main__':
    DemurrageAssumeutxoTest(__file__).main()
