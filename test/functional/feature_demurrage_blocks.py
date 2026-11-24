#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the BIP 462 rules on blocks.

- "Activation block": the block at ACTIVATION_HEIGHT sets bit 31 of its header
  version, and no other block can.
- "Demurrage commitment": every block from ACTIVATION_HEIGHT commits, in its
  coinbase, to the demurrage state and to the reference height of each of its
  transactions.
- "Block timestamps": the two timestamp rules of BIP 54 apply from
  ACTIVATION_HEIGHT. On regtest a difficulty adjustment period is 144 blocks.
- "UTXO set value": the node computes the total value of the UTXO set ahead of
  ACTIVATION_HEIGHT - 1, at a height of its own choosing, and keeps it current.
"""
import re
import time

from test_framework.blocktools import (
    DEMURRAGE_COMMITMENT_HEADER,
    add_demurrage_commitment,
    add_witness_commitment,
    create_block,
    create_coinbase,
    demurrage_activation_version,
    get_demurrage_commitment,
    get_demurrage_commitment_script,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
from test_framework.wallet import MiniWallet

INTERVAL = 144
ACTIVATION_HEIGHT = 2 * INTERVAL
MAX_TIMEWARP = 7200


class DemurrageBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"]]

    def mine(self, n=1):
        return self.generate(self.wallet, n)

    def mine_to(self, height):
        self.mine(height - self.nodes[0].getblockcount())

    def tip_time(self):
        return self.nodes[0].getblock(self.nodes[0].getbestblockhash())["time"]

    def commitment(self, txs=(), *, activation_height=ACTIVATION_HEIGHT, **override):
        """The demurrage commitment of the next block. txs holds a
        (transaction, reference height) pair for each transaction."""
        info = self.nodes[0].getdemurrageinfo()
        values = {
            "index": info["next_block"]["index"],
            "rate": info["next_block"]["rate"],
            "prev_normalized": int(info["normalized_utxo"], 16),
            "height": info["next_block"]["height"],
        }
        values.update(override)
        return get_demurrage_commitment(**values, activation_height=activation_height, txs=[(tx.txid_int, ref) for tx, ref in txs])

    def block(self, *, version=None, ntime=None, txs=(), scripts=None):
        """A block on the tip. txs holds (transaction, reference height) pairs.
        scripts replaces the demurrage commitment by other coinbase outputs."""
        node = self.nodes[0]
        height = node.getblockcount() + 1
        if version is None:
            version = demurrage_activation_version() if height == ACTIVATION_HEIGHT else 4
        coinbase = create_coinbase(height, script_pubkey=self.wallet.get_output_script())
        block = create_block(int(node.getbestblockhash(), 16), coinbase, ntime=ntime or self.tip_time() + 1, version=version, txlist=[tx for tx, _ in txs])
        if scripts is None:
            scripts = [get_demurrage_commitment_script(self.commitment(txs))] if height >= ACTIVATION_HEIGHT else []
        for script in scripts:
            add_demurrage_commitment(block, script=script)
        if txs:
            add_witness_commitment(block)
        block.solve()
        return block

    def submit(self, block, result=None):
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), result)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.now = int(time.time())
        node.setmocktime(self.now)

        self.test_timestamps_before_activation()
        self.test_utxo_value_ahead_of_activation()
        self.test_activation_block()
        self.test_commitment_output()
        self.test_timestamps()
        self.test_commitment_to_reference_heights()

    def test_timestamps_before_activation(self):
        node = self.nodes[0]
        self.log.info("Before activation, the timestamp rules do not apply")
        self.mine_to(INTERVAL - 2)
        # A block three hours ahead of the others, then the first block of a
        # period more than two hours before it.
        self.now += 3 * 3600
        node.setmocktime(self.now)
        self.mine()
        self.submit(self.block(ntime=self.tip_time() - MAX_TIMEWARP - 1))
        assert_equal(node.getblockcount(), INTERVAL)

    def utxo_scans(self):
        """The heights at which the node scanned the UTXO set for its value."""
        with open(self.nodes[0].debug_log_path, encoding="utf-8") as log:
            return [int(m.group(1)) for m in re.finditer(r"BIP 462: computing the value of the UTXO set at height (\d+) ", log.read())]

    def check_utxo_value(self):
        node = self.nodes[0]
        assert_equal(node.getdemurrageinfo()["utxo_value"], node.gettxoutsetinfo()["total_amount"])

    def test_utxo_value_ahead_of_activation(self):
        node = self.nodes[0]
        self.log.info("The value of the UTXO set is computed once, well ahead of activation")
        scans = self.utxo_scans()
        assert_equal(len(scans), 1)
        # Each node picks the height: in the first half of the blocks before activation.
        assert scans[0] <= (ACTIVATION_HEIGHT - 1) // 2
        assert "utxo_value" in node.getdemurrageinfo(scans[0])
        if scans[0] > 0:
            assert "utxo_value" not in node.getdemurrageinfo(scans[0] - 1)

        self.log.info("It is then kept current, as blocks create and spend outputs")
        self.check_utxo_value()
        for _ in range(3):
            self.wallet.send_self_transfer(from_node=node)
            self.wallet.send_self_transfer(from_node=node)
            self.mine()
            self.check_utxo_value()

        self.log.info("Across a restart and a reorganisation too")
        # The chain's timestamps are ahead of the clock.
        self.restart_node(0, extra_args=self.extra_args[0] + [f"-mocktime={self.now}"])
        self.check_utxo_value()
        node.invalidateblock(node.getbestblockhash())
        self.check_utxo_value()
        # A later timestamp, so that the next block differs from the invalid one.
        self.now += 1
        node.setmocktime(self.now)
        self.mine(2)
        self.wallet.rescan_utxos()
        self.check_utxo_value()
        assert_equal(self.utxo_scans(), scans)
        self.scans = scans

    def test_activation_block(self):
        node = self.nodes[0]
        self.log.info("No block before the activation block can set bit 31 of its version")
        self.mine_to(ACTIVATION_HEIGHT - 2)
        self.submit(self.block(version=demurrage_activation_version()), "bad-version(0x80000004)")
        self.mine()
        assert_greater_than(node.getblockheader(node.getbestblockhash())["version"], 0)

        self.log.info("The activation block must set it")
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 1)
        # The value of the UTXO set at this block was not computed by a scan.
        assert_equal(self.utxo_scans(), self.scans)
        self.check_utxo_value()
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_greater_than(0, tmpl["version"])
        # The version bits that signal deployments are unchanged.
        assert_equal((tmpl["version"] & 0xffffffff) >> 29, 0b101)
        assert_equal(tmpl["default_demurrage_commitment"], get_demurrage_commitment_script(self.commitment()).hex())
        self.submit(self.block(version=4), "bad-version(0x00000004)")
        self.submit(self.block(version=0x20000000), "bad-version(0x20000000)")

        self.log.info("Every block from the activation block commits to the demurrage state")
        self.submit(self.block(scripts=[]), "bad-demurrage-commitment-missing")
        info = node.getdemurrageinfo()
        for wrong in (
            {"index": info["next_block"]["index"] - 1},
            {"rate": info["next_block"]["rate"] + 1},
            {"prev_normalized": int(info["normalized_utxo"], 16) + 1},
            {"height": ACTIVATION_HEIGHT + 1},
        ):
            self.submit(self.block(scripts=[get_demurrage_commitment_script(self.commitment(**wrong))]), "bad-demurrage-commitment")
        self.submit(self.block())
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)
        assert_equal(node.getblockheader(node.getbestblockhash())["version"], demurrage_activation_version())
        assert_equal(node.getdemurrageinfo()["active"], True)

        self.log.info("No block after the activation block can set bit 31 of its version")
        self.submit(self.block(version=demurrage_activation_version()), "bad-version(0x80000004)")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_greater_than(tmpl["version"], 0)
        mined = node.getblock(self.mine()[0], 2)
        assert_greater_than(mined["version"], 0)
        assert_equal(mined["tx"][0]["vout"][1]["scriptPubKey"]["hex"], tmpl["default_demurrage_commitment"])

    def test_commitment_output(self):
        node = self.nodes[0]
        self.log.info("The last output that has the form of a commitment is the commitment")
        good = get_demurrage_commitment_script(self.commitment())
        bad = get_demurrage_commitment_script(self.commitment(rate=1))
        assert_equal(len(good), 38)
        self.submit(self.block(scripts=[good, bad]), "bad-demurrage-commitment")
        self.submit(self.block(scripts=[bad, good]))

        self.log.info("An output shorter than 38 bytes, or with another header, is not a commitment")
        good = get_demurrage_commitment_script(self.commitment())
        short = CScript([OP_RETURN, DEMURRAGE_COMMITMENT_HEADER + bytes(31)])
        other_header = CScript([OP_RETURN, bytes.fromhex("9996b0b4") + bytes(32)])
        assert_equal(len(short), 37)
        self.submit(self.block(scripts=[short]), "bad-demurrage-commitment-missing")
        self.submit(self.block(scripts=[other_header]), "bad-demurrage-commitment-missing")
        self.submit(self.block(scripts=[good, short, other_header]))

        self.log.info("A commitment may be followed by more script")
        longer = CScript(bytes(get_demurrage_commitment_script(self.commitment())) + bytes([OP_TRUE]))
        assert_equal(len(longer), 39)
        self.submit(self.block(scripts=[longer]))
        assert_equal(node.getchaintips()[0]["status"], "active")

    def test_timestamps(self):
        node = self.nodes[0]
        start = (node.getblockcount() // INTERVAL + 1) * INTERVAL
        self.mine_to(start - 1)
        t = self.tip_time()
        node.setmocktime(t)

        self.log.info("The last block of a period cannot be earlier than its first block")
        self.submit(self.block(ntime=t + 7000))
        self.mine(INTERVAL - 2)
        assert_greater_than(t + 7000, self.tip_time())
        assert_equal(node.getblockcount(), start + INTERVAL - 2)
        # The node's own templates follow the rule.
        assert_equal(node.getblocktemplate({"rules": ["segwit"]})["mintime"], t + 7000)
        self.submit(self.block(ntime=t + 6999), "time-timewarp-attack")
        node.setmocktime(t + 100)
        self.submit(self.block(ntime=t + 7300))
        assert_equal(node.getblockcount(), start + INTERVAL - 1)

        self.log.info("The first block of a period cannot be more than two hours earlier than its parent")
        self.submit(self.block(ntime=t + 7300 - MAX_TIMEWARP - 1), "time-timewarp-attack")
        self.submit(self.block(ntime=t + 7300 - MAX_TIMEWARP))
        assert_equal(node.getblockcount(), start + INTERVAL)
        self.mine(2)

    def test_commitment_to_reference_heights(self):
        node = self.nodes[0]
        self.log.info("Blocks commit to the reference height of each transaction")
        self.wallet.rescan_utxos()
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        mature = [u for u in utxos if u["height"] <= node.getblockcount() - 100]
        old = [u for u in mature if u["height"] < ACTIVATION_HEIGHT][:2]
        new = sorted((u for u in mature if u["height"] > ACTIVATION_HEIGHT), key=lambda u: u["height"])[:2]
        assert_equal(len(old), 2)
        assert_equal(len(new), 2)
        assert_greater_than(new[1]["height"], new[0]["height"])
        for u in old + new:
            self.wallet.get_utxo(txid=u["txid"], vout=u["vout"])

        # A transaction's reference height is the highest among the coins it
        # spends; one below ACTIVATION_HEIGHT is committed as ACTIVATION_HEIGHT - 1.
        spend_old = self.wallet.create_self_transfer(utxo_to_spend=old[0])
        spend_new = self.wallet.create_self_transfer(utxo_to_spend=new[0])
        mixed = self.wallet.create_self_transfer_multi(utxos_to_spend=[old[1], new[1]], demurrage=True)
        child = self.wallet.create_self_transfer(utxo_to_spend=spend_new["new_utxo"])
        txs = [
            (spend_old["tx"], old[0]["height"]),
            (spend_new["tx"], new[0]["height"]),
            (mixed["tx"], new[1]["height"]),
            (child["tx"], new[0]["height"]),
        ]
        ref_heights = {tx.txid_hex: ref for tx, ref in txs}

        def with_ref_height(position, ref):
            return [(tx, ref if i == position else r) for i, (tx, r) in enumerate(txs)]

        raw = get_demurrage_commitment_script(self.commitment(txs, activation_height=0))
        self.submit(self.block(txs=txs, scripts=[raw]), "bad-demurrage-commitment")
        for position, ref in ((1, new[0]["height"] + 1), (2, new[1]["height"] - 1), (3, node.getblockcount() + 1)):
            wrong = get_demurrage_commitment_script(self.commitment(with_ref_height(position, ref)))
            self.submit(self.block(txs=txs, scripts=[wrong]), "bad-demurrage-commitment")
        # The order of the leaves is the order of the transactions.
        swapped = get_demurrage_commitment_script(self.commitment([txs[1], txs[0]] + txs[2:]))
        self.submit(self.block(txs=txs, scripts=[swapped]), "bad-demurrage-commitment")
        # Any height below ACTIVATION_HEIGHT gives the same commitment.
        assert_equal(self.commitment(with_ref_height(0, 1)), self.commitment(txs))

        self.log.info("The node's block template carries the commitment")
        for tx, _ in txs:
            node.sendrawtransaction(tx.serialize().hex())
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(len(tmpl["transactions"]), len(txs))
        by_txid = {tx.txid_hex: tx for tx, _ in txs}
        in_order = [(by_txid[t["txid"]], ref_heights[t["txid"]]) for t in tmpl["transactions"]]
        assert_equal(tmpl["default_demurrage_commitment"], get_demurrage_commitment_script(self.commitment(in_order)).hex())

        self.submit(self.block(txs=in_order))
        assert_equal(node.getrawmempool(), [])
        for tx, ref in txs:
            if tx is not spend_new["tx"]:
                assert_equal(node.gettxout(tx.txid_hex, 0)["ref_height"], ref)

        self.log.info("A generated block does too")
        self.wallet.rescan_utxos()
        self.wallet.send_self_transfer(from_node=node)
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        block = node.getblock(self.mine()[0], 2)
        assert_equal(len(block["tx"]), 2)
        assert tmpl["default_demurrage_commitment"] in [out["scriptPubKey"]["hex"] for out in block["tx"][0]["vout"]]


if __name__ == '__main__':
    DemurrageBlocksTest(__file__).main()
