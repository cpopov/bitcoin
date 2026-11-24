#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet's opt-in replay protection for BIP 462 (-walletdemurragesighash).

If the chain splits at ACTIVATION_HEIGHT, a transaction that spends only
outputs created before the split, and that is signed without
SIGHASH_DEMURRAGE, is valid on both chains. With -walletdemurragesighash, the
wallet signs the transactions it sends with SIGHASH_ALL|SIGHASH_DEMURRAGE once
BIP 462 applies to the next block. A transaction with a taproot input is then
invalid on a chain that does not apply BIP 462.

The second node never applies BIP 462. It shares the chain up to
ACTIVATION_HEIGHT - 1, and then stays at that height. The test checks that:
- before activation, the option has no effect;
- from activation, sendtoaddress, bumpfee, send and sendall sign taproot inputs
  with SIGHASH_ALL|SIGHASH_DEMURRAGE, and the second node rejects them;
- the fee rate is not below the one requested, although the signatures are a
  byte longer;
- one such signature is enough, while a transaction without a taproot input is
  not protected;
- coin selection prefers an input set with a taproot coin: to one that wastes
  less, to one with more confirmations, and when it has to mix output types;
- the signatures commit to the values of the inputs when these are below their
  nominal values;
- without a taproot coin, coin selection prefers an input set with a coin that
  the second node does not have: one descended from a coinbase mined at or
  after ACTIVATION_HEIGHT, or from a transaction with a SIGHASH_DEMURRAGE
  signature;
- without the option, the wallet's transactions can be replayed, and coin
  selection has no such preference.
"""
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.messages import (
    COIN,
    tx_from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)

ACTIVATION_HEIGHT = 250
# Regtest's subsidy first falls below the target at this height, so the
# demurrage index falls from it.
FIRST_DEMURRAGE_HEIGHT = 300
ONE = 10**18

ACTIVATION_ARG = f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"
BAD_HASH_TYPE = "mempool-script-verify-flag-failed (Invalid Schnorr signature hash type)"
SIGHASH_ALL = 0x01
ALL_DEMURRAGE = 0x41


class WalletDemurrageReplayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[ACTIVATION_ARG, "-walletdemurragesighash=1"], []]
        # The test creates the one wallet it uses.
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node, legacy = self.nodes
        node.createwallet(wallet_name="w", load_on_startup=True)
        self.w = node.get_wallet_rpc("w")
        # Two wallets without taproot coins.
        for name in ("d", "e"):
            node.createwallet(wallet_name=name, load_on_startup=True)

        # Coinbase outputs that the wallets hold on both chains: taproot ones
        # and P2WPKH ones, and a P2SH-P2WPKH output for each of the others.
        self.generatetoaddress(node, 14, self.w.getnewaddress(address_type="bech32m"))
        self.generatetoaddress(node, 4, self.w.getnewaddress(address_type="bech32"))
        self.d_shared, self.e_shared = [
            node.getblock(self.generatetoaddress(node, 1, node.get_wallet_rpc(name).getnewaddress(address_type="p2sh-segwit"))[0])["tx"][0]
            for name in ("d", "e")]
        self.generatetoaddress(node, 101, ADDRESS_BCRT1_UNSPENDABLE)
        self.shared = {kind: sorted((u["txid"], u["vout"]) for u in self.w.listunspent() if u["desc"].startswith(f"{kind}("))
                       for kind in ("tr", "wpkh")}
        assert_equal([len(self.shared[kind]) for kind in ("tr", "wpkh")], [14, 4])

        self.test_before_activation()
        self.log.info("Split the chain: the second node stays below ACTIVATION_HEIGHT")
        self.generatetoaddress(node, ACTIVATION_HEIGHT - 1 - node.getblockcount(), ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(legacy.getblockcount(), ACTIVATION_HEIGHT - 1)
        self.disconnect_nodes(0, 1)
        self.test_own_sends()
        self.test_input_types()
        self.test_coin_selection()
        self.test_committed_values()
        self.test_post_activation_coinbase()
        self.test_demurrage_signed_parent()
        self.test_without_option()

    def coins(self, kind):
        """One of the wallet's coins of kind ("tr" or "wpkh") that exist on both
        chains, and that no earlier test used or spent."""
        unspent = {(u["txid"], u["vout"]) for u in self.w.listunspent()}
        while True:
            txid, vout = self.shared[kind].pop()
            if (txid, vout) in unspent:
                return [{"txid": txid, "vout": vout}]

    def hash_types(self, tx_hex):
        """The hash type of the signature of each input: the last byte of the
        first witness element, or None for a 64-byte taproot signature, which
        uses SIGHASH_DEFAULT."""
        tx = tx_from_hex(tx_hex)
        sigs = [w.scriptWitness.stack[0] for w in tx.wit.vtxinwit]
        return [None if len(sig) == 64 else sig[-1] for sig in sigs]

    def send(self, inputs):
        """A transaction that the wallet signs and does not broadcast, which
        spends the inputs only and pays 1 BTC to itself. Its locktime is 0:
        the wallet would otherwise set it to the height of its own chain, which
        the second node does not reach."""
        result = self.w.send(outputs=[{self.w.getnewaddress(address_type="bech32m"): 1}], inputs=inputs,
                             add_inputs=False, add_to_wallet=False, fee_rate=2, locktime=0)
        assert_equal(result["complete"], True)
        return result["hex"]

    def accepted(self, node, tx_hex):
        result = node.testmempoolaccept([tx_hex])[0]
        return True if result["allowed"] else result["reject-reason"]

    def send_unprotected(self, address, amount):
        """Pay amount to address from the first wallet, signed with
        SIGHASH_DEFAULT (PSBT signing keeps the hash type it is given), so that
        the outputs are not separated by a SIGHASH_DEMURRAGE signature."""
        psbt = self.w.walletcreatefundedpsbt(inputs=[], outputs=[{address: amount}], options={"fee_rate": 2})["psbt"]
        signed = self.w.walletprocesspsbt(psbt=psbt, sighashtype="DEFAULT")
        assert_equal(signed["complete"], True)
        assert ALL_DEMURRAGE not in self.hash_types(signed["hex"])
        return self.nodes[0].sendrawtransaction(signed["hex"])

    def funded_spends(self, wallet):
        """A transaction that the wallet funds and signs, and does not broadcast,
        which pays 1 BTC to itself at 1 sat/vB, and the txids of the coins it
        spends. Its locktime is 0, as in send()."""
        result = wallet.send(outputs=[{wallet.getnewaddress(address_type="bech32"): 1}], add_to_wallet=False, fee_rate=1, locktime=0)
        assert_equal(result["complete"], True)
        return result["hex"], [f"{vin.prevout.hash:064x}" for vin in tx_from_hex(result["hex"]).vin]

    def funded_hash_types(self, wallet, amount, fee_rate):
        """The sorted hash types of the inputs of a transaction that the wallet
        funds and signs, and does not broadcast, which pays amount to itself."""
        result = wallet.send(outputs=[{wallet.getnewaddress(address_type="bech32m"): amount}], add_to_wallet=False, fee_rate=fee_rate)
        assert_equal(result["complete"], True)
        assert_equal(self.accepted(self.nodes[0], result["hex"]), True)
        return sorted(self.hash_types(result["hex"]), key=lambda hash_type: -1 if hash_type is None else hash_type)

    def test_before_activation(self):
        node, legacy = self.nodes
        self.log.info("Before activation, the option has no effect")
        assert_greater_than(ACTIVATION_HEIGHT - 1, node.getblockcount())
        tx_hex = self.send(self.coins("tr"))
        assert_equal(self.hash_types(tx_hex), [None])
        assert_equal(self.accepted(node, tx_hex), True)
        assert_equal(self.accepted(legacy, tx_hex), True)

    def test_own_sends(self):
        node, legacy = self.nodes
        w = self.w
        self.log.info("From activation, sendtoaddress signs with SIGHASH_ALL|SIGHASH_DEMURRAGE, and spends taproot coins")
        # The four P2WPKH coins could pay too, and below the consolidation
        # feerate, their larger inputs would waste less.
        # At least four inputs: a size estimate that left out the signatures'
        # hash type byte would be a vbyte short, and the fee below 1 sat/vB.
        txid = w.sendtoaddress(address=w.getnewaddress(address_type="bech32m"), amount=160, fee_rate=1)
        tx = tx_from_hex(w.gettransaction(txid)["hex"])
        spent = [(f"{vin.prevout.hash:064x}", vin.prevout.n) for vin in tx.vin]
        self.shared["tr"] = [coin for coin in self.shared["tr"] if coin not in spent]
        assert_greater_than_or_equal(len(spent), 4)
        assert_equal(self.hash_types(tx.serialize().hex()), [ALL_DEMURRAGE] * len(spent))
        entry = node.getmempoolentry(txid)
        assert_greater_than_or_equal(entry["fees"]["base"] * COIN, entry["vsize"])
        assert_equal(self.accepted(legacy, tx.serialize().hex()), BAD_HASH_TYPE)

        self.log.info("bumpfee does too")
        bumped = w.bumpfee(txid)["txid"]
        tx_hex = w.gettransaction(bumped)["hex"]
        assert_equal(self.hash_types(tx_hex), [ALL_DEMURRAGE] * len(spent))
        assert_equal(self.accepted(legacy, tx_hex), BAD_HASH_TYPE)
        block = self.generate(node, 1, sync_fun=self.no_op)[0]
        assert bumped in node.getblock(block)["tx"]
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("send does too")
        tx_hex = self.send(self.coins("tr"))
        assert_equal(self.hash_types(tx_hex), [ALL_DEMURRAGE])
        assert_equal(self.accepted(node, tx_hex), True)
        assert_equal(self.accepted(legacy, tx_hex), BAD_HASH_TYPE)

        self.log.info("sendall does too")
        result = w.sendall(recipients=[w.getnewaddress(address_type="bech32m")], inputs=self.coins("tr"), add_to_wallet=False, fee_rate=2, locktime=0)
        assert_equal(self.hash_types(result["hex"]), [ALL_DEMURRAGE])
        assert_equal(self.accepted(node, result["hex"]), True)
        assert_equal(self.accepted(legacy, result["hex"]), BAD_HASH_TYPE)

    def test_input_types(self):
        node, legacy = self.nodes
        self.log.info("One taproot input signed with it protects the transaction. Other inputs are signed with SIGHASH_ALL")
        tx_hex = self.send(self.coins("tr") + self.coins("wpkh"))
        # The wallet shuffles the inputs.
        assert_equal(sorted(self.hash_types(tx_hex)), [SIGHASH_ALL, ALL_DEMURRAGE])
        assert_equal(self.accepted(node, tx_hex), True)
        assert_equal(self.accepted(legacy, tx_hex), BAD_HASH_TYPE)

        self.log.info("A transaction without a taproot input is not protected")
        tx_hex = self.send(self.coins("wpkh"))
        assert_equal(self.hash_types(tx_hex), [SIGHASH_ALL])
        assert_equal(self.accepted(node, tx_hex), True)
        assert_equal(self.accepted(legacy, tx_hex), True)

    def test_coin_selection(self):
        node = self.nodes[0]
        self.log.info("Coin selection prefers a taproot coin with fewer confirmations")
        node.createwallet(wallet_name="m", load_on_startup=True)
        m = node.get_wallet_rpc("m")
        self.send_unprotected(m.getnewaddress(address_type="bech32"), 3)
        self.generate(node, 6, sync_fun=self.no_op)
        self.send_unprotected(m.getnewaddress(address_type="bech32m"), 0.2)
        self.generate(node, 1, sync_fun=self.no_op)
        # Coin selection otherwise spends a coin received from another wallet
        # with six confirmations, as the P2WPKH coin has, first.
        assert_equal(self.funded_hash_types(m, 0.1, fee_rate=1), [ALL_DEMURRAGE])

        self.log.info("When no output type can pay alone, coin selection adds a taproot coin to a mix of others")
        self.send_unprotected(m.getnewaddress(address_type="p2sh-segwit"), 3)
        self.generate(node, 1, sync_fun=self.no_op)
        # Above the consolidation feerate, the mix with the fewest inputs, of
        # the P2WPKH and P2SH-P2WPKH coins, would otherwise waste the least.
        assert_equal(self.funded_hash_types(m, 4, fee_rate=20), [SIGHASH_ALL, SIGHASH_ALL, ALL_DEMURRAGE])

    def test_committed_values(self):
        node = self.nodes[0]
        w = self.w
        self.log.info("The signatures commit to the inputs' values when these are below their nominal values")
        self.generate(node, FIRST_DEMURRAGE_HEIGHT - node.getblockcount(), sync_fun=self.no_op)
        new_height = node.getblockcount() + 1
        coinbase = node.getblock(self.generatetoaddress(node, 1, w.getnewaddress(address_type="bech32m"), sync_fun=self.no_op)[0])["tx"][0]
        self.generate(node, 100, sync_fun=self.no_op)
        assert_greater_than(ONE, node.getdemurrageinfo(new_height)["index"])
        new = [{"txid": u["txid"], "vout": u["vout"]} for u in w.listunspent() if u["txid"] == coinbase]
        assert_equal(len(new), 1)
        # The older input is valued below its nominal value, at the reference
        # height of the newer one.
        result = w.send(outputs=[{w.getnewaddress(address_type="bech32m"): 55}], inputs=self.coins("tr") + new, add_inputs=False, fee_rate=2)
        tx_hex = w.gettransaction(result["txid"])["hex"]
        assert_equal(self.hash_types(tx_hex), [ALL_DEMURRAGE] * 2)
        # The node accepted the signatures, so they commit to the true values.
        assert result["txid"] in node.getrawmempool()
        assert result["txid"] in node.getblock(self.generate(node, 1, sync_fun=self.no_op)[0])["tx"]
        assert_equal(node.gettxout(result["txid"], 0)["ref_height"], new_height)

    def test_post_activation_coinbase(self):
        node, legacy = self.nodes
        self.log.info("Without a taproot coin, coin selection spends a coin descended from a post-activation coinbase")
        d = node.get_wallet_rpc("d")
        coinbase = node.getblock(self.generatetoaddress(node, 1, d.getnewaddress(address_type="bech32"), sync_fun=self.no_op)[0])["tx"][0]
        self.generate(node, 100, sync_fun=self.no_op)
        # Below the consolidation feerate, the shared P2SH-P2WPKH coin's larger
        # input would waste less.
        tx_hex, spent = self.funded_spends(d)
        assert_equal(spent, [coinbase])
        # ECDSA signatures do not carry the flag: the other chain rejects the
        # transaction because it does not have the coin.
        assert_equal(self.hash_types(tx_hex), [SIGHASH_ALL])
        assert_equal(self.accepted(node, tx_hex), True)
        assert_equal(self.accepted(legacy, tx_hex), "missing-inputs")

    def test_demurrage_signed_parent(self):
        node, legacy = self.nodes
        self.log.info("Without a taproot coin, coin selection spends an output of a DEMURRAGE-signed transaction")
        e = node.get_wallet_rpc("e")
        # The other wallet's transaction spends a coin created before the split,
        # so its outputs' reference height is below ACTIVATION_HEIGHT.
        funding = self.w.send(outputs=[{e.getnewaddress(address_type="bech32"): 5}], inputs=self.coins("tr"), add_inputs=False, fee_rate=2)["txid"]
        assert_equal(self.hash_types(self.w.gettransaction(funding)["hex"]), [ALL_DEMURRAGE])
        self.generate(node, 1, sync_fun=self.no_op)
        assert_greater_than(ACTIVATION_HEIGHT, node.gettxout(funding, 0)["ref_height"])
        # Below the consolidation feerate, the shared P2SH-P2WPKH coin's larger
        # input would waste less.
        tx_hex, spent = self.funded_spends(e)
        assert_equal(spent, [funding])
        assert_equal(self.accepted(legacy, tx_hex), "missing-inputs")

        self.log.info("And then an output of a transaction that descends from one, although its own signatures do not have the flag")
        child = node.sendrawtransaction(tx_hex)
        assert_equal(self.hash_types(tx_hex), [SIGHASH_ALL])
        self.generate(node, 1, sync_fun=self.no_op)
        tx_hex, spent = self.funded_spends(e)
        assert_equal(set(spent), {child})
        assert_equal(self.accepted(legacy, tx_hex), "missing-inputs")

    def test_without_option(self):
        node, legacy = self.nodes
        self.log.info("Without the option, the wallet's transactions can be replayed on the other chain")
        self.restart_node(0, extra_args=[ACTIVATION_ARG])
        # The wallet is loaded on startup.
        self.w = node.get_wallet_rpc("w")
        tx_hex = self.send(self.coins("tr"))
        assert_equal(self.hash_types(tx_hex), [None])
        assert_equal(self.accepted(node, tx_hex), True)
        txid = node.sendrawtransaction(tx_hex)
        assert_equal(legacy.sendrawtransaction(tx_hex), txid)

        self.log.info("Without the option, coin selection does not prefer taproot coins")
        m = node.get_wallet_rpc("m")
        # All three coins have six confirmations now. Below the consolidation
        # feerate, the P2SH-P2WPKH coin's larger input wastes the least.
        assert_equal(self.funded_hash_types(m, 0.1, fee_rate=1), [SIGHASH_ALL])
        assert_equal(self.funded_hash_types(m, 4, fee_rate=20), [SIGHASH_ALL, SIGHASH_ALL])
        # Nor coins descended from a post-activation coinbase: the wallet spends
        # its shared coin, and the transaction is valid on the other chain too.
        tx_hex, spent = self.funded_spends(node.get_wallet_rpc("d"))
        assert_equal(spent, [self.d_shared])
        assert_equal(self.accepted(legacy, tx_hex), True)
        # Nor outputs of transactions that descend from a DEMURRAGE-signed one.
        tx_hex, spent = self.funded_spends(node.get_wallet_rpc("e"))
        assert_equal(spent, [self.e_shared])
        assert_equal(self.accepted(legacy, tx_hex), True)


if __name__ == '__main__':
    WalletDemurrageReplayTest(__file__).main()
