#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the BIP 462 signature hash flag, SIGHASH_DEMURRAGE.

From ACTIVATION_HEIGHT, taproot signatures (key path and script path) may use
the hash types 0x41, 0x42 and 0x43. Such a signature also commits to the value
of every input at the index of the transaction's reference height, and to that
reference height in committed form. The test checks that:
- these hash types are invalid before activation, and valid from it;
- a signature is valid only for the true input values and reference height;
- SIGHASH_DEMURRAGE cannot be combined with SIGHASH_ANYONECANPAY, nor used
  without SIGHASH_ALL, SIGHASH_NONE or SIGHASH_SINGLE;
- the node and the wallet record the BIP 462 PSBT input fields (each input's
  reference height and its value at the transaction's reference height), and
  sign with SIGHASH_DEMURRAGE: descriptorprocesspsbt, walletprocesspsbt and
  signrawtransactionwithwallet;
- a signer that does not know the coins signs with the PSBT's fields, and
  knows the fee from them. Wrong values make its signature invalid.
"""
from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_privkey,
)
from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_compact_size,
    tx_from_hex,
)
from test_framework.psbt import (
    PSBT,
    PSBT_IN_PROPRIETARY,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    SIGHASH_DEMURRAGE,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair

ACTIVATION_HEIGHT = 250
ONE = 10**18
# Regtest's subsidy first falls below the target at this height, so the
# demurrage index falls from it.
FIRST_DEMURRAGE_HEIGHT = 300

BAD_HASH_TYPE = "mempool-script-verify-flag-failed (Invalid Schnorr signature hash type)"
BAD_SIGNATURE = "mempool-script-verify-flag-failed (Invalid Schnorr signature)"
VALUES_MISSING = "Signing with SIGHASH_DEMURRAGE needs the value of every input at the transaction's reference height (BIP 462), which the PSBT does not hold"
# The BIP 462 PSBT input fields: proprietary keys with identifier "bip462".
PSBT_BIP462_REF_HEIGHT = bytes([PSBT_IN_PROPRIETARY]) + ser_compact_size(6) + b"bip462" + bytes([0])
PSBT_BIP462_VALUE = bytes([PSBT_IN_PROPRIETARY]) + ser_compact_size(6) + b"bip462" + bytes([1])


class DemurrageSighashTest(BitcoinTestFramework):
    def set_test_params(self):
        # The second node is an offline signer: it does not apply BIP 462 and
        # does not know the coins it signs for.
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"], []]
        # The wallet part runs only if the wallet is compiled.
        self.uses_wallet = None

    def setup_network(self):
        # The nodes are not connected.
        self.setup_nodes()

    def mine(self, n=1):
        return self.generate(self.wallet, n, sync_fun=self.no_op)

    def index_at(self, height):
        return ONE if height < ACTIVATION_HEIGHT else self.nodes[0].getdemurrageinfo(height)["index"]

    def fund(self, utxos, amount=COIN, script=None):
        """Pay amount to the taproot output (or to script) from each of the
        wallet's utxos, and confirm the payments. Each coin takes the reference
        height of the utxo that funds it."""
        node = self.nodes[0]
        coins = []
        for utxo in utxos:
            self.wallet.get_utxo(txid=utxo["txid"], vout=utxo["vout"])
            tx = self.wallet.create_self_transfer(utxo_to_spend=utxo, fee_rate=0)["tx"]
            tx.vout[0].nValue -= amount + 1000
            tx.vout.append(CTxOut(amount, self.tap.scriptPubKey if script is None else script))
            txid = self.wallet.sendrawtransaction(from_node=node, tx_hex=tx.serialize().hex())
            coins.append({"txid": txid, "vout": 1, "txout": tx.vout[1], "ref_height": utxo["height"]})
        self.mine()
        return coins

    def input_values(self, coins):
        """The value of each coin at the index of the reference height of a
        transaction that spends them, and that height in committed form."""
        ref_height = max(coin["ref_height"] for coin in coins)
        values = [coin["txout"].nValue * self.index_at(ref_height) // self.index_at(coin["ref_height"]) for coin in coins]
        return values, max(ref_height, ACTIVATION_HEIGHT - 1)

    def spend(self, coins, hash_types, *, values=None, ref_height=None, script_path=()):
        """A transaction that spends the coins, with one output per input. Input
        i is signed with hash_types[i], through the script path if i is in
        script_path. values and ref_height replace what SIGHASH_DEMURRAGE
        signatures commit to."""
        true_values, true_ref_height = self.input_values(coins)
        values = true_values if values is None else values
        ref_height = true_ref_height if ref_height is None else ref_height
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"])) for coin in coins]
        tx.vout = [CTxOut(value - 10_000, self.wallet.get_output_script()) for value in true_values]
        spent = [coin["txout"] for coin in coins]
        for i, hash_type in enumerate(hash_types):
            demurrage = {"demurrage_values": values, "ref_height": ref_height} if hash_type & SIGHASH_DEMURRAGE else {}
            suffix = bytes([hash_type]) if hash_type != SIGHASH_DEFAULT else b""
            witness = CTxInWitness()
            if i in script_path:
                leaf = self.tap.leaves["checksig"]
                sighash = TaprootSignatureHash(tx, spent, hash_type, i, scriptpath=True, leaf_script=leaf.script, codeseparator_pos=0xffffffff, **demurrage)
                control = bytes([leaf.version + self.tap.negflag]) + self.tap.internal_pubkey + leaf.merklebranch
                witness.scriptWitness.stack = [sign_schnorr(self.leaf_key, sighash) + suffix, leaf.script, control]
            else:
                sighash = TaprootSignatureHash(tx, spent, hash_type, i, **demurrage)
                witness.scriptWitness.stack = [sign_schnorr(self.tweaked_key, sighash) + suffix]
            tx.wit.vtxinwit.append(witness)
        return tx

    def check(self, tx, reason=None):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        if reason is None:
            assert_equal(result["allowed"], True)
        else:
            assert_equal(result["allowed"], False)
            assert_equal(result["reject-reason"], reason)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        key = generate_privkey()
        self.leaf_key = generate_privkey()
        leaf_script = CScript([compute_xonly_pubkey(self.leaf_key)[0], OP_CHECKSIG])
        self.tap = taproot_construct(compute_xonly_pubkey(key)[0], [("checksig", leaf_script)])
        self.tweaked_key = tweak_add_privkey(key, self.tap.tweak)

        self.mine(200)
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        old = self.fund(sorted((u for u in utxos if u["height"] <= 100), key=lambda u: u["height"])[:10])

        # Keys for the node's and the wallet's signers: a taproot key path
        # output and a P2WPKH output, funded before activation.
        tr_key, _ = generate_keypair(wif=True)
        wpkh_key, _ = generate_keypair(wif=True)
        self.tr_desc = descsum_create(f"tr({tr_key})")
        self.wpkh_desc = descsum_create(f"wpkh({wpkh_key})")
        self.tr_desc_pub = node.getdescriptorinfo(self.tr_desc)["descriptor"]
        self.wpkh_desc_pub = node.getdescriptorinfo(self.wpkh_desc)["descriptor"]
        self.tr_script = address_to_scriptpubkey(node.deriveaddresses(self.tr_desc_pub)[0])
        self.wpkh_script = address_to_scriptpubkey(node.deriveaddresses(self.wpkh_desc_pub)[0])
        self.tr_old, self.wpkh_old = (self.fund([u], script=script)[0] for u, script in zip(self.old_coinbases(2), (self.tr_script, self.wpkh_script)))

        self.test_before_activation(old)
        self.test_activation(old)
        self.mine(FIRST_DEMURRAGE_HEIGHT + 110 - node.getblockcount())
        self.wallet.rescan_utxos()
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        mature = [u for u in utxos if u["coinbase"] and FIRST_DEMURRAGE_HEIGHT < u["height"] <= node.getblockcount() - 100]
        new = self.fund(sorted(mature, key=lambda u: u["height"])[:8])
        assert_greater_than(ONE, self.index_at(new[0]["ref_height"]))
        self.test_committed_values(old, new)
        self.test_hash_types(old, new)
        self.test_node_signing()
        self.test_wallet_signing()

    def old_coinbases(self, n):
        """n of the wallet's coinbase outputs from before activation."""
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        return sorted((u for u in utxos if u["coinbase"] and u["height"] <= 100), key=lambda u: u["height"])[:n]

    def new_coinbases(self, n):
        """n of the wallet's mature coinbase outputs from after the index starts to fall."""
        tip = self.nodes[0].getblockcount()
        utxos = self.wallet.get_utxos(confirmed_only=True, mark_as_spent=False)
        return sorted((u for u in utxos if u["coinbase"] and FIRST_DEMURRAGE_HEIGHT < u["height"] <= tip - 100), key=lambda u: u["height"])[:n]

    def psbt_for(self, coins, fee, descriptors):
        """A PSBT that spends the coins to one output and pays fee, updated by the
        node with the coins and the descriptors."""
        node = self.nodes[0]
        values, _ = self.input_values(coins)
        psbt = node.createpsbt([{"txid": c["txid"], "vout": c["vout"]} for c in coins], [{self.wallet.get_address(): Decimal(sum(values) - fee) / COIN}])
        return node.utxoupdatepsbt(psbt, descriptors)

    def test_before_activation(self, old):
        node = self.nodes[0]
        self.log.info("Before activation, the node records no BIP 462 PSBT fields, and cannot sign with SIGHASH_DEMURRAGE")
        psbt = self.psbt_for([self.tr_old], 10_000, [self.tr_desc_pub])
        assert "demurrage" not in node.decodepsbt(psbt)["inputs"][0]
        assert_raises_rpc_error(-25, VALUES_MISSING, node.descriptorprocesspsbt, psbt, [self.tr_desc], "ALL|DEMURRAGE")
        assert_equal(node.descriptorprocesspsbt(psbt, [self.tr_desc])["complete"], True)
        for invalid in ("DEMURRAGE", "ALL|DEMURRAGE|ANYONECANPAY", "ANYONECANPAY|DEMURRAGE"):
            assert_raises_rpc_error(-8, f"'{invalid}' is not a valid sighash parameter.", node.descriptorprocesspsbt, psbt, [self.tr_desc], invalid)

        self.log.info("Before activation, the SIGHASH_DEMURRAGE hash types are invalid")
        for hash_type in (0x41, 0x42, 0x43):
            self.check(self.spend([old[0]], [hash_type]), BAD_HASH_TYPE)
            self.check(self.spend([old[0]], [hash_type], script_path=[0]), BAD_HASH_TYPE)
        self.check(self.spend([old[0]], [SIGHASH_ALL]))
        # In a block too.
        tx = self.spend([old[0]], [SIGHASH_ALL | SIGHASH_DEMURRAGE])
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(height), ntime=node.getblock(tip)["time"] + 1, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), "block-script-verify-flag-failed (Invalid Schnorr signature hash type)")

    def test_activation(self, old):
        node = self.nodes[0]
        self.log.info("They are valid from the activation block")
        self.mine(ACTIVATION_HEIGHT - 2 - node.getblockcount())
        tx = self.spend([old[0]], [SIGHASH_ALL | SIGHASH_DEMURRAGE])
        self.check(tx, BAD_HASH_TYPE)
        self.mine()
        # The next block is the activation block.
        self.check(tx)
        txid = node.sendrawtransaction(tx.serialize().hex())

        self.log.info("A reorganisation below activation removes them from the mempool")
        tip = node.getbestblockhash()
        node.invalidateblock(tip)
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT - 2)
        assert txid not in node.getrawmempool()
        # Block templates are valid: the transaction would not be.
        node.getblocktemplate({"rules": ["segwit"]})
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), txid)
        assert txid in node.getblock(self.mine()[0])["tx"]
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT)

    def test_committed_values(self, old, new):
        node = self.nodes[0]
        self.log.info("A signature commits to the value of each input at the transaction's reference height")
        coins = [old[1], new[0]]
        values, ref_height = self.input_values(coins)
        assert_equal(ref_height, new[0]["ref_height"])
        # The older coin is valued below its nominal value.
        nominal = [coin["txout"].nValue for coin in coins]
        assert_greater_than(nominal[0], values[0])
        assert_equal(nominal[1], values[1])
        both = [SIGHASH_ALL | SIGHASH_DEMURRAGE] * 2
        self.check(self.spend(coins, both, values=nominal), BAD_SIGNATURE)
        self.check(self.spend(coins, both, values=[values[0] + 1, values[1]]), BAD_SIGNATURE)
        self.check(self.spend(coins, both, values=values[::-1]), BAD_SIGNATURE)
        self.check(self.spend(coins, both, values=values[:1]), BAD_SIGNATURE)
        # A single signature that uses the flag is enough to commit to all of them.
        self.check(self.spend(coins, [SIGHASH_DEFAULT, SIGHASH_ALL | SIGHASH_DEMURRAGE], values=nominal), BAD_SIGNATURE)
        self.check(self.spend(coins, [SIGHASH_DEFAULT, SIGHASH_ALL | SIGHASH_DEMURRAGE]))

        self.log.info("It commits to the transaction's reference height, in committed form")
        for wrong in (ref_height - 1, ref_height + 1, ACTIVATION_HEIGHT - 1, 0):
            self.check(self.spend(coins, both, ref_height=wrong), BAD_SIGNATURE)
        # A reference height below ACTIVATION_HEIGHT is committed as ACTIVATION_HEIGHT - 1.
        self.check(self.spend([old[2]], both[:1], ref_height=old[2]["ref_height"]), BAD_SIGNATURE)
        self.check(self.spend([old[2]], both[:1], ref_height=ACTIVATION_HEIGHT - 1))

        self.log.info("Transactions signed with it are relayed and mined")
        mixed = self.spend(coins, both)
        single = self.spend([old[2]], both[:1])
        txids = [node.sendrawtransaction(tx.serialize().hex()) for tx in (mixed, single)]
        # They are validated again when the mempool is loaded.
        self.restart_node(0)
        assert_equal(sorted(node.getrawmempool()), sorted(txids))
        block = node.getblock(self.mine()[0])
        assert all(txid in block["tx"] for txid in txids)
        # Its outputs are created at the transaction's reference height.
        assert_equal(node.gettxout(txids[0], 0)["ref_height"], ref_height)

    def test_hash_types(self, old, new):
        node = self.nodes[0]
        self.log.info("SIGHASH_DEMURRAGE combines with SIGHASH_ALL, SIGHASH_NONE and SIGHASH_SINGLE, on both spending paths")
        txs = []
        for n, hash_type in enumerate((SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE)):
            coins = [old[3 + n], new[1 + n]]
            tx = self.spend(coins, [hash_type | SIGHASH_DEMURRAGE] * 2, script_path=[1])
            self.check(tx)
            self.check(self.spend(coins, [hash_type | SIGHASH_DEMURRAGE] * 2, script_path=[1], values=[coin["txout"].nValue for coin in coins]), BAD_SIGNATURE)
            txs.append(tx)

        self.log.info("It cannot be used alone, nor with SIGHASH_ANYONECANPAY")
        coins = [old[6], new[4]]
        for hash_type in (
            SIGHASH_DEMURRAGE,
            SIGHASH_DEMURRAGE | 0x04,
            SIGHASH_DEMURRAGE | SIGHASH_ANYONECANPAY,
            SIGHASH_DEMURRAGE | SIGHASH_ANYONECANPAY | SIGHASH_ALL,
            SIGHASH_DEMURRAGE | SIGHASH_ANYONECANPAY | SIGHASH_NONE,
            SIGHASH_DEMURRAGE | SIGHASH_ANYONECANPAY | SIGHASH_SINGLE,
        ):
            self.check(self.spend(coins, [hash_type, SIGHASH_DEFAULT]), BAD_HASH_TYPE)
            self.check(self.spend(coins, [SIGHASH_DEFAULT, hash_type], script_path=[1]), BAD_HASH_TYPE)
        # The other inputs of the transaction may use any hash type.
        txs.append(self.spend(coins, [SIGHASH_ALL | SIGHASH_DEMURRAGE, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY], script_path=[0]))

        txids = [node.sendrawtransaction(tx.serialize().hex()) for tx in txs]
        block = node.getblock(self.mine()[0])
        assert all(txid in block["tx"] for txid in txids)


    def check_signatures(self, tx_hex, hash_types):
        """The last byte of the signature of each input (the first witness
        element), and the size of the taproot signatures."""
        tx = tx_from_hex(tx_hex)
        sigs = [w.scriptWitness.stack[0] for w in tx.wit.vtxinwit]
        assert_equal([sig[-1] for sig in sigs], hash_types)
        return tx

    def test_node_signing(self):
        node, signer = self.nodes
        self.log.info("utxoupdatepsbt records each input's reference height and its value at the transaction's reference height")
        tr_new = self.fund(self.new_coinbases(1), script=self.tr_script)[0]
        coins = [self.tr_old, tr_new, self.wpkh_old]
        values, committed = self.input_values(coins)
        assert_equal(committed, tr_new["ref_height"])
        # The coin from before activation is worth less than its nominal value.
        assert_greater_than(coins[0]["txout"].nValue, values[0])
        psbt = self.psbt_for(coins, 20_000, [self.tr_desc_pub, self.wpkh_desc_pub])
        decoded = node.decodepsbt(psbt)
        for coin, value, psbt_in in zip(coins, values, decoded["inputs"]):
            assert_equal(psbt_in["demurrage"], {"ref_height": max(coin["ref_height"], ACTIVATION_HEIGHT - 1), "value": Decimal(value) / COIN})
        assert_equal(decoded["fee"], Decimal(20_000) / COIN)
        assert_equal(node.analyzepsbt(psbt)["fee"], Decimal(20_000) / COIN)

        self.log.info("A signer that does not know the coins knows the fee from the fields, and signs with them")
        assert_equal(signer.getblockcount(), 0)
        assert_equal(signer.decodepsbt(psbt)["fee"], Decimal(20_000) / COIN)
        signed = signer.descriptorprocesspsbt(psbt, [self.tr_desc, self.wpkh_desc], "ALL|DEMURRAGE")
        assert_equal(signed["complete"], True)
        # The P2WPKH input is signed without SIGHASH_DEMURRAGE, which is for taproot only.
        tx = self.check_signatures(signed["hex"], [0x41, 0x41, 0x01])
        assert_equal([len(w.scriptWitness.stack[0]) for w in tx.wit.vtxinwit[:2]], [65, 65])
        # Unfinalized, the PSBT records the hash type of the taproot inputs only.
        unfinalized = signer.decodepsbt(signer.descriptorprocesspsbt(psbt, [self.tr_desc, self.wpkh_desc], "ALL|DEMURRAGE", True, False)["psbt"])
        assert_equal([psbt_in.get("sighash") for psbt_in in unfinalized["inputs"]], ["ALL|DEMURRAGE", "ALL|DEMURRAGE", None])
        assert unfinalized["inputs"][0]["taproot_key_path_sig"].endswith("41")
        self.check(tx)

        self.log.info("A value that is wrong makes the signature invalid: a valid signature pays the fee the fields give")
        tampered = PSBT.from_base64(psbt)
        tampered.i[0].map[PSBT_BIP462_VALUE] = (values[0] - 1).to_bytes(8, "little")
        assert_equal(signer.decodepsbt(tampered.to_base64())["fee"], Decimal(20_000 - 1) / COIN)
        bad = signer.descriptorprocesspsbt(tampered.to_base64(), [self.tr_desc, self.wpkh_desc], "ALL|DEMURRAGE")
        assert_equal(bad["complete"], True)
        self.check(tx_from_hex(bad["hex"]), BAD_SIGNATURE)
        # A node that knows the coins replaces wrong fields.
        assert_equal(node.decodepsbt(node.utxoupdatepsbt(tampered.to_base64()))["inputs"][0]["demurrage"]["value"], Decimal(values[0]) / COIN)

        self.log.info("Values that cannot be right, or missing fields, leave nothing to sign with")
        for index, key, value in (
            # An input worth more than its nominal value.
            (0, PSBT_BIP462_VALUE, coins[0]["txout"].nValue + 1),
            # The input at the transaction's reference height worth less than its nominal value.
            (1, PSBT_BIP462_VALUE, coins[1]["txout"].nValue - 1),
            # A missing field.
            (0, PSBT_BIP462_REF_HEIGHT, None),
        ):
            tampered = PSBT.from_base64(psbt)
            if value is None:
                del tampered.i[index].map[key]
            else:
                tampered.i[index].map[key] = value.to_bytes(8, "little")
            assert_raises_rpc_error(-25, VALUES_MISSING, signer.descriptorprocesspsbt, tampered.to_base64(), [self.tr_desc, self.wpkh_desc], "ALL|DEMURRAGE")
            # Signing without SIGHASH_DEMURRAGE does not need the fields.
            assert_equal(signer.descriptorprocesspsbt(tampered.to_base64(), [self.tr_desc, self.wpkh_desc])["complete"], True)

        self.log.info("The transaction signed with the true values is valid, and is mined")
        txid = node.sendrawtransaction(signed["hex"])
        assert txid in node.getblock(self.mine()[0])["tx"]
        assert_equal(node.gettxout(txid, 0)["ref_height"], committed)

    def test_wallet_signing(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping the wallet tests: the wallet is not compiled")
            return
        node = self.nodes[0]
        self.log.info("The wallet records the BIP 462 fields in the PSBTs it creates")
        node.createwallet("w")
        w = node.get_wallet_rpc("w")
        script = address_to_scriptpubkey(w.getnewaddress(address_type="bech32m"))
        coins = self.fund(self.old_coinbases(2) + self.new_coinbases(2), script=script)
        psbt_coins = [coins[0], coins[2]]
        values, committed = self.input_values(psbt_coins)
        funded = w.walletcreatefundedpsbt(inputs=[{"txid": c["txid"], "vout": c["vout"]} for c in psbt_coins],
                                          outputs=[{self.wallet.get_address(): Decimal("1.5")}], options={"add_inputs": False})
        decoded = node.decodepsbt(funded["psbt"])
        # PSBT version 0 holds the unsigned transaction; version 2 holds its fields per input and output.
        if "tx" in decoded:
            outpoints = [(vin["txid"], vin["vout"]) for vin in decoded["tx"]["vin"]]
            value_out = sum(vout["value"] for vout in decoded["tx"]["vout"])
        else:
            outpoints = [(psbt_in["previous_txid"], psbt_in["previous_vout"]) for psbt_in in decoded["inputs"]]
            value_out = sum(psbt_out["amount"] for psbt_out in decoded["outputs"])
        coin_outpoints = [(c["txid"], c["vout"]) for c in psbt_coins]
        for outpoint, psbt_in in zip(outpoints, decoded["inputs"]):
            n = coin_outpoints.index(outpoint)
            assert_equal(psbt_in["demurrage"], {"ref_height": max(psbt_coins[n]["ref_height"], ACTIVATION_HEIGHT - 1), "value": Decimal(values[n]) / COIN})
        assert_equal(decoded["fee"], Decimal(sum(values)) / COIN - value_out)

        self.log.info("walletprocesspsbt signs with SIGHASH_DEMURRAGE")
        processed = w.walletprocesspsbt(funded["psbt"], True, "ALL|DEMURRAGE")
        assert_equal(processed["complete"], True)
        self.check_signatures(processed["hex"], [0x41, 0x41])
        txid = node.sendrawtransaction(processed["hex"])
        assert txid in node.getblock(self.mine()[0])["tx"]

        self.log.info("signrawtransactionwithwallet signs with SIGHASH_DEMURRAGE")
        raw_coins = [coins[1], coins[3]]
        values, _ = self.input_values(raw_coins)
        raw = node.createrawtransaction([{"txid": c["txid"], "vout": c["vout"]} for c in raw_coins],
                                        [{w.getnewaddress(): Decimal(value - 10_000) / COIN} for value in values])
        signed = w.signrawtransactionwithwallet(raw, [], "SINGLE|DEMURRAGE")
        assert_equal(signed["complete"], True)
        self.check(self.check_signatures(signed["hex"], [0x43, 0x43]))
        assert_raises_rpc_error(-8, "'ALL|DEMURRAGE|ANYONECANPAY' is not a valid sighash parameter.", w.signrawtransactionwithwallet, raw, [], "ALL|DEMURRAGE|ANYONECANPAY")
        # A value one satoshi too high for the outputs is invalid, as with any signature.
        too_much = node.createrawtransaction([{"txid": c["txid"], "vout": c["vout"]} for c in raw_coins],
                                             [{w.getnewaddress(): Decimal(value) / COIN} for value in values[:1]] + [{w.getnewaddress(): Decimal(values[1] + 1) / COIN}])
        assert_equal(node.testmempoolaccept([w.signrawtransactionwithwallet(too_much, [], "ALL|DEMURRAGE")["hex"]])[0]["reject-reason"], "bad-txns-in-belowout")


if __name__ == '__main__':
    DemurrageSighashTest(__file__).main()
