#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the interfaces of BIP 462b (soft-fork demurrage).

feature_demurrage.py tests the consensus rules, the mempool and block assembly.
This test covers what software around the node sees:

- node interfaces: testmempoolaccept, submitpackage, scantxoutset and the REST
  interface report charges, and the fee limits of sendrawtransaction and
  testmempoolaccept apply to net fees;
- PSBT: the per-input confirmation height field, and the charge, net fee and
  charge bound that analyzepsbt derives from it;
- the wallet: effective balances and values, transactions that pay the charge
  of their inputs with a margin of WALLET_CHARGE_MARGIN blocks, and fee bumps
  that compare net fees;
- fee estimation, which tracks net feerates;
- compact blocks: a node builds the claim transaction of a block that it
  receives without it.

The chain enforces BIP 462b from height 288 and starts the index at height 432.
On regtest the first rate period with a non-zero rate begins at height 576. The
rate is then about 0.024% per block, so the charge of a coinbase output grows
by more than CHARGE_TOLERANCE every block, and its policy charge is evaluated
at the next block's height.
"""
from decimal import Decimal
import http.client
import json
import urllib.parse

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COIN,
    CTxOut,
    HeaderAndShortIDs,
    msg_cmpctblock,
    msg_headers,
    msg_sendcmpct,
    tx_from_hex,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

ACTIVATION_HEIGHT = 288
CHARGE_HEIGHT = 432
FIRST_CHARGED_HEIGHT = 576
START_HEIGHT = 600
CHARGE_TOLERANCE = 1000
WALLET_CHARGE_MARGIN = 6
POOL_SCRIPT = bytes.fromhex("04706f6f6c7551")
DECLARED = {"rules": ["segwit", "demurrage", "demurrage_charges"]}
FEE_RATE = 10  # sat/vB
SMALL_VALUE = Decimal("0.01")


def to_sat(btc):
    return int(Decimal(btc) * COIN)


class DemurrageInterfacesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [[
            f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}",
            f"-testactivationheight=demurrage_charges@{CHARGE_HEIGHT}",
            "-rest",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # ---- helpers ----

    def next_height(self):
        return self.nodes[0].getblockcount() + 1

    def mine(self, num_blocks=1):
        return self.generatetoaddress(self.nodes[0], num_blocks, self.mining_address)

    def mine_empty(self, num_blocks=1):
        """Mine blocks that leave the mempool as it is."""
        for _ in range(num_blocks):
            self.generateblock(self.nodes[0], f"addr({self.mining_address})", [])

    def charge_of(self, txid, vout):
        """The charge that an unspent output would owe in the next block, in satoshis."""
        return to_sat(self.nodes[0].gettxout(txid, vout)["charge"])

    def entry(self, txid):
        """(fee, policy charge, net fee, vsize) of a mempool transaction."""
        entry = self.nodes[0].getmempoolentry(txid)
        fee, charge, net = (to_sat(entry["fees"][key]) for key in ("base", "charge", "net"))
        assert_equal(net, fee - charge)
        return fee, charge, net, entry["vsize"]

    def coinbase_coin(self):
        """A mature 50 BTC coinbase output of the wallet, which nothing else in the test spends."""
        coin = next(u for u in self.wallet.listunspent() if u["amount"] == 50 and (u["txid"], u["vout"]) not in self.used)
        self.used.add((coin["txid"], coin["vout"]))
        self.wallet.lockunspent(False, [{"txid": coin["txid"], "vout": coin["vout"]}])
        return coin

    def raw_spend(self, coin, net_fee):
        """A signed transaction that spends a coin of the wallet and pays its
        charge in the next block and a net fee, in satoshis."""
        charge = self.charge_of(coin["txid"], coin["vout"])
        amount = coin["amount"] - Decimal(charge + net_fee) / COIN
        raw = self.nodes[0].createrawtransaction([{"txid": coin["txid"], "vout": coin["vout"]}], [{self.wallet.getnewaddress(): amount}])
        signed = self.wallet.signrawtransactionwithwallet(raw)
        assert signed["complete"]
        return signed["hex"], charge

    def rest_utxo(self, txid, vout):
        url = urllib.parse.urlparse(self.nodes[0].url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request("GET", f"/rest/getutxos/{txid}-{vout}.json")
        response = conn.getresponse()
        assert_equal(response.status, 200)
        utxos = json.loads(response.read().decode(), parse_float=Decimal)["utxos"]
        conn.close()
        return utxos[0]

    # ---- tests ----

    def run_test(self):
        node = self.nodes[0]
        self.wallet = node.get_wallet_rpc(self.default_wallet_name)
        self.mining_address = self.wallet.getnewaddress()
        self.used = set()

        self.log.info("Before the first charged block, nothing owes a charge")
        self.mine(CHARGE_HEIGHT - 32)
        balances = self.wallet.getbalances()["mine"]
        assert_equal(balances["effective"], balances["trusted"])
        self.mine(START_HEIGHT - node.getblockcount())

        self.test_node_interfaces()
        self.test_effective_balance()
        self.test_wallet_send()
        self.test_wallet_bumpfee()
        self.test_psbt()
        self.test_fee_estimation()
        self.test_compact_block_reconstruction()

    def test_node_interfaces(self):
        node = self.nodes[0]
        self.log.info("testmempoolaccept reports the policy charge, and its fee limit applies to the net fee")
        coin = self.coinbase_coin()
        tx_hex, charge = self.raw_spend(coin, net_fee=2_000)
        assert_greater_than(charge, 10_000_000)
        result = node.testmempoolaccept([tx_hex])[0]
        assert result["allowed"]
        assert_equal(result["chargeheight"], self.next_height())
        assert_equal(to_sat(result["fees"]["base"]), charge + 2_000)
        assert_equal(to_sat(result["fees"]["charge"]), charge)
        assert_equal(to_sat(result["fees"]["net"]), 2_000)
        # The fee is far above the default maxfeerate of 0.1 BTC/kvB. The net fee is not.
        assert_greater_than(result["fees"]["base"] * 1000 / result["vsize"], Decimal("0.1"))

        self.log.info("A net fee above the limit is refused")
        costly_hex, _ = self.raw_spend(coin, net_fee=3_000_000)
        assert_equal(node.testmempoolaccept([costly_hex])[0]["reject-reason"], "max-fee-exceeded")
        assert_raises_rpc_error(-25, "Fee rate exceeds maximum configured by user (maxfeerate)", node.sendrawtransaction, costly_hex)

        self.log.info("sendrawtransaction accepts a transaction whose fee is mostly its charge")
        txid = node.sendrawtransaction(tx_hex)
        assert_equal(self.entry(txid)[:3], (charge + 2_000, charge, 2_000))

        self.log.info("submitpackage reports the policy charge")
        coin = self.coinbase_coin()
        tx_hex, charge = self.raw_spend(coin, net_fee=2_000)
        result = node.submitpackage([tx_hex])
        assert_equal(result["package_msg"], "success")
        fees = next(iter(result["tx-results"].values()))["fees"]
        assert_equal((to_sat(fees["base"]), to_sat(fees["charge"]), to_sat(fees["net"])), (charge + 2_000, charge, 2_000))
        self.mine()

        self.log.info("scantxoutset and the REST interface report each output's charge and effective value")
        scan = node.scantxoutset("start", [f"addr({self.mining_address})"])
        assert_greater_than(len(scan["unspents"]), START_HEIGHT - 10)
        total_charge = 0
        for unspent in scan["unspents"][:20] + scan["unspents"][-20:]:
            txout = node.gettxout(unspent["txid"], unspent["vout"])
            assert_equal(unspent["charge"], txout["charge"])
            assert_equal(unspent["effective_value"], txout["effective_value"])
            assert_equal(unspent["effective_value"], unspent["amount"] - unspent["charge"])
            rest = self.rest_utxo(unspent["txid"], unspent["vout"])
            assert_equal(rest["charge"], txout["charge"])
            assert_equal(rest["effective_value"], txout["effective_value"])
        for unspent in scan["unspents"]:
            total_charge += to_sat(unspent["charge"])
        assert_greater_than(total_charge, 0)
        assert_equal(to_sat(scan["total_effective_value"]), to_sat(scan["total_amount"]) - total_charge)

    def test_effective_balance(self):
        node = self.nodes[0]
        self.log.info("The wallet reports each output's charge and effective value, and an effective balance")
        unspent = self.wallet.listunspent()
        for coin in unspent[:10]:
            txout = node.gettxout(coin["txid"], coin["vout"])
            assert_equal(coin["charge"], txout["charge"])
            assert_equal(coin["effective_value"], txout["effective_value"])
        # listunspent leaves out the locked outputs, which the balance includes.
        locked = [node.gettxout(txid, vout) for txid, vout in self.used if node.gettxout(txid, vout)]
        charges = sum(to_sat(coin["charge"]) for coin in unspent) + sum(to_sat(txout["charge"]) for txout in locked)
        balances = self.wallet.getbalances()["mine"]
        assert_equal(to_sat(balances["trusted"]), sum(to_sat(coin["amount"]) for coin in unspent) + sum(to_sat(txout["value"]) for txout in locked))
        assert_equal(to_sat(balances["effective"]), to_sat(balances["trusted"]) - charges)
        assert_greater_than(charges, 0)

        self.log.info("The effective balance falls with each block, and the balance does not")
        self.mine_empty()
        after = self.wallet.getbalances()["mine"]
        # The block matured a coinbase output, which adds to both.
        assert_greater_than(after["trusted"], balances["trusted"])
        assert_greater_than(after["trusted"] - after["effective"], balances["trusted"] - balances["effective"])

    def test_wallet_send(self):
        node = self.nodes[0]
        self.log.info("A wallet transaction pays the charge of its inputs on top of its feerate")
        # The wallet's coins are coinbase outputs, each with a charge far above
        # the default -maxtxfee of 0.1 BTC, which applies to the net fee.
        txid = self.wallet.sendtoaddress(address=self.wallet.getnewaddress(), amount=1, fee_rate=FEE_RATE)
        fee, charge, net, vsize = self.entry(txid)
        assert_greater_than(charge, 0)
        assert_greater_than_or_equal(net, FEE_RATE * vsize)
        assert_equal(to_sat(-self.wallet.gettransaction(txid)["fee"]), fee)

        self.log.info(f"It allows for the charge to grow for {WALLET_CHARGE_MARGIN} blocks, and no more")
        margin = net - FEE_RATE * vsize
        assert_greater_than(margin, CHARGE_TOLERANCE)
        self.mine_empty(WALLET_CHARGE_MARGIN)
        fee_after, charge_after, net_after, _ = self.entry(txid)
        assert_equal(fee_after, fee)
        assert_greater_than(charge_after, charge)
        # The wallet sized the fee for the largest signatures that it might make.
        # Nothing is left of the margin: one more block would take the net fee
        # below the feerate that the wallet chose.
        assert 0 <= net_after - FEE_RATE * vsize <= 2 * FEE_RATE, net_after - FEE_RATE * vsize
        self.mine()
        assert_equal(node.getrawmempool(), [])

        self.log.info("The charge can be subtracted from the amount sent")
        balance = self.wallet.getbalances()["mine"]["trusted"]
        txid = self.wallet.sendtoaddress(address=self.wallet.getnewaddress(), amount=5, fee_rate=FEE_RATE, subtractfeefromamount=True)
        fee, charge, net, vsize = self.entry(txid)
        assert_greater_than(charge, 0)
        assert_greater_than_or_equal(net, FEE_RATE * vsize)
        assert_equal(self.wallet.getbalances()["mine"]["trusted"], balance - Decimal(fee) / COIN)
        self.mine()

    def test_wallet_bumpfee(self):
        node = self.nodes[0]
        self.log.info("bumpfee compares net fees")
        # Outputs of a small value, whose charge grows by less than
        # CHARGE_TOLERANCE in a block, so that a margin costs little.
        self.wallet.sendmany(amounts={self.wallet.getnewaddress(): SMALL_VALUE for _ in range(4)}, fee_rate=FEE_RATE)
        self.mine()
        small = [coin for coin in self.wallet.listunspent() if coin["amount"] == SMALL_VALUE]
        assert_equal(len(small), 4)
        inputs = [{"txid": coin["txid"], "vout": coin["vout"]} for coin in small[:2]]
        self.mine(3)
        sent = self.wallet.send(outputs=[{self.wallet.getnewaddress(): SMALL_VALUE}], fee_rate=FEE_RATE, options={"inputs": inputs, "add_inputs": False})
        assert sent["complete"]
        txid = sent["txid"]
        fee, charge, net, vsize = self.entry(txid)
        # These inputs are evaluated a few blocks ahead, within the tolerance.
        assert_greater_than(node.getmempoolentry(txid)["chargeheight"], self.next_height())
        assert_greater_than(charge, 0)
        assert_greater_than_or_equal(net, FEE_RATE * vsize)

        self.mine_empty(2)
        bumped = self.wallet.bumpfee(txid)
        assert_equal(to_sat(bumped["origfee"]), fee)
        assert txid not in node.getrawmempool()
        new_fee, new_charge, new_net, new_vsize = self.entry(bumped["txid"])
        assert_equal(to_sat(bumped["fee"]), new_fee)
        # The replacement pays more net fee than the original did when it was
        # accepted, though the original's net fee has fallen since.
        assert_greater_than(new_net, net)
        assert_greater_than(new_charge, charge)

        self.log.info("A fee rate given to bumpfee is a net feerate")
        again = self.wallet.bumpfee(bumped["txid"], fee_rate=new_net // new_vsize + 5)
        final_fee, final_charge, final_net, final_vsize = self.entry(again["txid"])
        assert_greater_than_or_equal(final_net, (new_net // new_vsize + 5) * final_vsize)
        assert_greater_than(final_fee - final_net, 0)
        self.mine()
        assert_equal(node.getrawmempool(), [])

    def test_psbt(self):
        node = self.nodes[0]
        self.log.info("The wallet records each input's confirmation height in a PSBT")
        funded = self.wallet.walletcreatefundedpsbt([], [{self.wallet.getnewaddress(): 2}], 0, {"fee_rate": FEE_RATE})
        decoded = node.decodepsbt(funded["psbt"])
        charge = 0
        for psbt_input in decoded["inputs"]:
            txout = node.gettxout(psbt_input["previous_txid"], psbt_input["previous_vout"])
            assert_equal(psbt_input["confirmation_height"], node.getblockcount() - txout["confirmations"] + 1)
            charge += to_sat(txout["charge"])
        assert_greater_than(charge, 0)

        self.log.info("analyzepsbt gives the charge, the net fee and a bound that does not depend on the heights")
        analysis = node.analyzepsbt(funded["psbt"])
        assert_equal(analysis["fee"], funded["fee"])
        assert_equal(to_sat(analysis["charge"]), charge)
        assert_equal(to_sat(analysis["net_fee"]), to_sat(funded["fee"]) - charge)
        assert_greater_than_or_equal(to_sat(analysis["net_fee"]), FEE_RATE * analysis["estimated_vsize"])
        assert_greater_than_or_equal(analysis["charge_bound"], analysis["charge"])

        self.log.info("The field survives processing, and the transaction is accepted")
        processed = self.wallet.walletprocesspsbt(funded["psbt"], finalize=False)
        assert all("confirmation_height" in psbt_input for psbt_input in node.decodepsbt(processed["psbt"])["inputs"])
        final = node.finalizepsbt(processed["psbt"])
        assert final["complete"]
        txid = node.sendrawtransaction(final["hex"])
        assert_equal(self.entry(txid)[0], to_sat(funded["fee"]))

        self.log.info("utxoupdatepsbt records the height from the UTXO set, and not for an unconfirmed output")
        coin = self.coinbase_coin()
        child_vout = next(vout["n"] for vout in node.getrawtransaction(txid, True)["vout"] if vout["value"] == 2)
        created = node.createpsbt([{"txid": coin["txid"], "vout": coin["vout"]}, {"txid": txid, "vout": child_vout}], [{self.wallet.getnewaddress(): 51}])
        assert all("confirmation_height" not in psbt_input for psbt_input in node.decodepsbt(created)["inputs"])
        updated = node.decodepsbt(node.utxoupdatepsbt(created))["inputs"]
        assert_equal(updated[0]["confirmation_height"], node.getblockcount() - node.gettxout(coin["txid"], coin["vout"])["confirmations"] + 1)
        assert "confirmation_height" not in updated[1]

        self.log.info("An input with no confirmation height is taken to spend an unconfirmed output, which owes nothing")
        analysis = node.analyzepsbt(self.wallet.walletprocesspsbt(created, sign=False)["psbt"])
        assert_equal(to_sat(analysis["charge"]), self.charge_of(coin["txid"], coin["vout"]))
        assert_greater_than(analysis["charge_bound"], analysis["charge"])
        # Without the outputs that the inputs spend, there is no fee to split.
        assert "fee" not in node.analyzepsbt(created) and "charge" not in node.analyzepsbt(created)
        self.mine()

    def test_fee_estimation(self):
        node = self.nodes[0]
        self.log.info("Fee estimates are net feerates")
        # Each transaction pays a net feerate of FEE_RATE and a charge of many
        # times that. An estimate from fees would be far above FEE_RATE.
        for _ in range(12):
            for _ in range(3):
                coin = self.coinbase_coin()
                tx_hex, charge = self.raw_spend(coin, net_fee=FEE_RATE * 200)
                assert_greater_than(charge, 100 * FEE_RATE * 200)
                node.sendrawtransaction(tx_hex)
            self.mine()
        # FEE_RATE * 200 satoshis on about 110 vB is some 18 sat/vB. The
        # estimate from confirmed transactions is the feerate of their bucket.
        estimate = node.estimaterawfee(2)["short"]
        assert "errors" not in estimate, estimate
        assert_greater_than(estimate["feerate"], Decimal("0.00015"))
        assert_greater_than(Decimal("0.00025"), estimate["feerate"])
        assert_greater_than(Decimal("0.00025"), node.estimatesmartfee(2)["feerate"])

    def test_compact_block_reconstruction(self):
        node = self.nodes[0]
        self.log.info("A node builds the claim transaction of a compact block that lacks it")
        # Claim transactions begin once the first contribution has matured.
        while "claim" not in self.template_summary():
            self.mine()
        coin = self.coinbase_coin()
        tx_hex, charge = self.raw_spend(coin, net_fee=5_000)
        txid = node.sendrawtransaction(tx_hex)
        # A template is kept for a few seconds after the mempool changes.
        self.wait_until(lambda: len(node.getblocktemplate(DECLARED)["transactions"]) == 2)
        template = node.getblocktemplate(DECLARED)
        assert_equal(template["demurrage_contribution"], charge)
        claim = tx_from_hex(template["transactions"][0]["data"])
        assert_equal([vout.scriptPubKey for vout in claim.vout], [POOL_SCRIPT])
        assert_equal([tx["txid"] for tx in template["transactions"][1:]], [txid])

        coinbase = create_coinbase(template["height"])
        coinbase.vout[0].nValue = template["coinbasevalue"]
        coinbase.vout.append(CTxOut(template["demurrage_contribution"], POOL_SCRIPT))
        block = create_block(coinbase=coinbase, tmpl=template, txlist=[tx["data"] for tx in template["transactions"]])
        add_witness_commitment(block)
        block.solve()

        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
        # The peer announces the block, and the node asks for it as a compact block.
        peer.send_without_ping(msg_headers([block]))
        peer.wait_for_getdata([block.hash_int])
        compact = HeaderAndShortIDs()
        # Only the coinbase is prefilled, as by a node that does not implement BIP 462b.
        compact.initialize_from_block(block, prefill_list=[0], use_witness=True)
        assert_equal(len(compact.shortids), 2)
        peer.send_and_ping(msg_cmpctblock(compact.to_p2p()))
        self.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
        with p2p_lock:
            assert "getblocktxn" not in peer.last_message
        assert_equal(node.getblock(block.hash_hex)["tx"][1], claim.txid_hex)

    def template_summary(self):
        template = self.nodes[0].getblocktemplate(DECLARED)
        if template["transactions"] and tx_from_hex(template["transactions"][0]["data"]).vout[0].scriptPubKey == POOL_SCRIPT:
            return {"claim": template["transactions"][0]}
        return {}


if __name__ == '__main__':
    DemurrageInterfacesTest(__file__).main()
