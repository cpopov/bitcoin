#!/usr/bin/env python3
"""Experiment: BIP 462 reference heights vs TRUC (BIP 431) zero-fee commitments.

Builds a Lightning-style zero-fee commitment package after activation: a
parent with fee 0 and a 0-value P2A anchor (ephemeral dust), and a CPFP child
spending the anchor plus a wallet coin. Reports, for each way of carrying the
reference height, whether the node accepts the package. Also checks a legacy
transaction signed before activation.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../test/functional"))

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut  # noqa: E402
from test_framework.script_util import PAY_TO_ANCHOR  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402
from test_framework.wallet import MiniWallet  # noqa: E402

ACTIVATION_HEIGHT = 432
RESULTS = os.environ.get("TRUC_RESULTS", "/dev/stdout")


class TrucExperiment(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=demurrage@{ACTIVATION_HEIGHT}"]]

    def report(self, scenario, outcome):
        self.log.info(f"{scenario}: {outcome}")
        with open(RESULTS, "a") as f:
            f.write(f"{scenario}: {outcome}\n")

    def commitment_package(self, version, ref_height, parent_ref_height=None, parent=None):
        """Zero-fee parent with a P2A anchor, and a child paying for both."""
        node = self.nodes[0]
        if parent is None:
            utxo = self.wallet.get_utxo(confirmed_only=True)
            parent = CTransaction()
            parent.version = version
            parent.ref_height = parent_ref_height
            parent.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
            value = self.wallet.demurrage_effective_value(utxo, parent_ref_height) if parent_ref_height is not None else int(utxo["value"] * 10**8)
            parent.vout = [CTxOut(value, self.wallet.get_output_script()), CTxOut(0, PAY_TO_ANCHOR)]
            self.wallet.sign_tx(parent)
        sponsor = self.wallet.get_utxo(confirmed_only=True)
        child = CTransaction()
        child.version = version
        child.ref_height = ref_height
        child.vin = [CTxIn(COutPoint(parent.txid_int, 1)), CTxIn(COutPoint(int(sponsor["txid"], 16), sponsor["vout"]))]
        sponsor_value = self.wallet.demurrage_effective_value(sponsor, ref_height) if ref_height is not None else int(sponsor["value"] * 10**8)
        child.vout = [CTxOut(sponsor_value - 50_000, self.wallet.get_output_script())]
        self.wallet.sign_tx(child)
        child.wit.vtxinwit[0] = CTxInWitness()  # P2A is spent with an empty witness
        return parent, child

    def submit(self, scenario, parent, child):
        node = self.nodes[0]
        try:
            res = node.submitpackage([parent.serialize().hex(), child.serialize().hex()])
        except Exception as e:  # noqa: BLE001
            self.report(scenario, f"RPC error {e}")
            return False
        if res["package_msg"] == "success":
            self.report(scenario, "accepted")
            return True
        errors = {r.get("error") for r in res["tx-results"].values() if r.get("error")}
        self.report(scenario, f"rejected: {res['package_msg']} {sorted(errors)}")
        return False

    def pin_attempt(self, scenario, version, ref):
        """Pinning: instead of the honest CPFP, a counterparty sweeps the anchor
        with a 5 kvB child at a low feerate. Replacing it then costs more than
        its whole absolute fee. TRUC limits a child of an unconfirmed TRUC
        parent to 1,000 vB; other versions only have the default package limits."""
        parent, child = self.commitment_package(version, ref, parent_ref_height=ref)
        child.vout[0].nValue += 50_000 - 8_000  # 8,000 sat for ~5 kvB: ~1.6 sat/vB
        self.wallet._bulk_tx(child, 5_000)
        self.wallet.sign_tx(child)
        child.wit.vtxinwit[0] = CTxInWitness()
        self.submit(f"  ... 5 kvB low-feerate pinning child, {scenario}", parent, child)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, ACTIVATION_HEIGHT - 20)

        # A legacy transaction pre-signed before activation, with a 1,000 sat fee.
        utxo = self.wallet.get_utxo(confirmed_only=True)
        presigned = self.wallet.create_self_transfer(utxo_to_spend=utxo, fee=__import__("decimal").Decimal("0.00001"))
        self.generate(self.wallet, ACTIVATION_HEIGHT + 3 - node.getblockcount())
        assert_equal(node.getblockcount(), ACTIVATION_HEIGHT + 3)
        info = node.getdemurrageinfo()
        self.report("context", f"tip {info['height']}, rate {info['rate']} per 1e18 per block, index {info['index']}")
        try:
            node.sendrawtransaction(presigned["hex"])
            self.report("pre-activation pre-signed legacy tx, relay", "accepted")
        except Exception as e:  # noqa: BLE001
            self.report("pre-activation pre-signed legacy tx, relay", f"rejected: {e}")
        try:
            self.generateblock(node, self.wallet.get_address(), [presigned["hex"]])
            self.report("pre-activation pre-signed legacy tx, mined directly", "valid")
        except Exception as e:  # noqa: BLE001
            self.report("pre-activation pre-signed legacy tx, mined directly", f"invalid: {e}")
            self.wallet.rescan_utxos()

        tip = node.getblockcount()
        for scenario, version, ref in (
            ("v3 TRUC, no ref_height (legacy valuation)", 3, None),
            ("v4 with ref_height (BIP 462 0.4.0)", 4, tip),
            ("v3 TRUC with ref_height (decoupled)", 3, tip),
        ):
            parent, child = self.commitment_package(version, ref, parent_ref_height=ref)
            if self.submit(scenario, parent, child):
                self.wallet.rescan_utxos()
                self.pin_attempt(scenario, version, ref)
            self.wallet.rescan_utxos()

        # Pre-signed commitment: parent signed now, broadcast 30 blocks later with a fresh child.
        tip = node.getblockcount()
        parent, _ = self.commitment_package(3, tip, parent_ref_height=tip)
        self.generate(self.wallet, 30)
        self.wallet.rescan_utxos()
        # The parent is not broadcast yet: keep its input out of the child's reach.
        self.wallet.get_utxo(txid=f"{parent.vin[0].prevout.hash:064x}", vout=parent.vin[0].prevout.n)
        _, child = self.commitment_package(3, node.getblockcount(), parent=parent)
        if self.submit("v3 TRUC with ref_height, broadcast 30 blocks after signing", parent, child):
            self.generate(self.wallet, 1)
            self.report("  ... mined", str(node.getmempoolinfo()["size"] == 0))


if __name__ == "__main__":
    TrucExperiment(__file__).main()
