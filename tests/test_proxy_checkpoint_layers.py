"""Tests for computing the seven defense layer results."""

import unittest

from proxy.checkpoint import (
    BLOCK,
    FLAG,
    LAYER_ASTRA,
    LAYER_DRISHTI,
    LAYER_DWAAR,
    LAYER_IDS,
    LAYER_MARYADA,
    LAYER_PEHCHAAN,
    LAYER_SANKALP,
    LAYER_SMRITI,
    PASS,
    decide,
    layers,
)
from proxy.models import ALLOW, DENY, HOLD, DecisionSignals, LayerResult, ToolRequest
from proxy.policy import POLICY_V1


class TestCheckpointLayers(unittest.TestCase):
    """Test computation and validation of the seven Chakravyuh defense layers."""

    def setUp(self) -> None:
        self.policy = POLICY_V1
        self.summary_req = ToolRequest("req-1", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "s1")
        self.signals_low = DecisionSignals(False, False, "low", 0.05, "ALLOW", "Low risk")
        self.signals_high = DecisionSignals(False, False, "high", 0.85, "DENY", "High risk")
        self.signals_inject = DecisionSignals(True, False, "low", 0.9, "DENY", "Injection")

    def test_layer_constants_and_order(self) -> None:
        expected = ["DWAAR", "PEHCHAAN", "SMRITI", "SANKALP", "ASTRA", "MARYADA", "DRISHTI"]
        self.assertEqual(list(LAYER_IDS), expected)
        self.assertEqual((LAYER_DWAAR, LAYER_PEHCHAAN, LAYER_SMRITI, LAYER_SANKALP, LAYER_ASTRA, LAYER_MARYADA, LAYER_DRISHTI), tuple(expected))
        self.assertEqual((PASS, FLAG, BLOCK), ("PASS", "FLAG", "BLOCK"))

    def test_layers_all_seven_for_allow(self) -> None:
        dec = decide(self.summary_req, self.signals_low, policy=self.policy)
        self.assertEqual(dec.decision, ALLOW)

        res = layers(self.summary_req, self.signals_low, dec, self.policy)
        self.assertEqual(len(res), 7)
        self.assertEqual([l.layer_id for l in res], list(LAYER_IDS))

        for item in res:
            self.assertIsInstance(item, LayerResult)
            self.assertEqual(item.status, PASS)
            self.assertEqual(item.evidence_id, dec.evidence_id)
            self.assertTrue(len(item.reason) > 0)

    def test_layers_for_deny(self) -> None:
        # R1: Unallowed tool denies at DWAAR
        r1_req = ToolRequest("r1", "export_records", {"q": "all"}, "Export", "s1")
        dec_r1 = decide(r1_req, self.signals_low, policy=self.policy)
        self.assertEqual(dec_r1.decision, DENY)
        res_r1 = layers(r1_req, self.signals_low, dec_r1, self.policy)
        dwaar = next(l for l in res_r1 if l.layer_id == LAYER_DWAAR)
        self.assertEqual(dwaar.status, BLOCK)
        self.assertEqual(dwaar.evidence_id, dec_r1.evidence_id)

        # R2: External destination denies at MARYADA
        r2_req = ToolRequest("r2", "send_email", {"recipient": "attacker@evil.com"}, "Send", "s1")
        dec_r2 = decide(r2_req, self.signals_high, policy=self.policy)
        self.assertEqual(dec_r2.decision, DENY)
        res_r2 = layers(r2_req, self.signals_high, dec_r2, self.policy)
        maryada = next(l for l in res_r2 if l.layer_id == LAYER_MARYADA)
        self.assertEqual(maryada.status, BLOCK)

        # R3: High-impact + injection denies at DRISHTI
        r3_req = ToolRequest("r3", "send_email", {"recipient": "dean@example.edu"}, "Send", "s1")
        dec_r3 = decide(r3_req, self.signals_inject, policy=self.policy)
        self.assertEqual(dec_r3.decision, DENY)
        res_r3 = layers(r3_req, self.signals_inject, dec_r3, self.policy)
        drishti = next(l for l in res_r3 if l.layer_id == LAYER_DRISHTI)
        self.assertEqual(drishti.status, BLOCK)

    def test_layers_for_hold(self) -> None:
        # R4: Signals is None flags SMRITI without any BLOCK
        r4_req = ToolRequest("r4", "send_email", {"recipient": "dean@example.edu"}, "Send", "s1")
        dec_r4 = decide(r4_req, None, policy=self.policy)
        self.assertEqual(dec_r4.decision, HOLD)
        res_r4 = layers(r4_req, None, dec_r4, self.policy)
        self.assertTrue(all(l.status != BLOCK for l in res_r4))
        smriti = next(l for l in res_r4 if l.layer_id == LAYER_SMRITI)
        self.assertEqual(smriti.status, FLAG)

        # R5: Approval required flags PEHCHAAN without any BLOCK
        r5_req = ToolRequest("r5", "transfer_records", {"destination": "dean@example.edu"}, "Transfer", "s1")
        dec_r5 = decide(r5_req, self.signals_low, policy=self.policy)
        self.assertEqual(dec_r5.decision, HOLD)
        res_r5 = layers(r5_req, self.signals_low, dec_r5, self.policy)
        self.assertTrue(all(l.status != BLOCK for l in res_r5))
        pehchaan = next(l for l in res_r5 if l.layer_id == LAYER_PEHCHAAN)
        self.assertEqual(pehchaan.status, FLAG)


if __name__ == "__main__":
    unittest.main()
