"""Tests for proxy canonical hashing helpers."""

import unittest

from core.contracts import canonical_json as core_canonical_json
from proxy.canonical import (
    action_digest,
    canonical_json,
    request_fingerprint,
    sha256_hex,
)
from proxy.models import ToolRequest


class TestProxyCanonical(unittest.TestCase):
    """Verify deterministic canonical serialization and hashing."""

    def test_reexports_core_canonical_json(self) -> None:
        self.assertIs(canonical_json, core_canonical_json)

    def test_sha256_hex(self) -> None:
        self.assertEqual(
            sha256_hex("test"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )

    def test_key_order_and_whitespace_do_not_change_hash(self) -> None:
        dict_a = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
        dict_b = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
        hash_a = sha256_hex(canonical_json(dict_a))
        hash_b = sha256_hex(canonical_json(dict_b))
        self.assertEqual(hash_a, hash_b)

    def test_request_fingerprint_changes_when_arguments_change(self) -> None:
        req1 = ToolRequest(
            request_id="req-1",
            tool="send_email",
            arguments={"to": "user1@example.com"},
            purpose="send report",
            scenario_id="sc-1",
        )
        req2 = ToolRequest(
            request_id="req-1",
            tool="send_email",
            arguments={"to": "user2@example.com"},  # Changed argument
            purpose="send report",
            scenario_id="sc-1",
        )
        fp1 = request_fingerprint(req1)
        fp2 = request_fingerprint(req2)
        self.assertNotEqual(fp1, fp2)

        # Identical request gives identical fingerprint
        self.assertEqual(fp1, request_fingerprint(req1))

    def test_action_digest_ignores_request_metadata(self) -> None:
        tool = "send_email"
        args = {"recipient": "dean@example.edu", "file": "synthetic_report.pdf"}

        d1 = action_digest(tool, args)
        d2 = action_digest(tool, dict(reversed(list(args.items()))))
        self.assertEqual(d1, d2)

        # Changing tool changes digest
        self.assertNotEqual(d1, action_digest("export_records", args))

        # Changing an argument changes digest
        modified_args = dict(args)
        modified_args["file"] = "synthetic_circular.pdf"
        self.assertNotEqual(d1, action_digest(tool, modified_args))


if __name__ == "__main__":
    unittest.main()
