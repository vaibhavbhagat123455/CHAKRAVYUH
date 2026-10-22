"""Tests for proxy configuration module."""

import unittest

from proxy.config import ProxyConfig


class TestProxyConfig(unittest.TestCase):
    """Verify ProxyConfig defaults, environment parsing, and validation."""

    def test_defaults(self) -> None:
        cfg = ProxyConfig()
        self.assertEqual(cfg.tool_timeout_seconds, 5.0)
        self.assertEqual(cfg.hold_ttl_seconds, 120)
        self.assertIsNone(cfg.policy_file)
        self.assertIsNone(cfg.log_target)
        self.assertIsNone(cfg.analyser_target)
        self.assertIsNone(cfg.approval_create_target)
        self.assertIsNone(cfg.approval_verify_target)

    def test_from_env_defaults(self) -> None:
        cfg = ProxyConfig.from_env({})
        self.assertEqual(cfg.tool_timeout_seconds, 5.0)
        self.assertEqual(cfg.hold_ttl_seconds, 120)
        self.assertIsNone(cfg.policy_file)
        self.assertIsNone(cfg.log_target)
        self.assertIsNone(cfg.analyser_target)
        self.assertIsNone(cfg.approval_create_target)
        self.assertIsNone(cfg.approval_verify_target)

    def test_from_env_custom_values(self) -> None:
        env = {
            "CHAKRAVYUH_TOOL_TIMEOUT": "2.5",
            "CHAKRAVYUH_HOLD_TTL": "60",
            "CHAKRAVYUH_POLICY_FILE": "/path/to/custom_policy.json",
            "CHAKRAVYUH_LOG": "pkg.log:append_event",
            "CHAKRAVYUH_ANALYSER": "pkg.ai:analyse",
            "CHAKRAVYUH_APPROVAL_CREATE": "pkg.appr:create",
            "CHAKRAVYUH_APPROVAL_VERIFY": "pkg.appr:verify",
        }
        cfg = ProxyConfig.from_env(env)
        self.assertEqual(cfg.tool_timeout_seconds, 2.5)
        self.assertEqual(cfg.hold_ttl_seconds, 60)
        self.assertEqual(cfg.policy_file, "/path/to/custom_policy.json")
        self.assertEqual(cfg.log_target, "pkg.log:append_event")
        self.assertEqual(cfg.analyser_target, "pkg.ai:analyse")
        self.assertEqual(cfg.approval_create_target, "pkg.appr:create")
        self.assertEqual(cfg.approval_verify_target, "pkg.appr:verify")

    def test_non_positive_values_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            ProxyConfig(tool_timeout_seconds=0)

        with self.assertRaises(ValueError):
            ProxyConfig(tool_timeout_seconds=-1.0)

        with self.assertRaises(ValueError):
            ProxyConfig(hold_ttl_seconds=0)

        with self.assertRaises(ValueError):
            ProxyConfig(hold_ttl_seconds=-5)

    def test_invalid_env_types_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            ProxyConfig.from_env({"CHAKRAVYUH_TOOL_TIMEOUT": "not-a-number"})

        with self.assertRaises(ValueError):
            ProxyConfig.from_env({"CHAKRAVYUH_HOLD_TTL": "not-a-number"})

    def test_is_frozen(self) -> None:
        cfg = ProxyConfig()
        with self.assertRaises(Exception):
            cfg.tool_timeout_seconds = 10.0  # type: ignore


if __name__ == "__main__":
    unittest.main()
