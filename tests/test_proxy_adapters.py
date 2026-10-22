"""Tests for dotted-path callable loader and adapter error handling."""

import sys
import unittest

import pytest

from proxy.adapters.loader import AdapterError, load_callable


class TestCallableLoader(unittest.TestCase):
    """Test dynamic dotted-path callable loading and error cases."""

    def test_malformed_paths_raise_adapter_error(self) -> None:
        malformed_cases = [
            "",
            "   ",
            "no_colon_path",
            ":function_only",
            "module_only:",
            "too:many:colons",
        ]
        for path in malformed_cases:
            with self.subTest(path=path):
                with self.assertRaises(AdapterError) as ctx:
                    load_callable(path)
                self.assertIn("malformed", str(ctx.exception).lower())

    def test_missing_module_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("nonexistent_package_123.foo:bar")
        self.assertIn("not found", str(ctx.exception).lower())
        self.assertIn("nonexistent_package_123.foo", str(ctx.exception))

    def test_missing_attribute_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("math:nonexistent_function_xyz")
        self.assertIn("not found in module", str(ctx.exception).lower())

    def test_non_callable_attribute_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("math:pi")
        self.assertIn("not callable", str(ctx.exception).lower())

    def test_valid_builtin_callable_loads(self) -> None:
        func = load_callable("math:floor")
        self.assertTrue(callable(func))
        self.assertEqual(func(3.7), 3)


def test_custom_module_loaded_from_tmp_path(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test loading a callable from a fake module written to tmp_path."""
    mod_dir = tmp_path / "fake_pkg"
    mod_dir.mkdir()
    (mod_dir / "__init__.py").write_text("", encoding="utf-8")
    (mod_dir / "worker.py").write_text("def do_work(x):\n    return x * 2\n", encoding="utf-8")

    monkeypatch.syspath_prepend(str(tmp_path))
    loaded = load_callable("fake_pkg.worker:do_work")
    assert callable(loaded)
    assert loaded(21) == 42


if __name__ == "__main__":
    unittest.main()
