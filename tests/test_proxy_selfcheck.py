"""Tests for python -m proxy.selfcheck smoke command."""

import io
import subprocess
import sys
import unittest


class TestProxySelfcheck(unittest.TestCase):
    """Verify smoke test command checks ALLOW, DENY, DENY, HOLD and exit codes."""

    def test_run_selfcheck_programmatic(self) -> None:
        from proxy.selfcheck import run_selfcheck

        out = io.StringIO()
        code = run_selfcheck(stdout=out)
        self.assertEqual(code, 0)
        output = out.getvalue()
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        self.assertEqual(len(lines), 6)
        for line in lines:
            self.assertTrue(line.startswith("PASS:"), f"Line did not pass: {line}")

    def test_subprocess_smoke_command(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "proxy.selfcheck"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
        self.assertIn("PASS: safe summary", proc.stdout)
        self.assertIn("PASS: malicious send_email", proc.stdout)
        self.assertIn("PASS: unknown tool", proc.stdout)
        self.assertIn("PASS: transfer hold", proc.stdout)
        self.assertIn("PASS: executor ran exactly once", proc.stdout)
        self.assertIn("PASS: every DENY decision includes an evidence_id", proc.stdout)

    def test_run_selfcheck_failure_exit_code(self) -> None:
        from unittest.mock import patch
        import proxy.selfcheck as sc

        broken_cases = list(sc.CASES)
        broken_cases[0] = dict(broken_cases[0], expected_decision="DENY")
        out = io.StringIO()
        with patch.object(sc, "CASES", broken_cases):
            code = sc.run_selfcheck(stdout=out)
        self.assertNotEqual(code, 0)
        self.assertIn("FAIL:", out.getvalue())


if __name__ == "__main__":
    unittest.main()
