"""Zero-dependency validation command for the Member 3 module."""

import sys
import unittest


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_complete_validation")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
