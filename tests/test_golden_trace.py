"""The committed golden trace is a known-good schema v2 reference.

A fresh clone can validate it to confirm the toolchain agrees on a trace we
know is valid -- before investing hours in a full Chromium build. This is the
deterministic counterpart to a real capture (which is large and non-repeatable);
see docs/reproduce.md for capturing and validating a real trace.
"""
import unittest
from pathlib import Path

from scripts.validate_trace import validate_trace

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "golden-schema-v2.ndjson"


class GoldenTraceTests(unittest.TestCase):
    def test_golden_schema_v2_trace_validates(self):
        # exactly the command documented in docs/reproduce.md; raises on failure
        validate_trace(GOLDEN, expected=["TextEncoder.encode"], schema_version=2)


if __name__ == "__main__":
    unittest.main()
