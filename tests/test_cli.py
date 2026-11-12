"""End-to-end CLI behaviour on the bundled sample project."""

from __future__ import annotations
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from taint_scanner.cli import main


class CliTests(unittest.TestCase):
    def test_scan_writes_json_report(self) -> None:
        output = os.path.join(ROOT, ".test_tmp", "cli_report.json")
        cache = os.path.join(ROOT, ".test_tmp", "cli_cache")
        os.makedirs(os.path.dirname(output), exist_ok=True)
        code = main([
            "scan", os.path.join(ROOT, "samples"),
            "-o", output, "--cache-dir", cache, "--no-cache",
        ])
        self.assertEqual(code, 0)
        with open(output, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["summary"]["finding_count"], 9)
        self.assertGreaterEqual(report["summary"]["unsupported_count"], 1)
        self.assertIn("routes", report)
        for finding in report["findings"]:
            self.assertIn(finding["kind"],
                          ("sql_injection", "command_injection"))
            self.assertTrue(finding["flow"])


if __name__ == "__main__":
    unittest.main()
