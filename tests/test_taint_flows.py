"""Cross-module propagation, field isolation and branch/sanitiser behaviour."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from taint_scanner.modulegraph import Project
from taint_scanner.scanner import Scanner

from tests._util import report_signature
from taint_scanner.analysis import TaintEngine


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


def scan(tmp_dir: str, use_cache: bool) -> dict:
    scanner = Scanner(SAMPLES, cache_dir=tmp_dir)
    try:
        result = scanner.scan(use_cache=use_cache)
        return {
            "findings": result.findings,
            "unsupported": result.unsupported,
            "routes": result.routes,
        }
    finally:
        scanner.close()


class TaintFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = scan(os.path.join(ROOT, ".test_cache_flows"), False)

    def _sources(self, kind: str | None = None) -> dict[str, list[tuple]]:
        grouped: dict[str, list[tuple]] = {}
        for finding in self.result["findings"]:
            if kind and finding.kind != kind:
                continue
            grouped.setdefault(finding.source.split("::")[-1], []).append(
                (finding.kind, finding.file, finding.lineno)
            )
        return grouped

    def test_expected_vulnerable_routes(self) -> None:
        sources = self._sources()
        expected = {
            "unsafe_sql_route",
            "failover_integer_route",
            "field_isolation_route",
            "object_field_route",
            "alias_route",
            "same_helper_mixed_route",
            "command_unsafe_route",
            "branch_route",
            "deep_chain_route",
        }
        self.assertEqual(set(sources), expected)

    def test_safe_routes_have_no_finding(self) -> None:
        sources = set(self._sources())
        for safe in ("safe_sql_route", "safe_integer_route", "command_safe_route"):
            self.assertNotIn(safe, sources)

    def test_three_layer_chain_evidence(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("deep_chain_route")
        )
        calls = [step for step in finding.flow if step.kind == "call"]
        self.assertGreaterEqual(len(calls), 4)
        self.assertIn("three_layer_entry", calls[0].detail)
        self.assertIn("stage_one", calls[1].detail)
        self.assertIn("stage_two", calls[2].detail)
        self.assertIn("stage_three", calls[3].detail)
        self.assertEqual(finding.file.replace("\\", "/"),
                         "app/services/pipeline.py")
        self.assertEqual(finding.lineno, 16)

    def test_relative_import_and_alias(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("alias_route")
        )
        self.assertEqual(finding.kind, "sql_injection")
        self.assertEqual(finding.file.replace("\\", "/"), "app/database.py")

    def test_dict_field_isolation(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("field_isolation_route")
        )
        roots = {term.root.split("::")[-1] for term in finding.taint_terms}
        self.assertEqual(roots, {"name"})
        self.assertEqual(finding.lineno, 42)

    def test_object_field_isolation(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("object_field_route")
        )
        roots = {term.root.split("::")[-1] for term in finding.taint_terms}
        self.assertEqual(roots, {"account_id"})
        self.assertNotIn("display_name", roots)

    def test_mutually_exclusive_branches_not_merged(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("branch_route")
        )
        branches = [step for step in finding.flow if step.kind == "branch"]
        self.assertEqual(len(branches), 1)
        self.assertIn("taken", branches[0].detail)
        self.assertNotIn("else", branches[0].detail)

    def test_sanitiser_failure_branch_reports_raw_string(self) -> None:
        finding = next(
            f for f in self.result["findings"]
            if f.source.endswith("failover_integer_route")
        )
        self.assertEqual(finding.lineno, 37)
        branches = [step for step in finding.flow if step.kind == "branch"]
        self.assertTrue(
            any("exception" in step.detail for step in branches)
        )

    def test_successful_int_conversion_is_clean(self) -> None:
        sources = set(self._sources())
        self.assertNotIn("safe_integer_route", sources)

    def test_unsupported_constructs_are_reported(self) -> None:
        reasons = {(u.file, u.lineno, u.reason) for u in self.result["unsupported"]}
        self.assertTrue(
            any("loops" in reason for _, _, reason in reasons)
        )

    def test_symbol_level_dict_fields_do_not_leak(self) -> None:
        import shutil
        target = os.path.join(ROOT, ".test_tmp", "symbol_iso")
        shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target)
        source = (
            "def g(conn, payload):\n"
            "    conn.execute('SELECT * FROM a WHERE k = ?', (payload['clean'],))\n"
            "    conn.execute(\"SELECT * FROM a WHERE n = '\" + payload['dirty'] + \"'\")\n"
        )
        with open(os.path.join(target, "m.py"), "w", encoding="utf-8") as handle:
            handle.write(source)
        project = Project(target)
        project.load()
        engine = TaintEngine(project)
        summary = engine.get_summary("m", "g")
        self.assertEqual(len(summary.findings), 1)
        finding = summary.findings[0]
        self.assertTrue(
            all(term.path == ("dirty",) for term in finding.taint_terms)
        )


if __name__ == "__main__":
    unittest.main()
