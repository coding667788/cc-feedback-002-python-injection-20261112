"""Persistent cache: reuse, invalidation and crash recovery."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TEST_TMP_ROOT = os.path.join(ROOT, ".test_tmp")


def _fresh_dir(path: str) -> str:
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)
    return path

from taint_scanner.scanner import Scanner

from tests._util import report_signature


APP_MAIN = '''
from .helpers import build_query


def get():
    def decorator(func):
        return func
    return decorator


@get()
def entry_route(keyword: str):
    connection = None
    return build_query(connection, keyword)
'''

HELPERS_VULN = '''
def build_query(connection, keyword):
    sql = "SELECT * FROM t WHERE name = '" + keyword + "'"
    return connection.execute(sql)
'''

HELPERS_SAFE = '''
def build_query(connection, keyword):
    return connection.execute("SELECT * FROM t WHERE name = ?", (keyword,))
'''

UNRELATED = '''
def standalone(value):
    return value + "x"
'''


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = _fresh_dir(os.path.join(TEST_TMP_ROOT, "cache_case"))
        self.project = os.path.join(self.tmp, "mini")
        self.pkg = os.path.join(self.project, "pkg")
        os.makedirs(self.pkg)
        self._write("pkg/__init__.py", "")
        self._write("pkg/main.py", APP_MAIN)
        self._write("pkg/helpers.py", HELPERS_VULN)
        self._write("pkg/unrelated.py", UNRELATED)
        self.cache_dir = os.path.join(self.tmp, "cache")
        self.report = os.path.join(self.tmp, "report.json")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, content: str) -> None:
        with open(os.path.join(self.project, rel), "w", encoding="utf-8") as handle:
            handle.write(content)

    def _run(self, use_cache: bool) -> dict:
        scanner = Scanner(self.project, cache_dir=self.cache_dir)
        try:
            result = scanner.scan(use_cache=use_cache)
            from taint_scanner.report import write_report
            write_report(result, scanner.root, self.report)
            return {
                "reused": result.reused_summaries,
                "recomputed": result.recomputed_summaries,
                "hit_files": result.cache_hit_files,
            }
        finally:
            scanner.close()

    def test_full_then_cached_are_identical(self) -> None:
        first = self._run(False)
        sig_first = report_signature(self.report)
        second = self._run(True)
        sig_second = report_signature(self.report)
        self.assertEqual(sig_first, sig_second)
        self.assertGreater(second["reused"], 0)
        self.assertEqual(second["recomputed"], 0)

    def test_change_public_function_invalidates_callers(self) -> None:
        self._run(False)
        sig_vuln = report_signature(self.report)
        self.assertEqual(len(sig_vuln["findings"]), 1)

        # Modify the public helper: vulnerable concatenation -> bound parameter.
        self._write("pkg/helpers.py", HELPERS_SAFE)
        stats = self._run(True)
        sig_safe = report_signature(self.report)
        self.assertEqual(len(sig_safe["findings"]), 0)
        # The helper and its caller are recomputed; unrelated module is reused.
        self.assertGreaterEqual(stats["recomputed"], 2)

        # Restore the helper and confirm the vulnerability returns identically.
        self._write("pkg/helpers.py", HELPERS_VULN)
        self._run(True)
        self.assertEqual(report_signature(self.report), sig_vuln)

    def test_delete_function_is_handled_not_cached_stale(self) -> None:
        self._run(False)
        # Remove the helper module entirely; the report must not crash and
        # must not keep stale findings from the deleted function.
        os.remove(os.path.join(self.pkg, "helpers.py"))
        self._run(True)
        sig = report_signature(self.report)
        self.assertEqual(
            [f for f in sig["findings"] if "build_query" in f[1]], []
        )


class CrashRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = _fresh_dir(os.path.join(TEST_TMP_ROOT, "crash_case"))
        self.project = os.path.join(self.tmp, "mini")
        self.pkg = os.path.join(self.project, "pkg")
        os.makedirs(self.pkg)
        with open(os.path.join(self.pkg, "__init__.py"), "w", encoding="utf-8"):
            pass
        with open(os.path.join(self.pkg, "main.py"), "w", encoding="utf-8") as h:
            h.write(APP_MAIN)
        with open(os.path.join(self.pkg, "helpers.py"), "w", encoding="utf-8") as h:
            h.write(HELPERS_VULN)
        self.cache_dir = os.path.join(self.tmp, "cache")
        self.report = os.path.join(self.tmp, "report.json")
        self.env = dict(os.environ)
        self.env["PYTHONPATH"] = ROOT

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _invoke(self, fault: str | None) -> subprocess.CompletedProcess:
        env = dict(self.env)
        if fault:
            env["TAINT_SCANNER_FAULT"] = fault
        cmd = [
            sys.executable, "-m", "taint_scanner", "scan", self.project,
            "--cache-dir", self.cache_dir, "-o", self.report,
        ]
        return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                              text=True)

    def test_interrupted_write_then_restart_matches_full_scan(self) -> None:
        clean = subprocess.run(
            [sys.executable, "-m", "taint_scanner", "scan", self.project,
             "--cache-dir", os.path.join(self.tmp, "clean_cache"),
             "-o", os.path.join(self.tmp, "clean.json")],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(clean.returncode, 0, clean.stderr)
        expected = report_signature(os.path.join(self.tmp, "clean.json"))

        for fault in ("after_file_facts", "after_summaries", "before_commit"):
            crashed = self._invoke(fault)
            self.assertEqual(crashed.returncode, 7, crashed.stderr)
            restarted = self._invoke(None)
            self.assertEqual(restarted.returncode, 0, restarted.stderr)
            self.assertEqual(report_signature(self.report), expected)


if __name__ == "__main__":
    unittest.main()
