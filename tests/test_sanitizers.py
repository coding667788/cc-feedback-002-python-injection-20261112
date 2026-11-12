"""Direct checks for the int()/str() sanitiser semantics."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from taint_scanner.analysis import Bind, FuncAnalyzer, PathResult, State, TaintEngine
from taint_scanner.models import Term
from taint_scanner.modulegraph import Project


SANITISER_SOURCE = '''
def success(value):
    try:
        number = int(value)
        rendered = str(number)
    except ValueError:
        rendered = value
    return rendered


def always_failover(value):
    try:
        number = int(value)
        rendered = str(number)
    except ValueError:
        rendered = value
    return rendered
'''


class SanitiserTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.dir = os.path.join(ROOT, ".test_tmp", "sanitiser")
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        self.module_path = os.path.join(self.dir, "sanmod.py")
        with open(self.module_path, "w", encoding="utf-8") as handle:
            handle.write(SANITISER_SOURCE)
        self.project = Project(self.dir)
        self.project.load()
        self.engine = TaintEngine(self.project)

    def _run(self, func: str) -> list:
        node = self.project.get_func_node("sanmod", func)
        analyzer = FuncAnalyzer(self.project, self.engine, "sanmod", node)
        state = State()
        state.env["value"] = Bind(terms={Term("sanmod::%s::value" % func)})
        return analyzer.run(state)

    def test_success_path_keeps_safe_int_only(self) -> None:
        paths = self._run("success")
        returned_terms = [
            term
            for path in paths
            for record in path.returns
            for term in record.terms
        ]
        # The success path returns a clean decimal string with no raw taint.
        success_path = next(
            path for path in paths
            if any("completed without exception" in item
                   for item in path.branch_evidence)
        )
        for record in success_path.returns:
            for term in record.terms:
                self.assertTrue(term.safe_int)

    def test_failure_path_keeps_raw_taint(self) -> None:
        paths = self._run("always_failover")
        failure_path = next(
            path for path in paths
            if any("raised an exception" in item
                   for item in path.branch_evidence)
        )
        raw = [
            term
            for record in failure_path.returns
            for term in record.terms
            if not term.safe_int
        ]
        self.assertTrue(raw)

if __name__ == "__main__":
    unittest.main()
