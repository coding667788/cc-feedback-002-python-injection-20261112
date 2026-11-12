"""Scan orchestration: fresh full scans, incremental scans and crash recovery."""

from __future__ import annotations

import os
import ast
from dataclasses import dataclass
from typing import Optional

from .analysis import TaintEngine
from .cache import ScanCache
from .models import Finding, UnsupportedItem
from .modulegraph import Project


def _fault_point(name: str) -> None:
    """Controlled crash hook used by the interruption-recovery tests."""
    marker = os.environ.get("TAINT_SCANNER_FAULT")
    if marker and marker == name:
        os._exit(7)


@dataclass
class ScanResult:
    findings: list[Finding]
    unsupported: list[UnsupportedItem]
    routes: list[dict]
    reused_summaries: int
    recomputed_summaries: int
    cache_hit_files: int


class Scanner:
    def __init__(self, root: str, cache_dir: Optional[str] = None):
        self.root = os.path.abspath(root)
        self.cache_dir = cache_dir or os.path.join(self.root, ".taint_cache")
        self.cache = ScanCache(self.cache_dir)

    def close(self) -> None:
        self.cache.close()

    # ------------------------------------------------------------- scanning
    def scan(self, use_cache: bool = True) -> ScanResult:
        project = Project(self.root)
        project.load()
        engine = TaintEngine(project)

        self._sync_file_facts(project)
        stale = self._stale_summary_keys(project) if use_cache else set(
            self.cache.all_summary_bases().keys()
        )
        self.cache.delete_summaries(stale)

        reused, recomputed = self._build_summaries(engine, use_cache)
        _fault_point("after_summaries")

        route_results = []
        all_findings: list[Finding] = []
        all_unsupported: list[UnsupportedItem] = []
        route_entries = self._collect_routes(project)
        for module_name, func_name in route_entries:
            result = engine.analyze_route(module_name, func_name)
            if result is None:
                continue
            route_results.append(
                {
                    "source": result["source_key"],
                    "method": result["summary"].route_method,
                    "params": result["param_names"],
                    "file": project.rel_path(project.modules[module_name].path),
                    "lineno": result["node"].lineno,
                }
            )
            all_findings.extend(result["findings"])
            all_unsupported.extend(result["unsupported"])

        # unsupported constructs inside non-route helpers still matter
        for summary in engine.summaries.values():
            all_unsupported.extend(summary.unsupported)

        all_findings = self._dedupe_findings(all_findings)
        all_unsupported = self._dedupe_unsupported(all_unsupported)
        _fault_point("after_report")
        self._persist_summaries(engine)

        return ScanResult(
            findings=all_findings,
            unsupported=all_unsupported,
            routes=route_results,
            reused_summaries=reused,
            recomputed_summaries=recomputed,
            cache_hit_files=self._cache_hit_files(project),
        )

    # ------------------------------------------------------------ internals
    def _sync_file_facts(self, project: Project) -> None:
        cached_hashes = self.cache.all_file_hashes()
        current = {
            info.rel_path: info.source_hash for info in project.modules.values()
        }
        deleted = set(cached_hashes) - set(current)
        self.cache.delete_file_facts(deleted)
        facts: dict[str, dict] = {}
        for rel_path, source_hash in sorted(current.items()):
            if cached_hashes.get(rel_path) == source_hash:
                continue
            info = project.path_index[rel_path]
            facts[rel_path] = {
                "module_name": info.name,
                "source_hash": source_hash,
                "imports": {
                    name: binding.to_dict() for name, binding in info.imports.items()
                },
                "defs": [
                    {"name": d.name, "kind": d.kind, "lineno": d.lineno}
                    for d in info.defs.values()
                ],
            }
        _fault_point("after_file_facts")
        self.cache.put_file_facts(facts)

    def _cache_hit_files(self, project: Project) -> int:
        cached = self.cache.all_file_hashes()
        return sum(
            1
            for info in project.modules.values()
            if cached.get(info.rel_path) == info.source_hash
        )

    def _stale_summary_keys(self, project: Project) -> set[str]:
        cached_bases = self.cache.all_summary_bases()
        engine = TaintEngine(project)
        current_keys = set()
        changed_modules = {
            info.name
            for info in project.modules.values()
            if self.cache.all_file_hashes().get(info.rel_path) != info.source_hash
        }
        for module_name, info in project.modules.items():
            for node in info.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    current_keys.add(engine._summary_key(module_name, node.name, None))
            for class_name, methods in info.classes.items():
                for method in methods:
                    current_keys.add(
                        engine._summary_key(module_name, method, class_name)
                    )
        stale = set(cached_bases) - current_keys  # deleted functions / modules
        for key in cached_bases:
            module_name = key.split("::", 1)[0]
            if module_name in changed_modules:
                stale.add(key)
        return stale

    def _build_summaries(self, engine: TaintEngine, use_cache: bool) -> tuple[int, int]:
        reused = 0
        recomputed = 0
        original_get = engine.get_summary
        cache = self.cache

        def cached_get(module_name: str, func_name: str, class_name=None):
            key = engine._summary_key(module_name, func_name, class_name)
            if key in engine.summaries:
                return engine.summaries[key]
            if use_cache:
                provisional = original_get(module_name, func_name, class_name)
                if provisional is None:
                    return None
                stored = cache.get_summary(key, provisional.basis)
                if stored is not None:
                    engine.summaries[key] = stored
                    nonlocal reused
                    reused += 1
                    return stored
            summary = original_get(module_name, func_name, class_name)
            if summary is not None:
                nonlocal recomputed
                recomputed += 1
            return summary

        engine.get_summary = cached_get  # type: ignore[method-assign]
        engine.analyze_all()
        engine.get_summary = original_get  # type: ignore[method-assign]
        return reused, recomputed

    def _persist_summaries(self, engine: TaintEngine) -> None:
        _fault_point("before_commit")
        self.cache.put_summaries(engine.summaries)

    def _collect_routes(self, project: Project) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        for module_name, info in sorted(project.modules.items()):
            for node in info.tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                is_route, _ = TaintEngine(project)._route_info(node)
                if is_route:
                    entries.append((module_name, node.name))
        return entries

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        unique: dict[tuple, Finding] = {}
        for finding in findings:
            unique.setdefault(finding.identity(), finding)
        return [
            unique[key]
            for key in sorted(unique, key=lambda item: (
                item[3], item[4], item[1], item[0]
            ))
        ]

    @staticmethod
    def _dedupe_unsupported(items: list[UnsupportedItem]) -> list[UnsupportedItem]:
        unique: dict[tuple, UnsupportedItem] = {}
        for item in items:
            marker = (item.file, item.lineno, item.function, item.reason)
            unique.setdefault(marker, item)
        return [unique[key] for key in sorted(unique)]
