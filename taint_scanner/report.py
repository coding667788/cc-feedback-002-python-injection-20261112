"""JSON report rendering."""

from __future__ import annotations

import json
from typing import Any

from .scanner import ScanResult


def build_report(result: ScanResult, root: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "scanned_root": root,
        "summary": {
            "route_count": len(result.routes),
            "finding_count": len(result.findings),
            "unsupported_count": len(result.unsupported),
            "reused_summaries": result.reused_summaries,
            "recomputed_summaries": result.recomputed_summaries,
            "cache_hit_files": result.cache_hit_files,
        },
        "routes": result.routes,
        "findings": [finding.to_dict() for finding in result.findings],
        "unsupported": [item.to_dict() for item in result.unsupported],
    }


def render_json(result: ScanResult, root: str, indent: int = 2) -> str:
    return json.dumps(build_report(result, root), indent=indent, ensure_ascii=False)


def write_report(result: ScanResult, root: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(render_json(result, root))
