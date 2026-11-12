"""Shared helpers for the scanner's unittest suite."""

from __future__ import annotations

import json
import os
import shutil


def reset_dir(path: str) -> None:
    if os.path.exists(path):
        shutil.rmtree(path)


def report_signature(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    findings = [
        (
            finding["kind"],
            finding["source"],
            finding["file"],
            finding["lineno"],
            tuple(
                (step["kind"], step["file"], step["lineno"], step["detail"])
                for step in finding["flow"]
            ),
            tuple(
                (term["root"], tuple(term["path"]), term["safe_int"])
                for term in finding["taint_terms"]
            ),
        )
        for finding in data["findings"]
    ]
    unsupported = [
        (item["file"], item["lineno"], item["reason"])
        for item in data["unsupported"]
    ]
    return {"findings": findings, "unsupported": unsupported}
