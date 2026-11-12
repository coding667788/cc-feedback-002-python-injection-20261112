from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


UNKNOWN = object()


@dataclass(frozen=True)
class SourceRecord:
    route_method: str
    route_path: str
    file: str
    line: int
    column: int
    route_line: int
    function: str
    parameter: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "route_parameter",
            "route": f"{self.route_method} {self.route_path}",
            "route_method": self.route_method,
            "route_path": self.route_path,
            "route_line": self.route_line,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "function": self.function,
            "parameter": self.parameter,
        }


@dataclass(frozen=True)
class CallEvidence:
    file: str
    line: int
    column: int
    caller_function: str
    callee_file: str
    callee_function: str
    argument: str
    parameter: str
    call_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "call",
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "caller_function": self.caller_function,
            "callee_file": self.callee_file,
            "callee_function": self.callee_function,
            "argument": self.argument,
            "parameter": self.parameter,
            "call": self.call_text,
        }


@dataclass(frozen=True)
class BranchEvidence:
    file: str
    line: int
    column: int
    function: str
    condition: str
    outcome: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": "branch",
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "function": self.function,
            "condition": self.condition,
            "outcome": self.outcome,
        }
        if self.detail:
            result["detail"] = self.detail
        return result


Evidence = CallEvidence | BranchEvidence


@dataclass(frozen=True)
class Taint:
    source: SourceRecord
    events: tuple[Evidence, ...] = ()

    def add(self, event: Evidence) -> "Taint":
        return Taint(self.source, self.events + (event,))


@dataclass(frozen=True)
class Ref:
    kind: str
    module: str
    name: str = ""


@dataclass(frozen=True)
class Value:
    taints: frozenset[Taint] = frozenset()
    fields: tuple[tuple[tuple[str, ...], frozenset[Taint]], ...] = ()
    kind: str = "unknown"
    const: Any = UNKNOWN
    sanitized_numeric: bool = False
    ref: Ref | None = None

    @staticmethod
    def make_fields(items: dict[tuple[str, ...], frozenset[Taint]]) -> tuple[
        tuple[tuple[str, ...], frozenset[Taint]], ...
    ]:
        return tuple(sorted((path, taints) for path, taints in items.items() if taints))

    def field_map(self) -> dict[tuple[str, ...], frozenset[Taint]]:
        return {path: taints for path, taints in self.fields}


@dataclass(frozen=True)
class EventRecord:
    file: str
    line: int
    column: int
    function: str
    category: str
    message: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": "unsupported",
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "function": self.function,
            "message": self.message,
        }
        if self.detail:
            result["detail"] = self.detail
        return result


@dataclass
class RouteEntry:
    module: str
    function: str
    method: str
    path: str
    file: str
    line: int
    column: int
    route_line: int


@dataclass
class FunctionInfo:
    module: str
    name: str
    node: Any
    file: str

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass
class ModuleInfo:
    name: str
    path: str
    relative_path: str
    source: str
    digest: str
    tree: Any
    is_package: bool = False
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    classes: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    routes: list[RouteEntry] = field(default_factory=list)


@dataclass
class Outcome:
    env: dict[str, Value] | None
    returns: list[Value] = field(default_factory=list)


@dataclass
class AnalysisResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    unsupported: list[dict[str, Any]] = field(default_factory=list)
