"""Core immutable-ish data structures shared by the scanner.

Every dataclass here can be round-tripped through :mod:`json` so that analysis
summaries can live in the SQLite cache as plain strings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


HTTP_DECORATORS = {"get", "post", "put", "delete", "patch", "api_route"}
SQLITE_EXEC_METHODS = {"execute", "executemany", "executescript"}
SHELL_FUNCS = {"system", "popen", "check_output", "run", "call", "Popen", "check_call"}
SHELL_MODULES = {"os", "subprocess"}


@dataclass(frozen=True)
class Term:
    """A symbolic taint term.

    ``root`` is either a route source key (``"<route>::<param>"``) or a formal
    parameter reference (``"<func-key>::<param>"``).  ``path`` holds the
    attribute / constant-subscript chain, which makes the analysis field
    sensitive.  ``safe_int`` marks terms produced by a successful ``int()``
    conversion followed by ``str()`` (a decimal string we treat as clean).
    """

    root: str
    path: tuple[str, ...] = ()
    safe_int: bool = False

    def project(self, name: str) -> "Term":
        return Term(self.root, self.path + (name,), self.safe_int)

    def with_safe_int(self) -> "Term":
        return Term(self.root, self.path, True)

    def to_dict(self) -> dict[str, Any]:
        return {"root": self.root, "path": list(self.path), "safe_int": self.safe_int}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Term":
        return Term(data["root"], tuple(data["path"]), data.get("safe_int", False))


@dataclass
class FlowStep:
    """One piece of evidence on the propagation path of a finding."""

    kind: str  # "call" | "branch" | "sink" | "assign" | "return"
    file: str
    lineno: int
    detail: str
    code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "FlowStep":
        return FlowStep(**data)


@dataclass
class Finding:
    kind: str  # "sql_injection" | "command_injection"
    source: str
    dangerous_param: str
    file: str
    lineno: int
    function: str
    sink: str
    code: str
    taint_terms: list[Term] = field(default_factory=list)
    flow: list[FlowStep] = field(default_factory=list)

    def identity(self) -> tuple:
        return (
            self.kind,
            self.source,
            self.dangerous_param,
            self.file,
            self.lineno,
            self.sink,
            tuple((s.kind, s.file, s.lineno, s.detail) for s in self.flow),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["flow"] = [step.to_dict() for step in self.flow]
        data["taint_terms"] = [term.to_dict() for term in self.taint_terms]
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Finding":
        return Finding(
            kind=data["kind"],
            source=data["source"],
            dangerous_param=data["dangerous_param"],
            taint_terms=[Term.from_dict(item) for item in data.get("taint_terms", [])],
            file=data["file"],
            lineno=data["lineno"],
            function=data["function"],
            sink=data["sink"],
            code=data["code"],
            flow=[FlowStep.from_dict(step) for step in data.get("flow", [])],
        )


@dataclass
class UnsupportedItem:
    """A construct the scanner does not model precisely.

    Unsupported items are reported explicitly instead of being silently treated
    as safe, so a clean report never hides analysis gaps.
    """

    file: str
    lineno: int
    function: str
    reason: str
    code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "UnsupportedItem":
        return UnsupportedItem(**data)


def term_list_to_dict(terms: set[Term]) -> list[dict[str, Any]]:
    return [term.to_dict() for term in sorted(terms, key=lambda t: (t.root, t.path, t.safe_int))]


def term_list_from_dict(data: list[dict[str, Any]]) -> set[Term]:
    return {Term.from_dict(item) for item in data}
