"""Context-, field- and branch-sensitive taint analysis.

Design summary
--------------
* Each function is summarised once.  The summary describes, symbolically,
  what happens to its formal parameters (terms rooted at
  ``"<module>::<func>::<param>"``), including every feasible branch path.
* A call site instantiates the callee summary with the caller's concrete
  taint terms, so a safe call and a tainted call to the same function stay
  separate (context sensitivity).
* Attribute access and constant subscripts extend a term's field path, so
  taint on one object/dict field never leaks to other fields.
* ``if`` is handled by forking the interpreter state; mutually exclusive
  branches are never merged into one path.  ``try/except`` is handled the
  same way, which is what makes the ``int()`` sanitiser's success and
  failure branches distinguishable.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from .models import (
    HTTP_DECORATORS,
    SHELL_FUNCS,
    SHELL_MODULES,
    SQLITE_EXEC_METHODS,
    Finding,
    FlowStep,
    Term,
    UnsupportedItem,
)
from .modulegraph import Project

MAX_PATHS = 64
MAX_CALL_DEPTH = 20


@dataclass
class CallTarget:
    kind: str  # "func" | "method" | "constructor" | "external" | "unknown"
    module: Optional[str] = None
    func: Optional[str] = None
    class_name: Optional[str] = None
    method: Optional[str] = None
    external_name: Optional[str] = None


@dataclass
class CallRecord:
    target: CallTarget
    arg_terms: list[list[Term]]
    arg_tags: list[Optional[str]]
    receiver_tag: Optional[str]
    shell_value: Optional[bool]
    kwarg_terms: dict[str, list[Term]]
    lineno: int
    code: str


@dataclass
class ReturnRecord:
    terms: set[Term]
    object_id: Optional[str]
    type_tag: Optional[str]
    object_fields: dict[str, list[Term]] = field(default_factory=dict)
    object_class: Optional[str] = None


@dataclass
class WriteRecord:
    param_index: Optional[int]
    param_name: Optional[str]
    field_path: tuple[str, ...]
    terms: set[Term]
    object_id: Optional[str]


@dataclass
class Summary:
    key: str
    module: str
    func: str
    is_route: bool
    route_method: Optional[str]
    source_params: list[str]
    basis: str
    findings: list[Finding]
    unsupported: list[UnsupportedItem]
    returns: list[ReturnRecord]
    writes: list[WriteRecord]
    calls: list[CallRecord]


@dataclass
class Bind:
    terms: set[Term] = field(default_factory=set)
    object_id: Optional[str] = None
    type_tag: Optional[str] = None


@dataclass
class HeapEntry:
    fields: dict[str, Bind] = field(default_factory=dict)
    type_tag: Optional[str] = None
    class_name: Optional[str] = None


@dataclass
class State:
    env: dict[str, Bind] = field(default_factory=dict)
    heap: dict[str, HeapEntry] = field(default_factory=dict)
    flow: list[FlowStep] = field(default_factory=list)

    def copy(self) -> "State":
        new_env = {
            name: Bind(set(bind.terms), bind.object_id, bind.type_tag)
            for name, bind in self.env.items()
        }
        new_heap = {
            oid: HeapEntry(dict(entry.fields), entry.type_tag, entry.class_name)
            for oid, entry in self.heap.items()
        }
        return State(new_env, new_heap, list(self.flow))


@dataclass
class PathResult:
    returns: list[ReturnRecord] = field(default_factory=list)
    writes: list[WriteRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unsupported: list[UnsupportedItem] = field(default_factory=list)
    returned: bool = False
    branch_evidence: list[str] = field(default_factory=list)


class FuncAnalyzer:
    """Symbolic interpreter for one function node."""

    def __init__(self, project: Project, engine: "TaintEngine", module: str,
                 node: ast.AST, class_name: Optional[str] = None):
        self.project = project
        self.engine = engine
        self.module = module
        self.node = node
        self.class_name = class_name
        self.info = project.modules[module]
        self.paths: list[PathResult] = []
        self._obj_counter = 0
        self.params = [arg.arg for arg in node.args.args]
        self.call_records: list[CallRecord] = []
        self._work: list[tuple] = []
        self.func_qualname = f"{class_name}.{node.name}" if class_name else node.name

    # ------------------------------------------------------------- utilities
    def _code(self, node: ast.AST) -> str:
        segment = ast.get_source_segment(self.info.source, node)
        return " ".join(segment.split()) if segment else ""

    def _rel(self, path: str) -> str:
        return self.project.rel_path(path)

    def _new_object_id(self) -> str:
        self._obj_counter += 1
        return f"{self.module}::{self.node.name}::obj{self._obj_counter}"

    def _unsupported(self, path: PathResult, node: ast.AST, reason: str) -> None:
        path.unsupported.append(
            UnsupportedItem(
                file=self._rel(self.info.path),
                lineno=getattr(node, "lineno", 0),
                function=self.node.name,
                reason=reason,
                code=self._code(node),
            )
        )

    def _finding(self, state: State, path: PathResult, kind: str,
                 node: ast.AST, sink: str, dangerous: str,
                 terms: set[Term]) -> None:
        live = {term for term in terms if not term.safe_int}
        if not live:
            return
        sources = sorted({term.root for term in live})
        path.findings.append(
            Finding(
                kind=kind,
                source=sources[0],
                dangerous_param=dangerous,
                file=self._rel(self.info.path),
                lineno=node.lineno,
                function=self.node.name,
                sink=sink,
                code=self._code(node),
                taint_terms=sorted(live, key=lambda t: (t.root, t.path, t.safe_int)),
                flow=list(state.flow),
            )
        )

    # ----------------------------------------------------------- expressions
    def eval_expr(self, state: State, path: PathResult, node: ast.AST) -> Bind:
        if isinstance(node, ast.Constant):
            tag = type(node.value).__name__ if node.value is not None else "NoneType"
            return Bind(type_tag=tag)
        if isinstance(node, ast.Name):
            if node.id in state.env:
                bind = state.env[node.id]
                return Bind(set(bind.terms), bind.object_id, bind.type_tag)
            return Bind()
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._eval_sequence(state, path, node.elts,
                                       type(node).__name__.lower())
        if isinstance(node, ast.Dict):
            return self._eval_dict(state, path, node)
        if isinstance(node, ast.JoinedStr):
            return self._eval_fstring(state, path, node)
        if isinstance(node, ast.FormattedValue):
            return self.eval_expr(state, path, node.value)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(state, path, node)
        if isinstance(node, ast.UnaryOp):
            return self.eval_expr(state, path, node.operand)
        if isinstance(node, ast.BoolOp):
            bind = Bind()
            for value in node.values:
                sub = self.eval_expr(state, path, value)
                bind.terms |= sub.terms
                bind.object_id = sub.object_id or bind.object_id
                bind.type_tag = sub.type_tag or bind.type_tag
            return bind
        if isinstance(node, ast.IfExp):
            self.eval_expr(state, path, node.test)
            left = self.eval_expr(state, path, node.body)
            right = self.eval_expr(state, path, node.orelse)
            return Bind(left.terms | right.terms, left.object_id or right.object_id,
                        left.type_tag or right.type_tag)
        if isinstance(node, ast.Compare):
            self.eval_expr(state, path, node.left)
            for comparator in node.comparators:
                self.eval_expr(state, path, comparator)
            return Bind(type_tag="bool")
        if isinstance(node, ast.Call):
            return self._eval_call(state, path, node)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(state, path, node)
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(state, path, node)
        if isinstance(node, ast.Starred):
            return self.eval_expr(state, path, node.value)
        if isinstance(node, ast.Lambda):
            self._unsupported(path, node, "lambda expressions are not modelled")
            return Bind()
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._unsupported(path, node, "comprehensions are not modelled")
            return Bind()
        if isinstance(node, ast.Await):
            return self.eval_expr(state, path, node.value)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            self._unsupported(path, node, "generator yield is not modelled")
            return Bind()
        self._unsupported(path, node, f"unsupported expression {type(node).__name__}")
        return Bind()

    def _eval_sequence(self, state: State, path: PathResult,
                       elements: list[ast.AST], type_tag: str) -> Bind:
        bind = Bind(type_tag=type_tag)
        for element in elements:
            bind.terms |= self.eval_expr(state, path, element).terms
        return bind

    def _eval_dict(self, state: State, path: PathResult, node: ast.Dict) -> Bind:
        oid = self._new_object_id()
        heap_entry = HeapEntry(type_tag="dict")
        for key_node, value_node in zip(node.keys, node.values):
            value = self.eval_expr(state, path, value_node)
            if key_node is None:
                self._unsupported(path, node, "dict unpacking is not modelled")
                continue
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                heap_entry.fields[key_node.value] = Bind(
                    set(value.terms), value.object_id, value.type_tag
                )
            else:
                self._unsupported(path, key_node, "non-constant dict key is not modelled")
        state.heap[oid] = heap_entry
        return Bind(object_id=oid, type_tag="dict")

    def _eval_fstring(self, state: State, path: PathResult, node: ast.JoinedStr) -> Bind:
        bind = Bind(type_tag="str")
        for value in node.values:
            if isinstance(value, ast.Constant):
                continue
            sub = self.eval_expr(state, path, value)
            bind.terms |= sub.terms
        return bind

    def _eval_binop(self, state: State, path: PathResult, node: ast.BinOp) -> Bind:
        left = self.eval_expr(state, path, node.left)
        right = self.eval_expr(state, path, node.right)
        if isinstance(node.op, ast.Add):
            tag = "str" if left.type_tag == "str" or right.type_tag == "str" else None
            return Bind(left.terms | right.terms, left.object_id or right.object_id, tag)
        if isinstance(node.op, ast.Mod):
            tag = "str" if left.type_tag == "str" else None
            return Bind(left.terms | right.terms, type_tag=tag)
        return Bind(left.terms | right.terms)

    def _eval_attribute(self, state: State, path: PathResult, node: ast.Attribute) -> Bind:
        value = self.eval_expr(state, path, node.value)
        if value.object_id and value.object_id in state.heap:
            entry = state.heap[value.object_id]
            if node.attr in entry.fields:
                field_bind = entry.fields[node.attr]
                projected = {term.project(node.attr) for term in value.terms}
                return Bind(field_bind.terms | projected, field_bind.object_id,
                            field_bind.type_tag)
        projected = {term.project(node.attr) for term in value.terms}
        return Bind(projected)

    def _eval_subscript(self, state: State, path: PathResult, node: ast.Subscript) -> Bind:
        value = self.eval_expr(state, path, node.value)
        if isinstance(node.slice, ast.Slice):
            self._unsupported(path, node, "slice subscripts are not modelled")
            return Bind()
        key = self._slice_key(node.slice)
        if key is None:
            self.eval_expr(state, path, node.slice)
            self._unsupported(path, node, "non-constant subscript is not modelled")
            return Bind()
        if value.object_id and value.object_id in state.heap:
            entry = state.heap[value.object_id]
            if key in entry.fields:
                field_bind = entry.fields[key]
                projected = {term.project(key) for term in value.terms}
                return Bind(field_bind.terms | projected, field_bind.object_id,
                            field_bind.type_tag)
        projected = {term.project(key) for term in value.terms}
        return Bind(projected)

    @staticmethod
    def _slice_key(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # ------------------------------------------------------------ statements
    def run(self, initial: State) -> list[PathResult]:
        seed = PathResult()
        self.paths = []
        self._work = [(self.node.body, 0, initial, seed)]
        while self._work:
            statements, start, state, path = self._work.pop(0)
            self._run_suffix(statements, start, state, path)
        return self.paths

    def _run_suffix(self, statements: list[ast.stmt], start: int,
                    state: State, path: PathResult) -> None:
        index = start
        while index < len(statements):
            node = statements[index]
            if isinstance(node, ast.If):
                self._enqueue_if(node, statements, index, state, path)
                return
            if isinstance(node, ast.Try):
                self._enqueue_try(node, statements, index, state, path)
                return
            self._exec_stmt(node, state, path)
            if path.returned:
                self.paths.append(path)
                return
            index += 1
        self.paths.append(path)

    def _exec_block(self, statements: list[ast.stmt], state: State,
                    path: PathResult) -> None:
        saved = self._work
        self._work = []
        self._work.append((statements, 0, state, path))
        while self._work:
            block, start, block_state, block_path = self._work.pop(0)
            self._run_suffix(block, start, block_state, block_path)
        self._work = saved

    def _exec_stmt(self, node: ast.stmt, state: State, path: PathResult) -> None:
        handler = getattr(self, f"_stmt_{type(node).__name__}", None)
        if handler is None:
            self._unsupported(path, node, f"unsupported statement {type(node).__name__}")
            return
        handler(node, state, path)

    def _stmt_Pass(self, node: ast.stmt, state: State, path: PathResult) -> None:
        return

    def _stmt_Expr(self, node: ast.Expr, state: State, path: PathResult) -> None:
        self.eval_expr(state, path, node.value)

    def _stmt_Return(self, node: ast.Return, state: State, path: PathResult) -> None:
        if node.value is None:
            path.returns.append(ReturnRecord(set(), None, None))
        else:
            bind = self.eval_expr(state, path, node.value)
            object_fields: dict[str, list[Term]] = {}
            object_class = None
            if bind.object_id and bind.object_id in state.heap:
                entry = state.heap[bind.object_id]
                object_class = entry.class_name
                for name, field_bind in entry.fields.items():
                    object_fields[name] = sorted(
                        field_bind.terms, key=lambda t: (t.root, t.path, t.safe_int)
                    )
            path.returns.append(
                ReturnRecord(
                    set(bind.terms), bind.object_id, bind.type_tag,
                    object_fields=object_fields, object_class=object_class,
                )
            )
        path.returned = True

    def _stmt_Assign(self, node: ast.Assign, state: State, path: PathResult) -> None:
        value = self.eval_expr(state, path, node.value)
        for target in node.targets:
            self._assign_target(target, value, state, path, node)

    def _stmt_AnnAssign(self, node: ast.AnnAssign, state: State,
                        path: PathResult) -> None:
        if node.value is None:
            return
        value = self.eval_expr(state, path, node.value)
        self._assign_target(node.target, value, state, path, node)

    def _stmt_AugAssign(self, node: ast.AugAssign, state: State,
                        path: PathResult) -> None:
        if not isinstance(node.target, ast.Name) or node.target.id not in state.env:
            self._unsupported(path, node, "augmented assignment target is not a local variable")
            return
        current = state.env[node.target.id]
        extra = self.eval_expr(state, path, node.value)
        state.env[node.target.id] = Bind(
            current.terms | extra.terms,
            current.object_id or extra.object_id,
            current.type_tag or extra.type_tag,
        )

    def _assign_target(self, target: ast.AST, value: Bind, state: State,
                       path: PathResult, statement: ast.stmt) -> None:
        if isinstance(target, ast.Name):
            state.env[target.id] = Bind(set(value.terms), value.object_id, value.type_tag)
            if target.id in self.params:
                state.flow.append(
                    FlowStep(
                        kind="assign",
                        file=self._rel(self.info.path),
                        lineno=statement.lineno,
                        detail=f"parameter-local {target.id} reassigned",
                        code=self._code(statement),
                    )
                )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                if isinstance(element, ast.Starred):
                    self._unsupported(path, statement, "starred unpacking is not modelled")
                    continue
                self._assign_target(element, value, state, path, statement)
        elif isinstance(target, ast.Attribute):
            self._assign_attribute(target, value, state, path, statement)
        elif isinstance(target, ast.Subscript):
            self._assign_subscript(target, value, state, path, statement)
        else:
            self._unsupported(path, statement,
                              f"unsupported assignment target {type(target).__name__}")

    def _assign_attribute(self, node: ast.Attribute, value: Bind, state: State,
                          path: PathResult, statement: ast.stmt) -> None:
        receiver = self.eval_expr(state, path, node.value)
        if receiver.object_id and receiver.object_id in state.heap:
            state.heap[receiver.object_id].fields[node.attr] = Bind(
                set(value.terms), value.object_id, value.type_tag
            )
        self._record_write(receiver, (node.attr,), value, state, path, statement)

    def _assign_subscript(self, node: ast.Subscript, value: Bind, state: State,
                          path: PathResult, statement: ast.stmt) -> None:
        receiver = self.eval_expr(state, path, node.value)
        key = self._slice_key(node.slice)
        if key is None:
            self._unsupported(path, statement,
                              "write through non-constant subscript is not modelled")
            return
        if receiver.object_id and receiver.object_id in state.heap:
            state.heap[receiver.object_id].fields[key] = Bind(
                set(value.terms), value.object_id, value.type_tag
            )
        self._record_write(receiver, (key,), value, state, path, statement)

    def _record_write(self, receiver: Bind, field_path: tuple[str, ...],
                      value: Bind, state: State, path: PathResult,
                      statement: ast.stmt) -> None:
        roots = {term.root for term in receiver.terms}
        for index, param in enumerate(self.params):
            param_root = f"{self.module}::{self.func_qualname}::{param}"
            if param_root in roots:
                projected = set(value.terms)
                path.writes.append(
                    WriteRecord(index, param, field_path, projected, receiver.object_id)
                )
                state.flow.append(
                    FlowStep(
                        kind="assign",
                        file=self._rel(self.info.path),
                        lineno=statement.lineno,
                        detail=f"field {'.'.join(field_path)} of parameter {param} updated",
                        code=self._code(statement),
                    )
                )

    def _enqueue_if(self, node: ast.If, statements: list[ast.stmt], index: int,
                    state: State, path: PathResult) -> None:
        self.eval_expr(state, path, node.test)
        if len(self.paths) + len(self._work) + 2 > MAX_PATHS:
            self._unsupported(path, node, f"branch limit ({MAX_PATHS}) reached")
            self._work.append((statements, index + 1, state, path))
            return
        condition = self._code(node.test)
        true_state, false_state = state.copy(), state.copy()
        true_path, false_path = self._fork_path(path)
        true_state.flow.append(
            FlowStep("branch", self._rel(self.info.path), node.lineno,
                     f"if ({condition}) taken", self._code(node))
        )
        false_state.flow.append(
            FlowStep("branch", self._rel(self.info.path), node.lineno,
                     f"if ({condition}) not taken (else)", self._code(node))
        )
        true_path.branch_evidence.append(f"if ({condition}) taken")
        false_path.branch_evidence.append(f"if ({condition}) not taken (else)")
        self._work.append((node.body + statements[index + 1:], 0,
                           true_state, true_path))
        self._work.append((node.orelse + statements[index + 1:], 0,
                           false_state, false_path))

    def _fork_path(self, path: PathResult) -> tuple[PathResult, PathResult]:
        left = PathResult(
            returns=list(path.returns),
            writes=list(path.writes),
            findings=list(path.findings),
            unsupported=list(path.unsupported),
            returned=path.returned,
        )
        right = PathResult(
            returns=list(path.returns),
            writes=list(path.writes),
            findings=list(path.findings),
            unsupported=list(path.unsupported),
            returned=path.returned,
            branch_evidence=list(path.branch_evidence),
        )
        left.branch_evidence = list(path.branch_evidence)
        return left, right

    def _enqueue_try(self, node: ast.Try, statements: list[ast.stmt], index: int,
                     state: State, path: PathResult) -> None:
        success_state, failure_state = state.copy(), state.copy()
        success_path, failure_path = self._fork_path(path)
        success_state.flow.append(
            FlowStep("branch", self._rel(self.info.path), node.lineno,
                     "try block completed without exception", self._code(node))
        )
        failure_state.flow.append(
            FlowStep("branch", self._rel(self.info.path), node.lineno,
                     "try block raised an exception; handler entered",
                     self._code(node))
        )
        success_path.branch_evidence.append("try block completed without exception")
        failure_path.branch_evidence.append(
            "try block raised an exception; handler entered"
        )
        for handler in node.handlers:
            if handler.name:
                failure_state.env[handler.name] = Bind()
        success_block = (
            node.body
            + node.orelse
            + node.finalbody
            + statements[index + 1:]
        )
        failure_block = (
            self._handler_body(node.handlers)
            + node.finalbody
            + statements[index + 1:]
        )
        self._work.append((success_block, 0, success_state, success_path))
        self._work.append((failure_block, 0, failure_state, failure_path))

    @staticmethod
    def _handler_body(handlers: list[ast.ExceptHandler]) -> list[ast.stmt]:
        body: list[ast.stmt] = []
        for handler in handlers:
            body.extend(handler.body)
        return body

    def _stmt_While(self, node: ast.While, state: State, path: PathResult) -> None:
        self._unsupported(path, node, "loops are analysed at most once and not iterated")
        self.eval_expr(state, path, node.test)
        self._exec_block(node.body, state, path)

    def _stmt_For(self, node: ast.For, state: State, path: PathResult) -> None:
        self._unsupported(path, node, "loops are analysed at most once and not iterated")
        self.eval_expr(state, path, node.iter)
        self._assign_target(node.target, Bind(), state, path, node)
        self._exec_block(node.body, state, path)

    def _stmt_AsyncFor(self, node: ast.AsyncFor, state: State,
                       path: PathResult) -> None:
        self._stmt_For(node, state, path)

    def _stmt_Break(self, node, state, path) -> None:
        self.paths.append(path)

    def _stmt_Continue(self, node, state, path) -> None:
        self.paths.append(path)

    def _stmt_With(self, node: ast.With, state: State, path: PathResult) -> None:
        for item in node.items:
            bind = self.eval_expr(state, path, item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(item.optional_vars, bind, state, path, node)
        self._exec_block(node.body, state, path)

    def _stmt_AsyncWith(self, node: ast.AsyncWith, state: State,
                        path: PathResult) -> None:
        self._stmt_With(node, state, path)

    def _stmt_Raise(self, node: ast.Raise, state: State, path: PathResult) -> None:
        if node.exc is not None:
            self.eval_expr(state, path, node.exc)

    def _stmt_Assert(self, node: ast.Assert, state: State, path: PathResult) -> None:
        self.eval_expr(state, path, node.test)

    def _stmt_Global(self, node, state, path) -> None:
        return

    def _stmt_Nonlocal(self, node, state, path) -> None:
        self._unsupported(path, node, "nonlocal variables are not modelled")

    def _stmt_FunctionDef(self, node, state, path) -> None:
        return

    _stmt_AsyncFunctionDef = _stmt_FunctionDef
    _stmt_ClassDef = _stmt_FunctionDef

    def _stmt_Import(self, node, state, path) -> None:
        return

    _stmt_ImportFrom = _stmt_Import

    def _stmt_Delete(self, node, state, path) -> None:
        self._unsupported(path, node, "del statements are not modelled")

    # ---------------------------------------------------------------- calls
    def _eval_call(self, state: State, path: PathResult, node: ast.Call) -> Bind:
        target, receiver = self._resolve_target(node, state, path)
        args = [self.eval_expr(state, path, arg) for arg in node.args]
        kwargs = {
            keyword.arg: self.eval_expr(state, path, keyword.value)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        for keyword in node.keywords:
            if keyword.arg is None:
                self._unsupported(path, node, "**kwargs unpacking is not modelled")

        special = self._builtin_semantics(node, target, args, kwargs, state, path)
        if special is not None:
            return special
        if target.kind == "method" and target.class_name == "__duck__":
            # sqlite-style execute sinks are still external method calls.
            if target.method in SQLITE_EXEC_METHODS and receiver[0] is not None:
                self._check_external_sink(
                    node, target, args, kwargs,
                    (receiver[0], "", target.method), state, path
                )
            result = self.engine.instantiate(
                target=target,
                arg_binds=args,
                kwarg_binds=kwargs,
                call_file=self._rel(self.info.path),
                call_lineno=node.lineno,
                call_code=self._code(node),
                state=state,
                path=path,
                analyzer=self,
                receiver_bind=receiver[0] if receiver and receiver[0] else None,
            )
            return result if result is not None else Bind()

        if target.kind == "unknown":
            self._unsupported(path, node, "unresolved callee; call skipped")
            return Bind()
        if target.kind == "external":
            return self._check_external_sink(
                node, target, args, kwargs, receiver, state, path
            )
        self.call_records.append(
            CallRecord(
                target=target,
                arg_terms=[sorted(bind.terms, key=lambda t: (t.root, t.path))
                           for bind in args],
                arg_tags=[bind.type_tag for bind in args],
                receiver_tag=receiver[0].type_tag if receiver and receiver[0] else None,
                shell_value=self._literal_bool(node, "shell"),
                kwarg_terms={
                    name: sorted(bind.terms, key=lambda t: (t.root, t.path))
                    for name, bind in kwargs.items()
                },
                lineno=node.lineno,
                code=self._code(node),
            )
        )

        result = self.engine.instantiate(
            target=target,
            arg_binds=args,
            kwarg_binds=kwargs,
            call_file=self._rel(self.info.path),
            call_lineno=node.lineno,
            call_code=self._code(node),
            state=state,
            path=path,
            analyzer=self,
            receiver_bind=receiver[0] if receiver and receiver[0] else None,
        )
        return result if result is not None else Bind()

    def _builtin_semantics(self, node: ast.Call, target: CallTarget,
                           args: list[Bind], kwargs: dict[str, Bind],
                           state: State, path: PathResult) -> Optional[Bind]:
        if target.kind != "external" or target.external_name not in {"int", "str"}:
            return None
        if target.external_name == "int":
            if args:
                state.flow.append(
                    FlowStep(
                        kind="branch",
                        file=self._rel(self.info.path),
                        lineno=node.lineno,
                        detail="int() conversion success path returns a clean integer",
                        code=self._code(node),
                    )
                )
            return Bind(type_tag="int")
        # str() preserves the safe-int marker; everything else keeps taint.
        if args:
            only_safe = args[0].terms and all(term.safe_int for term in args[0].terms)
            if args[0].type_tag == "int" or only_safe:
                terms = {term.with_safe_int() for term in args[0].terms} or set()
                if args[0].type_tag == "int" and not terms:
                    return Bind(type_tag="str")
                return Bind(terms=terms, type_tag="str")
            return Bind(set(args[0].terms), args[0].object_id, "str")
        return Bind(type_tag="str")

    def _check_external_sink(self, node: ast.Call, target: CallTarget,
                             args: list[Bind], kwargs: dict[str, Bind],
                             receiver: tuple[Optional[Bind], str, str],
                             state: State, path: PathResult) -> None:
        receiver_bind, module_name, func_name = receiver
        # sqlite3 style: cursor.execute / connection.execute ...
        if func_name in SQLITE_EXEC_METHODS and receiver_bind is not None:
            # The project only models sqlite3 connections/cursors; any
            # .execute-style call on a tracked value is treated as a sqlite
            # sink.  Bound-parameter calls are safe because the fixed SQL
            # string carries no taint terms.
            self._finding(
                state, path, "sql_injection", node,
                f"sqlite3.{func_name}", "sql",
                args[0].terms if args else set()
            )
            return Bind(type_tag=receiver_bind.type_tag)
        if module_name == "sqlite3":
            if func_name == "connect":
                return Bind(type_tag="sqlite_connection")
            if func_name == "Cursor":
                return Bind(type_tag="sqlite_cursor")
        if func_name == "cursor" and receiver_bind is not None:
            if receiver_bind.type_tag == "sqlite_connection":
                return Bind(type_tag="sqlite_cursor")
        # subprocess / os command execution
        if module_name in SHELL_MODULES and func_name in SHELL_FUNCS:
            self._check_command_sink(node, func_name, args, kwargs, state, path)
            return Bind()
        return Bind()

    def _check_command_sink(self, node: ast.Call, func_name: str,
                            args: list[Bind], kwargs: dict[str, Bind],
                            state: State, path: PathResult) -> None:
        shell_bind = kwargs.get("shell")
        shell_value: Optional[bool] = None
        if shell_bind is not None:
            literal = self._literal_bool(node, "shell")
            if literal is None:
                self._unsupported(path, node, "shell= argument is not a constant True/False")
                return
            shell_value = literal
        if func_name in {"system", "popen"}:
            shell_value = True
        if shell_value is not True:
            return  # shell=False / default parameter list: no shell injection
        if not args:
            return
        self._finding(state, path, "command_injection", node,
                      f"subprocess.{func_name}(shell=True)", "cmd", args[0].terms)

    def _literal_bool(self, node: ast.Call, keyword: str) -> Optional[bool]:
        for kw in node.keywords:
            if kw.arg == keyword and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, bool):
                    return kw.value.value
        return None

    def _resolve_target(self, node: ast.Call, state: State,
                        path: PathResult) -> tuple[CallTarget, tuple]:
        func = node.func
        if isinstance(func, ast.Name):
            kind, mod, symbol = self.project.resolve_chain(self.module, func.id)
            if kind in {"local", "import-symbol"} and mod is not None:
                if symbol in self.project.modules.get(mod, _EMPTY).classes:
                    return CallTarget("constructor", module=mod, class_name=symbol), (None, "", symbol)
                return CallTarget("func", module=mod, func=symbol), (None, "", symbol)
            if kind == "import-module":
                return CallTarget("external", external_name=func.id), (None, mod or "", func.id)
            if func.id in {"int", "str"}:
                return CallTarget("external", external_name=func.id), (None, "builtins", func.id)
            return CallTarget("unknown"), (None, "", func.id)
        if isinstance(func, ast.Attribute):
            receiver_bind = self.eval_expr(state, path, func.value)
            module_name, base_name = self._attribute_owner(func.value)
            # method on a class instance
            if receiver_bind.type_tag and receiver_bind.type_tag.startswith("class:"):
                class_name = receiver_bind.type_tag.split(":", 1)[1]
                return (
                    CallTarget("method", module=module_name, class_name=class_name,
                               method=func.attr),
                    (receiver_bind, module_name, func.attr),
                )
            if module_name:
                if module_name in self.project.modules:
                    info = self.project.modules[module_name]
                    if func.attr in info.defs and info.defs[func.attr].kind == "function":
                        return (
                            CallTarget("func", module=module_name, func=func.attr),
                            (receiver_bind, module_name, func.attr),
                        )
                    if func.attr in info.classes:
                        return (
                            CallTarget("constructor", module=module_name,
                                       class_name=func.attr),
                            (receiver_bind, module_name, func.attr),
                        )
                return (
                    CallTarget("external", external_name=func.attr),
                    (receiver_bind, module_name, func.attr),
                )
            if base_name:
                if base_name in SHELL_MODULES or base_name == "sqlite3":
                    return (
                        CallTarget("external", external_name=func.attr),
                        (receiver_bind, base_name, func.attr),
                    )
                # Attribute on a local value with no resolvable owner module:
                # treat it as a regular method call whose result inherits the
                # receiver's taint (e.g. "abc".strip()).
                return (
                    CallTarget("method", class_name="__duck__", method=func.attr),
                    (receiver_bind, base_name, func.attr),
                )
            return CallTarget("unknown"), (receiver_bind, "", func.attr)
        self._unsupported(path, node, "indirect/dynamic callee is not modelled")
        return CallTarget("unknown"), (None, "", "")

    def _attribute_owner(self, node: ast.AST) -> tuple[str, str]:
        if isinstance(node, ast.Name):
            kind, mod, symbol = self.project.resolve_chain(self.module, node.id)
            if kind == "import-module":
                return mod or "", mod.split(".")[-1] if mod else node.id
            if kind == "import-symbol" and mod is not None:
                return mod, symbol or node.id
            return "", node.id
        if isinstance(node, ast.Attribute):
            module_name, _ = self._attribute_owner(node.value)
            if module_name:
                return module_name, node.attr
        return "", ""


_EMPTY = type("EmptyModule", (), {"classes": {}})()


# --------------------------------------------------------------------- engine
class TaintEngine:
    def __init__(self, project: Project):
        self.project = project
        self.summaries: dict[str, Summary] = {}
        self._busy: set[str] = set()
        self._depth = 0

    # ------------------------------------------------------------- routing
    @staticmethod
    def _decorator_name(node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            return TaintEngine._decorator_name(node.func)
        return None

    def _route_info(self, node: ast.AST) -> tuple[bool, Optional[str]]:
        for decorator in getattr(node, "decorator_list", []):
            name = self._decorator_name(decorator)
            if name in HTTP_DECORATORS:
                return True, name
        return False, None

    # ------------------------------------------------------------ analysis
    def analyze_all(self) -> dict[str, Summary]:
        keys: list[tuple[str, str, Optional[str], str]] = []
        for module_name, info in sorted(self.project.modules.items()):
            for node in info.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    keys.append((module_name, node.name, None, node.name))
            for class_name in sorted(info.classes):
                method_node = None
                for sub in info.tree.body:
                    if isinstance(sub, ast.ClassDef) and sub.name == class_name:
                        method_node = sub
                if method_node is None:
                    continue
                for sub in method_node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        keys.append((module_name, sub.name, class_name,
                                     f"{class_name}.{sub.name}"))
        for module_name, func_name, class_name, _ in keys:
            self.get_summary(module_name, func_name, class_name)
        return self.summaries

    def get_summary(self, module_name: str, func_name: str,
                    class_name: Optional[str] = None) -> Optional[Summary]:
        key = self._summary_key(module_name, func_name, class_name)
        if key in self.summaries:
            return self.summaries[key]
        if key in self._busy:
            return None  # recursion cut point
        node = (
            self.project.get_method_node(module_name, class_name, func_name)
            if class_name
            else self.project.get_func_node(module_name, func_name)
        )
        if node is None:
            return None
        self._busy.add(key)
        analyzer = FuncAnalyzer(self.project, self, module_name, node, class_name)
        initial = State()
        for arg in node.args.args:
            root = f"{module_name}::{analyzer.func_qualname}::{arg.arg}"
            initial.env[arg.arg] = Bind(terms={Term(root)})
        results = analyzer.run(initial)
        self._busy.discard(key)
        summary = self._build_summary(key, module_name, func_name, class_name,
                                      node, analyzer, results)
        self.summaries[key] = summary
        return summary

    def _summary_key(self, module_name: str, func_name: str,
                     class_name: Optional[str]) -> str:
        return f"{module_name}::{class_name + '.' if class_name else ''}{func_name}"

    def _build_summary(self, key: str, module_name: str, func_name: str,
                       class_name: Optional[str], node: ast.AST,
                       analyzer: FuncAnalyzer,
                       results: list[PathResult]) -> Summary:
        is_route, route_method = self._route_info(node)
        findings: list[Finding] = []
        unsupported: list[UnsupportedItem] = []
        returns: list[ReturnRecord] = []
        writes: list[WriteRecord] = []
        seen_finding: set = set()
        seen_unsup: set = set()
        for path in results:
            for finding in path.findings:
                identity = finding.identity()
                if identity not in seen_finding:
                    seen_finding.add(identity)
                    findings.append(finding)
            for item in path.unsupported:
                marker = (item.file, item.lineno, item.reason)
                if marker not in seen_unsup:
                    seen_unsup.add(marker)
                    unsupported.append(item)
            returns.extend(path.returns)
            writes.extend(path.writes)
        source_params = [arg.arg for arg in node.args.args] if is_route else []
        basis = self._content_basis(module_name, func_name, class_name,
                                    analyzer.call_records)
        return Summary(
            key=key,
            module=module_name,
            func=func_name,
            is_route=is_route,
            route_method=route_method,
            source_params=source_params,
            basis=basis,
            findings=findings,
            unsupported=unsupported,
            returns=returns,
            writes=writes,
            calls=list(analyzer.call_records),
        )

    def _content_basis(self, module_name: str, func_name: str,
                       class_name: Optional[str],
                       call_records: list[CallRecord]) -> str:
        info = self.project.modules[module_name]
        parts = [info.source_hash, class_name or "-", func_name]
        callee_bases: list[str] = []
        for record in call_records:
            target = record.target
            if target.kind == "constructor":
                callee_key = f"class:{target.module}::{target.class_name}"
            elif target.kind == "method":
                callee_key = self._summary_key(target.module, target.method,
                                                target.class_name)
            else:
                callee_key = self._summary_key(target.module, target.func, None)
            callee_bases.append(callee_key)
            callee_summary = self.summaries.get(callee_key)
            if callee_summary is not None:
                callee_bases.append(callee_summary.basis)
            else:
                callee_bases.append("unresolved")
        parts.extend(sorted(callee_bases))
        raw = "||".join(parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # -------------------------------------------------------- instantiation
    def instantiate(self, target: CallTarget, arg_binds: list[Bind],
                    kwarg_binds: dict[str, Bind], call_file: str,
                    call_lineno: int, call_code: str, state: State,
                    path: PathResult, analyzer: FuncAnalyzer,
                    receiver_bind: Optional[Bind] = None) -> Optional[Bind]:
        if self._depth >= MAX_CALL_DEPTH:
            analyzer._unsupported(
                path, ast.Constant(value=None, lineno=call_lineno),
                f"call depth limit ({MAX_CALL_DEPTH}) reached"
            )
            return None
        if target.kind == "method" and target.class_name == "__duck__":
            # Unknown instance method: conservatively propagate receiver taint
            # plus any argument taint onto the returned value.
            terms = set(receiver_bind.terms) if receiver_bind else set()
            for actual in arg_binds:
                terms |= actual.terms
            tag = receiver_bind.type_tag if receiver_bind else None
            return Bind(terms=terms, type_tag=tag)
        if target.kind == "constructor":
            oid = analyzer._new_object_id()
            state.heap[oid] = HeapEntry(type_tag=f"class:{target.class_name}",
                                        class_name=target.class_name)
            init_summary = self.get_summary(target.module, "__init__",
                                            target.class_name)
            if init_summary is not None:
                self_bind = Bind(object_id=oid,
                                 type_tag=f"class:{target.class_name}")
                applied = self._apply_summary(
                    init_summary,
                    CallTarget("method", module=target.module,
                               class_name=target.class_name, method="__init__"),
                    [self_bind] + arg_binds, kwarg_binds,
                    call_file, call_lineno, call_code, state, path, analyzer,
                )
            return Bind(object_id=oid, type_tag=f"class:{target.class_name}")
        class_name = target.class_name if target.kind == "method" else (
            target.class_name if target.kind == "constructor" else None
        )
        summary = self.get_summary(target.module, target.func or target.method, class_name)
        if summary is None:
            return None

        self._depth += 1
        try:
            return self._apply_summary(summary, target, arg_binds, kwarg_binds,
                                       call_file, call_lineno, call_code,
                                       state, path, analyzer)
        finally:
            self._depth -= 1

    def _apply_summary(self, summary: Summary, target: CallTarget,
                       arg_binds: list[Bind], kwarg_binds: dict[str, Bind],
                       call_file: str, call_lineno: int, call_code: str,
                       state: State, path: PathResult,
                       analyzer: FuncAnalyzer) -> Bind:
        if target.kind == "method" and target.class_name:
            callee_node = self.project.get_method_node(
                summary.module, target.class_name, summary.func
            )
        else:
            callee_node = self.project.get_func_node(summary.module, summary.func)
        param_names = [arg.arg for arg in callee_node.args.args] if callee_node else []
        qual_func = (
            f"{target.class_name}.{summary.func}"
            if target.kind == "method" and target.class_name
            else summary.func
        )
        param_root = {
            name: f"{summary.module}::{qual_func}::{name}" for name in param_names
        }
        term_map: dict[Term, set[Term]] = {}
        heap_map: dict[str, str] = {}

        def bind_param(index: int, name: str, actual: Bind) -> None:
            root = Term(param_root[name])
            term_map[root] = set(actual.terms)
            if actual.object_id:
                heap_map[f"{summary.key}::obj::{name}"] = actual.object_id

        for index, actual in enumerate(arg_binds[: len(param_names)]):
            bind_param(index, param_names[index], actual)
        for name, actual in kwarg_binds.items():
            if name in param_root:
                root_index = param_names.index(name)
                bind_param(root_index, name, actual)

        def subst(term: Term) -> set[Term]:
            if term.root not in param_root.values():
                return {term}
            param_name = next(
                name for name, root in param_root.items() if root == term.root
            )
            mapped = term_map.get(Term(term.root), set())
            out: set[Term] = set()
            if term.path:
                object_id = heap_map.get(f"{summary.key}::obj::{param_name}")
                if object_id and object_id in state.heap:
                    current = state.heap[object_id].fields
                    for segment in term.path:
                        nested = current.get(segment)
                        if nested is None:
                            break
                        for base in nested.terms:
                            out.add(Term(base.root, base.path,
                                         base.safe_int or term.safe_int))
                        if nested.object_id and nested.object_id in state.heap:
                            current = state.heap[nested.object_id].fields
                        else:
                            current = {}
                if out:
                    return out
            if not mapped:
                # Symbolic analysis: keep the formal parameter term so taint
                # keeps flowing through deeper call chains.
                return {term}
            for base in mapped:
                out.add(Term(base.root, base.path + term.path,
                             base.safe_int or term.safe_int))
            return out

        # findings of the callee become findings of the caller
        for finding in summary.findings:
            mapped_terms: set[Term] = set()
            for term in finding.taint_terms:
                mapped_terms |= subst(term)
            concrete = {
                term for term in mapped_terms
                if not term.safe_int and term.root not in param_root.values()
            }
            symbolic = {term for term in mapped_terms if term.root in param_root.values()}
            if not concrete and not symbolic:
                continue
            if not concrete:
                # Still purely symbolic: re-emit against this frame's formal
                # parameter roots so an outer caller can instantiate it later.
                live = {term for term in symbolic if not term.safe_int}
            else:
                live = concrete
            mapped_sources = sorted({term.root for term in live})
            new_flow = [
                FlowStep(
                    kind="call",
                    file=call_file,
                    lineno=call_lineno,
                    detail=(
                        f"call {summary.key}("
                        + ", ".join(
                            self._render_arg(arg, state) for arg in arg_binds
                        )
                        + ")"
                    ),
                    code=call_code,
                )
            ]
            for step in finding.flow:
                new_flow.append(FlowStep(step.kind, step.file, step.lineno,
                                         step.detail, step.code))
            path.findings.append(
                Finding(
                    kind=finding.kind,
                    source=mapped_sources[0],
                    dangerous_param=finding.dangerous_param,
                    file=finding.file,
                    lineno=finding.lineno,
                    function=finding.function,
                    sink=finding.sink,
                    code=finding.code,
                    taint_terms=sorted(live,
                                       key=lambda t: (t.root, t.path, t.safe_int)),
                    flow=new_flow,
                )
            )

        for item in summary.unsupported:
            if not any(existing.file == item.file and existing.lineno == item.lineno
                       and existing.reason == item.reason for existing in path.unsupported):
                path.unsupported.append(item)

        # parameter writes propagate back onto caller objects / taint roots
        for write in summary.writes:
            if write.param_name is None:
                continue
            if write.param_name not in param_root:
                continue
            root = Term(param_root[write.param_name])
            caller_terms = term_map.get(root, set())
            mapped_terms: set[Term] = set()
            for write_term in write.terms:
                mapped_terms |= subst(write_term)
            if caller_terms:
                for base in caller_terms:
                    extended = {
                        Term(base.root, base.path + write.field_path, base.safe_int)
                    }
                    state.flow.append(
                        FlowStep(
                            kind="assign",
                            file=call_file,
                            lineno=call_lineno,
                            detail=(
                                f"callee mutates field {'.'.join(write.field_path)} "
                                f"of argument {write.param_name}"
                            ),
                            code=call_code,
                        )
                    )
                    mapped_terms |= extended
            actual_index = (
                param_names.index(write.param_name)
                if write.param_name in param_names
                else None
            )
            if actual_index is not None and actual_index < len(arg_binds):
                actual = arg_binds[actual_index]
                target_oid = actual.object_id
                if target_oid and target_oid in state.heap and write.field_path:
                    field = write.field_path[0]
                    existing = state.heap[target_oid].fields.get(field, Bind())
                    state.heap[target_oid].fields[field] = Bind(
                        existing.terms | mapped_terms,
                        existing.object_id,
                        existing.type_tag,
                    )

        result_terms: set[Term] = set()
        result_object: Optional[str] = None
        result_tag: Optional[str] = None
        for ret in summary.returns:
            for term in ret.terms:
                result_terms |= subst(term)
            if ret.object_id:
                result_object = self._rebuild_returned_object(
                    ret, summary, analyzer, state, subst, param_root
                )
            result_tag = ret.type_tag or result_tag
        return Bind(result_terms, result_object, result_tag)

    def _rebuild_returned_object(self, ret, summary: Summary,
                                 analyzer: FuncAnalyzer, state: State,
                                 subst, param_root: dict[str, str]) -> str:
        new_id = analyzer._new_object_id()
        fields: dict[str, Bind] = {}
        for field_name, field_terms in ret.object_fields.items():
            mapped: set[Term] = set()
            for term in field_terms:
                mapped |= subst(term)
            fields[field_name] = Bind(mapped)
        state.heap[new_id] = HeapEntry(
            fields=fields,
            type_tag=ret.type_tag,
            class_name=ret.object_class,
        )
        return new_id

    @staticmethod
    def _render_arg_terms(terms: set[Term]) -> str:
        if not terms:
            return "constant"
        ordered = sorted(terms, key=lambda t: (t.root, t.path, t.safe_int))
        return ";".join(
            t.root + ("." + ".".join(t.path) if t.path else "") for t in ordered
        )

    @staticmethod
    def _render_arg(bind: Bind, state: State) -> str:
        terms = set(bind.terms)
        if bind.object_id and bind.object_id in state.heap:
            for field_bind in state.heap[bind.object_id].fields.values():
                terms |= field_bind.terms
        return TaintEngine._render_arg_terms(terms)

    # ---------------------------------------------------------- route entry
    def analyze_route(self, module_name: str, func_name: str) -> Optional[dict]:
        summary = self.get_summary(module_name, func_name)
        if summary is None or not summary.is_route:
            return None
        node = self.project.get_func_node(module_name, func_name)
        if node is None:
            return None
        source_key = f"{module_name}::{func_name}"
        initial = State()
        param_names = [arg.arg for arg in node.args.args]
        for name in param_names:
            initial.env[name] = Bind(terms={Term(f"{source_key}::{name}")})
        analyzer = FuncAnalyzer(self.project, self, module_name, node)
        results = analyzer.run(initial)

        findings: list[Finding] = []
        unsupported: list[UnsupportedItem] = []
        seen_finding: set = set()
        seen_unsup: set = set()
        for path in results:
            for finding in path.findings:
                identity = finding.identity()
                if identity in seen_finding:
                    continue
                seen_finding.add(identity)
                finding.source = source_key
                findings.append(finding)
            for item in path.unsupported:
                marker = (item.file, item.lineno, item.reason)
                if marker not in seen_unsup:
                    seen_unsup.add(marker)
                    unsupported.append(item)
        return {
            "summary": summary,
            "node": node,
            "source_key": source_key,
            "param_names": param_names,
            "findings": findings,
            "unsupported": unsupported,
        }
