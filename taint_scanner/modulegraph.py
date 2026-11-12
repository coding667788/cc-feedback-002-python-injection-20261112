"""Project discovery and import resolution.

The scanner walks a source tree, parses every ``.py`` file with :mod:`ast`
(never importing it), assigns dotted module names exactly like CPython's
import machinery and resolves absolute / relative imports, including the
``import ... as ...`` and ``from ... import ... as ...`` alias forms.
"""

from __future__ import annotations

import ast
import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ImportBinding:
    local_name: str
    kind: str  # "module" | "symbol"
    source_module: Optional[str]  # dotted project module, or None for external
    target_name: Optional[str]  # set for from-imports
    level: int
    lineno: int

    def to_dict(self) -> dict:
        return {
            "local_name": self.local_name,
            "kind": self.kind,
            "source_module": self.source_module,
            "target_name": self.target_name,
            "level": self.level,
            "lineno": self.lineno,
        }

    @staticmethod
    def from_dict(data: dict) -> "ImportBinding":
        return ImportBinding(**data)


@dataclass
class DefInfo:
    name: str
    kind: str  # "function" | "class"
    lineno: int


@dataclass
class ModuleInfo:
    name: str
    path: str
    rel_path: str
    package: Optional[str]
    is_package: bool
    source_hash: str
    source: str
    tree: ast.AST
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    defs: dict[str, DefInfo] = field(default_factory=dict)
    classes: dict[str, dict[str, int]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)

    def func_key(self, func_name: str) -> str:
        return f"{self.name}::{func_name}"


def _rel_posix(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _hash_source(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _module_name_for(rel_path: str) -> tuple[str, Optional[str], bool]:
    parts = rel_path.split("/")
    is_package = parts[-1] == "__init__.py"
    if is_package:
        mod_parts = parts[:-1]
    else:
        mod_parts = parts[:-1] + [parts[-1][:-3]]
    name = ".".join(mod_parts)
    package = ".".join(mod_parts[:-1]) if len(mod_parts) > 1 else None
    if is_package:
        package = name
    return name, package, is_package


class Project:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.modules: dict[str, ModuleInfo] = {}
        self.path_index: dict[str, ModuleInfo] = {}

    # ------------------------------------------------------------------ load
    def load(self) -> None:
        py_files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for filename in sorted(filenames):
                if filename.endswith(".py"):
                    py_files.append(os.path.join(dirpath, filename))

        for path in py_files:
            rel = _rel_posix(path, self.root)
            name, package, is_package = _module_name_for(rel)
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            tree = ast.parse(source, filename=path)
            info = ModuleInfo(
                name=name,
                path=path,
                rel_path=rel,
                package=package,
                is_package=is_package,
                source_hash=_hash_source(source),
                source=source,
                tree=tree,
            )
            self.modules[name] = info
            self.path_index[rel] = info

        for info in self.modules.values():
            self._index_module(info)

    def _index_module(self, info: ModuleInfo) -> None:
        for node in info.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info.defs[node.name] = DefInfo(node.name, "function", node.lineno)
            elif isinstance(node, ast.ClassDef):
                info.defs[node.name] = DefInfo(node.name, "class", node.lineno)
                methods: dict[str, int] = {}
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods[sub.name] = sub.lineno
                info.classes[node.name] = methods
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    source_module = self._imported_module(alias.name)
                    info.imports[local] = ImportBinding(
                        local, "module", source_module, None, 0, node.lineno
                    )
            elif isinstance(node, ast.ImportFrom):
                base = self._resolve_relative(info, node.module or "", node.level)
                for alias in node.names:
                    local = alias.asname or alias.name
                    sub_name = f"{base}.{alias.name}" if base else alias.name
                    if base is None:
                        source_module, target = None, alias.name
                    elif sub_name in self.modules:
                        source_module, target = sub_name, None
                    elif base in self.modules:
                        source_module, target = base, alias.name
                    else:
                        source_module, target = None, alias.name
                    info.imports[local] = ImportBinding(
                        local, "symbol", source_module, target, node.level, node.lineno
                    )
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Name):
                    info.aliases[target.id] = node.value.id

    def _resolve_relative(self, info: ModuleInfo, module: str, level: int) -> Optional[str]:
        if level == 0:
            return module if module in self.modules else (module or None)
        base_parts = info.package.split(".") if info.package else []
        keep = len(base_parts) - (level - 1)
        if keep < 0:
            return None
        parts = base_parts[:keep]
        if module:
            parts.extend(module.split("."))
        resolved = ".".join(parts)
        return resolved

    def _imported_module(self, dotted: str) -> Optional[str]:
        if dotted in self.modules:
            return dotted
        head = dotted.split(".")[0]
        return head if head in self.modules else None

    # --------------------------------------------------------------- lookup
    def rel_path(self, path: str) -> str:
        return _rel_posix(path, self.root)

    def get_func_node(self, module_name: str, func_name: str) -> Optional[ast.AST]:
        info = self.modules.get(module_name)
        if info is None:
            return None
        for node in info.tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == func_name
            ):
                return node
        return None

    def get_method_node(self, module_name: str, class_name: str, method: str) -> Optional[ast.AST]:
        info = self.modules.get(module_name)
        if info is None or class_name not in info.classes:
            return None
        for node in info.tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == method:
                        return sub
        return None

    def resolve_name(self, module_name: str, name: str) -> tuple[str, Optional[str], Optional[str]]:
        """Resolve a bare name inside a module.

        Returns ``(kind, module_name, symbol)`` where kind is one of
        ``local``, ``import-module``, ``import-symbol``, ``alias`` or
        ``unresolved``.
        """
        info = self.modules.get(module_name)
        if info is None:
            return "unresolved", None, None
        if name in info.defs:
            return "local", module_name, name
        if name in info.imports:
            binding = info.imports[name]
            if binding.source_module is None:
                return "unresolved", None, None
            if binding.kind == "module":
                return "import-module", binding.source_module, None
            if binding.target_name:
                target_mod = binding.source_module
                sub = f"{target_mod}.{binding.target_name}"
                if sub in self.modules:
                    return "import-module", sub, None
                return "import-symbol", target_mod, binding.target_name
            return "import-module", binding.source_module, None
        if name in info.aliases:
            return "alias", module_name, info.aliases[name]
        return "unresolved", None, None

    def resolve_chain(self, module_name: str, name: str) -> tuple[str, Optional[str], Optional[str]]:
        seen: set[str] = set()
        current_mod, current_name = module_name, name
        while True:
            kind, mod, symbol = self.resolve_name(current_mod, current_name)
            if kind == "alias" and symbol not in seen:
                seen.add(symbol)
                current_name = symbol
                continue
            return kind, mod, symbol

    def find_symbol_module(self, module_name: str, symbol: str) -> Optional[str]:
        info = self.modules.get(module_name)
        if info and symbol in info.defs:
            return module_name
        return None
