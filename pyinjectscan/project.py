from __future__ import annotations

import ast
import hashlib
import io
import tokenize
from pathlib import Path

from .models import EventRecord, FunctionInfo, ModuleInfo, RouteEntry


ROUTE_DECORATOR_NAMES = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "trace",
    "api_route",
    "route",
    "websocket",
}


class Project:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[tuple[str, str], FunctionInfo] = {}
        self.parse_issues: list[EventRecord] = []
        self._dependency_cache: dict[str, tuple[str, ...]] = {}

    @property
    def relative_root(self) -> str:
        return self.root.as_posix()

    def discover(self) -> None:
        for path in sorted(self.root.rglob("*.py")):
            if self._is_excluded(path):
                continue
            self._load_file(path)
        for module in self.modules.values():
            for entry in module.routes:
                info = module.functions.get(entry.function)
                if info is not None:
                    entry.line = info.node.lineno
                    entry.column = info.node.col_offset
        self._build_imports()

    def _is_excluded(self, path: Path) -> bool:
        parts = set(path.relative_to(self.root).parts)
        return bool(parts & {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"})

    def _read_source(self, path: Path) -> str:
        try:
            with tokenize.open(path) as handle:
                return handle.read()
        except (UnicodeDecodeError, SyntaxError, LookupError):
            return path.read_text(encoding="utf-8-sig")

    def _load_file(self, path: Path) -> None:
        try:
            source = self._read_source(path)
        except OSError as exc:
            self.parse_issues.append(
                EventRecord(
                    file=path.relative_to(self.root).as_posix(),
                    line=1,
                    column=0,
                    function="<module>",
                    category="read_error",
                    message="文件无法读取，内容未分析。",
                    detail=str(exc),
                )
            )
            return
        relative = path.relative_to(self.root)
        module_name = self.module_name_for(relative)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        try:
            tree = ast.parse(source, filename=str(path), type_comments=False)
        except SyntaxError as exc:
            self.parse_issues.append(
                EventRecord(
                    file=relative.as_posix(),
                    line=exc.lineno or 1,
                    column=max((exc.offset or 1) - 1, 0),
                    function="<module>",
                    category="syntax_error",
                    message="语法错误，文件未分析。",
                    detail=exc.msg,
                )
            )
            return
        info = ModuleInfo(
            name=module_name,
            path=str(path),
            relative_path=relative.as_posix(),
            source=source,
            digest=digest,
            tree=tree,
            is_package=path.name == "__init__.py",
        )
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = FunctionInfo(module_name, node.name, node, info.relative_path)
                info.functions[node.name] = fn
                self.functions[(module_name, node.name)] = fn
                info.routes.extend(self._route_entries(info, node))
            elif isinstance(node, ast.ClassDef):
                info.classes.add(node.name)
        self.modules[module_name] = info

    @staticmethod
    def module_name_for(relative: Path) -> str:
        parts = list(relative.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _route_entries(self, module: ModuleInfo, node: ast.AST) -> list[RouteEntry]:
        entries: list[RouteEntry] = []
        for decorator in getattr(node, "decorator_list", []):
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if not isinstance(func, ast.Attribute) or func.attr not in ROUTE_DECORATOR_NAMES:
                continue
            path = "/"
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                if isinstance(decorator.args[0].value, str):
                    path = decorator.args[0].value
            for keyword in decorator.keywords:
                if keyword.arg == "path" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        path = keyword.value.value
            method = "GET" if func.attr in {"get", "api_route", "route", "websocket"} else func.attr.upper()
            if func.attr == "api_route":
                for keyword in decorator.keywords:
                    if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                        values = [
                            item.value
                            for item in keyword.value.elts
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)
                        ]
                        if values:
                            method = values[0].upper()
            entries.append(
                RouteEntry(
                    module=module.name,
                    function=node.name,
                    method=method,
                    path=path,
                    file=module.relative_path,
                    line=node.lineno,
                    column=node.col_offset,
                    route_line=decorator.lineno,
                )
            )
        return entries

    def _build_imports(self) -> None:
        for module in self.modules.values():
            module.imports = self.collect_import_targets(module.tree, module.name, module.is_package)

    def collect_import_targets(self, tree: ast.AST, module: str, is_package: bool) -> set[str]:
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    targets.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                target = self.resolve_from_module(
                    module=module,
                    is_package=is_package,
                    level=node.level,
                    imported=node.module,
                )
                if target is not None:
                    targets.add(target)
                for alias in node.names:
                    if alias.name != "*" and target is not None:
                        submodule = f"{target}.{alias.name}" if target else alias.name
                        if submodule in self.modules:
                            targets.add(submodule)
        return targets

    def resolve_from_module(
        self,
        module: str,
        is_package: bool,
        level: int,
        imported: str | None,
    ) -> str | None:
        if level == 0:
            return imported
        package = module if is_package else module.rpartition(".")[0]
        if not package and level > 0:
            return None
        parts = package.split(".") if package else []
        up = level - 1
        if up > len(parts):
            return None
        if up:
            parts = parts[:-up]
        if imported:
            parts.extend(imported.split("."))
        return ".".join(parts) if parts else ""

    def route_entries(self) -> list[RouteEntry]:
        entries = [entry for module in self.modules.values() for entry in module.routes]
        return sorted(entries, key=lambda item: (item.file, item.route_line, item.path, item.method))

    def module_digests(self) -> dict[str, str]:
        return {module.name: module.digest for module in self.modules.values()}

    def dependency_closure(self, module_name: str) -> tuple[str, ...]:
        cached = self._dependency_cache.get(module_name)
        if cached is not None:
            return cached
        pending = [module_name]
        seen: set[str] = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            module = self.modules.get(name)
            if module is None:
                continue
            for imported in sorted(module.imports):
                if imported.startswith(self.root_package_prefixes(name)) or imported in self.modules:
                    if imported not in seen:
                        pending.append(imported)
        result = tuple(sorted(seen))
        self._dependency_cache[module_name] = result
        return result

    def root_package_prefixes(self, current: str) -> tuple[str, ...]:
        top = current.split(".", 1)[0]
        return (top + ".",) if "." in current else ()

    def module_or_none(self, name: str) -> ModuleInfo | None:
        return self.modules.get(name)

    def submodule(self, parent: str, name: str) -> ModuleInfo | None:
        return self.modules.get(f"{parent}.{name}" if parent else name)

    def function(self, module: str, name: str) -> FunctionInfo | None:
        return self.functions.get((module, name))


def write_nothing(*args: object, **kwargs: object) -> None:
    """Compatibility marker kept intentionally empty."""
