"""Static sanity check for intra-package imports.

Hassfest and HACS only look at file layout, not at whether the names a module
imports from a sibling module actually exist. A rename that misses one import
therefore ships fine and then fails at runtime with ``ImportError``. This script
parses every module of the integration and verifies that each
``from .module import name`` resolves to a name defined there.
"""

from __future__ import annotations

import ast
import pathlib
import sys

PKG = pathlib.Path("custom_components/ha_ssl")


def exported_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            # module-level assignments, including ones inside try/except
            names.add(node.id)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return names


def main() -> int:
    if not PKG.is_dir():
        print(f"[import-check] package not found: {PKG}")
        return 1

    exported = {p.stem: exported_names(p) for p in PKG.glob("*.py")}
    problems: list[str] = []

    for path in PKG.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.level != 1 or not node.module:
                continue
            source = exported.get(node.module)
            if source is None:
                continue
            for alias in node.names:
                if alias.name != "*" and alias.name not in source:
                    problems.append(
                        f"{path.name}: from .{node.module} import {alias.name} "
                        f"(not defined in {node.module}.py)"
                    )

    if problems:
        print("[import-check] FAIL")
        for problem in problems:
            print("  - " + problem)
        return 1

    print(f"[import-check] OK ({len(exported)} modules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
