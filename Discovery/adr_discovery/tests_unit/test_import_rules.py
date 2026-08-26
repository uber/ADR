"""The rules that make the package modular, checked against the code.

Every other guarantee in this design is a claim about intent. This one is a
claim about the code: it walks the import graph, runs in well under a
second, and fails on the pull request that would have reintroduced the
problem the rewrite exists to remove.
"""

from __future__ import annotations

import ast
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.abspath(os.path.join(HERE, ".."))

STAGES = ("world", "enumerator", "extractor", "identifier", "resolver", "judge", "reporter")
CROSS_CUTTING = ("catalog", "redact", "coverage")
BASE = ("contracts",)

#: Modules that reach the operating system directly.
HOST_MODULES = {"os", "os.path", "pathlib", "subprocess", "socket", "shutil", "glob"}

#: `world/` is the door. `cli.py` is the process boundary -- it owns argv,
#: stdout, the exit code and the output file, none of which are the machine
#: under inventory. Nothing else may touch the host, and the test asserts
#: this list stays exactly two entries long.
HOST_ALLOWED = ("world", "cli.py")


def _modules():
    for dirpath, dirnames, filenames in os.walk(PACKAGE):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", "tests_unit"}]
        for name in filenames:
            if name.endswith(".py"):
                full = os.path.join(dirpath, name)
                yield os.path.relpath(full, PACKAGE), full


def _imports(path: str):
    """(module, is_relative, level) for every import in the file."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, False, 0
        elif isinstance(node, ast.ImportFrom):
            yield (node.module or ""), node.level > 0, node.level


def _top_package(rel: str) -> str:
    return rel.split(os.sep)[0]


def _resolved_target(rel: str, module: str, level: int) -> str:
    """Which top-level package a relative import points at."""
    parts = rel.split(os.sep)[:-1]
    base = parts[: len(parts) - (level - 1)] if level > 1 else parts
    return (base + module.split("."))[0] if (base or module) else ""


# --------------------------------------------------------------------------


def test_only_world_touches_the_host():
    offenders = []
    for rel, full in _modules():
        top = _top_package(rel)
        if top in HOST_ALLOWED or rel in HOST_ALLOWED:
            continue
        for module, is_relative, _ in _imports(full):
            if is_relative:
                continue
            if module in HOST_MODULES or module.split(".")[0] in HOST_MODULES:
                offenders.append(f"{rel} imports {module}")
    assert not offenders, "only world/ may touch the host:\n  " + "\n  ".join(offenders)


def test_host_exemption_list_has_not_grown():
    # A rule whose exemption list can grow silently is not a rule.
    assert HOST_ALLOWED == ("world", "cli.py")


def test_no_stage_imports_a_sibling_stage():
    offenders = []
    for rel, full in _modules():
        top = _top_package(rel)
        if top not in STAGES:
            continue
        for module, is_relative, level in _imports(full):
            target = _resolved_target(rel, module, level) if is_relative else module.split(".")[0]
            if target in STAGES and target != top:
                offenders.append(f"{rel} imports stage {target}")
    assert not offenders, "a stage imported a sibling:\n  " + "\n  ".join(offenders)


def test_only_the_pipeline_imports_more_than_one_stage():
    offenders = []
    for rel, full in _modules():
        if rel in ("pipeline.py", "cli.py") or _top_package(rel) in STAGES:
            continue
        touched = set()
        for module, is_relative, level in _imports(full):
            target = _resolved_target(rel, module, level) if is_relative else module.split(".")[0]
            if target in STAGES:
                touched.add(target)
        if len(touched) > 1:
            offenders.append(f"{rel} imports {sorted(touched)}")
    assert not offenders, "order must live in pipeline.py alone:\n  " + "\n  ".join(offenders)


def test_catalog_imports_nothing_from_the_package():
    package_names = set(STAGES) | set(CROSS_CUTTING) | set(BASE) | {"pipeline", "cli"}
    offenders = []
    for rel, full in _modules():
        if _top_package(rel) != "catalog":
            continue
        for module, is_relative, level in _imports(full):
            if is_relative and _resolved_target(rel, module, level) != "catalog":
                offenders.append(f"{rel} imports {module or '..'}")
            elif not is_relative and module.split(".")[0] in package_names:
                offenders.append(f"{rel} imports {module}")
    assert not offenders, (
        "the catalog ships on its own cadence and may not depend on the collector:\n  "
        + "\n  ".join(offenders)
    )


def test_no_stage_holds_mutable_module_level_state():
    """`PROJECT_ROOTS` in five files is the defect this rewrite exists for.

    Module-level containers are allowed only if immutable, so a stage cannot
    accumulate state between runs or disagree with a sibling about a value.
    """
    offenders = []
    for rel, full in _modules():
        if _top_package(rel) not in STAGES:
            continue
        with open(full, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), full)
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [
                    t.id for t in targets
                    if isinstance(t, ast.Name) and t.id != "__all__"  # module protocol, not state
                ]
                offenders.extend(f"{rel}: {n} is a mutable module-level container" for n in names)
    assert not offenders, "\n  ".join(offenders)
