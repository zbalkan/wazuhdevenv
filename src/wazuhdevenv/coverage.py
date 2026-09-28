"""Static coverage analysis for workspace Wazuh rules and tests."""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .errors import CoverageError

_XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


@dataclass(frozen=True)
class CoverageResult:
    defined_rule_ids: frozenset[str]
    referenced_rule_ids: frozenset[str]
    test_function_count: int

    @property
    def covered_rule_ids(self) -> frozenset[str]:
        return self.defined_rule_ids & self.referenced_rule_ids

    @property
    def uncovered_rule_ids(self) -> frozenset[str]:
        return self.defined_rule_ids - self.referenced_rule_ids

    @property
    def coverage_percent(self) -> float:
        if not self.defined_rule_ids:
            return 0.0
        return len(self.covered_rule_ids) / len(self.defined_rule_ids) * 100.0


def collect_rule_ids(rules_dir: Path) -> set[str]:
    if not rules_dir.is_dir():
        raise CoverageError(f"workspace rules directory not found: {rules_dir}")

    rule_ids: set[str] = set()
    for path in sorted(rules_dir.rglob("*.xml")):
        try:
            text = path.read_text(encoding="utf-8")
            text = _XML_DECLARATION.sub("", text, count=1)
            root = ET.fromstring(f"<wazuhdevenv>{text}</wazuhdevenv>")
        except (OSError, UnicodeError, ET.ParseError) as exc:
            raise CoverageError(f"cannot parse rule file {path}: {exc}") from exc

        for rule in root.iter("rule"):
            rule_id = rule.attrib.get("id")
            if rule_id:
                rule_ids.add(rule_id.strip())

    return rule_ids


def _literal_rule_id(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        value = str(node.value).strip()
        return value or None
    return None


def _is_rule_id_attribute(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "rule_id"


def _rule_ids_from_compare(node: ast.Compare) -> set[str]:
    found: set[str] = set()
    operands = [node.left, *node.comparators]
    for left, operator, right in zip(operands, node.ops, operands[1:]):
        if not isinstance(operator, ast.Eq):
            continue
        if _is_rule_id_attribute(left):
            value = _literal_rule_id(right)
            if value is not None:
                found.add(value)
        if _is_rule_id_attribute(right):
            value = _literal_rule_id(left)
            if value is not None:
                found.add(value)
    return found


def _rule_ids_from_assert_equal(node: ast.Call) -> set[str]:
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "assertEqual"
        and len(node.args) >= 2
    ):
        return set()

    left, right = node.args[:2]
    if _is_rule_id_attribute(left):
        value = _literal_rule_id(right)
        return {value} if value is not None else set()
    if _is_rule_id_attribute(right):
        value = _literal_rule_id(left)
        return {value} if value is not None else set()
    return set()


def _parametrize_argnames(node: ast.AST) -> list[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [name.strip() for name in node.value.split(",") if name.strip()]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                return None
            names.append(element.value)
        return names
    return None


def _parametrize_rows(node: ast.AST) -> list[list[ast.AST]] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None

    rows: list[list[ast.AST]] = []
    for row in node.elts:
        if isinstance(row, (ast.Tuple, ast.List)):
            rows.append(list(row.elts))
        elif (
            isinstance(row, ast.Call)
            and isinstance(row.func, ast.Attribute)
            and row.func.attr == "param"
        ):
            rows.append(list(row.args))
        else:
            return None
    return rows


def _rule_ids_from_parametrize(node: ast.Call) -> set[str]:
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "parametrize"
        and len(node.args) >= 2
    ):
        return set()

    names = _parametrize_argnames(node.args[0])
    if not names or "rule_id" not in names:
        return set()

    rows = _parametrize_rows(node.args[1])
    if rows is None:
        return set()

    index = names.index("rule_id")
    found: set[str] = set()
    for row in rows:
        if index >= len(row):
            continue
        value = _literal_rule_id(row[index])
        if value is not None:
            found.add(value)
    return found


def collect_test_references(tests_dir: Path) -> tuple[set[str], int]:
    if not tests_dir.is_dir():
        raise CoverageError(f"workspace tests directory not found: {tests_dir}")

    referenced: set[str] = set()
    test_function_count = 0

    for path in sorted(tests_dir.rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise CoverageError(f"cannot parse test file {path}: {exc}") from exc

        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and node.name.startswith("test_"):
                test_function_count += 1
            elif isinstance(node, ast.Compare):
                referenced.update(_rule_ids_from_compare(node))
            elif isinstance(node, ast.Call):
                referenced.update(_rule_ids_from_assert_equal(node))
                referenced.update(_rule_ids_from_parametrize(node))

    return referenced, test_function_count


def analyze_workspace(workspace: Path) -> CoverageResult:
    defined = collect_rule_ids(workspace / "rules")
    referenced, test_function_count = collect_test_references(workspace / "tests")
    return CoverageResult(
        defined_rule_ids=frozenset(defined),
        referenced_rule_ids=frozenset(referenced),
        test_function_count=test_function_count,
    )


def format_report(result: CoverageResult) -> str:
    lines = [
        "=== Wazuh Rule Coverage Report ===",
        f"Total rules defined: {len(result.defined_rule_ids)}",
        f"Total test functions: {result.test_function_count}",
        f"Rules referenced in tests: {len(result.referenced_rule_ids)}",
        f"Coverage: {result.coverage_percent:.2f}%",
    ]
    if result.uncovered_rule_ids:
        lines.extend(
            [
                "",
                "Uncovered Rule IDs:",
                *(
                    f"  - {rule_id}"
                    for rule_id in sorted(result.uncovered_rule_ids, key=_rule_sort_key)
                ),
            ]
        )
    return "\n".join(lines)


def _rule_sort_key(rule_id: str) -> tuple[int, int | str]:
    if rule_id.isascii() and rule_id.isdigit():
        return (0, int(rule_id))
    return (1, rule_id)
