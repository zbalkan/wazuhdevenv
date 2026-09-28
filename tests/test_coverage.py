from __future__ import annotations

from pathlib import Path

import pytest

from wazuhdevenv.coverage import (  # type: ignore
    analyze_workspace,
    collect_rule_ids,
    collect_test_references,
    format_report,
)
from wazuhdevenv.errors import CoverageError  # type: ignore


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / "rules").mkdir(parents=True)
    (workspace / "tests").mkdir()
    return workspace


def test_analyze_workspace_finds_direct_and_parametrized_pytest_rule_ids(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    (workspace / "rules/custom.xml").write_text(
        """
<group name="custom">
  <rule id="100100" level="3"><description>one</description></rule>
  <rule id="100101" level="3"><description>two</description></rule>
  <rule id="100102" level="3"><description>three</description></rule>
</group>
""",
        encoding="utf-8",
    )
    (workspace / "tests/test_rules.py").write_text(
        """
import pytest

def test_direct(send_log):
    response = send_log("one")
    assert response.rule_id == "100100"

@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param("two", "custom", "100101", 3),
    ],
)
def test_parametrized(send_log, log, decoder, rule_id, rule_level):
    response = send_log(log)
    assert response.rule_id == rule_id
""",
        encoding="utf-8",
    )

    result = analyze_workspace(workspace)

    assert result.defined_rule_ids == frozenset({"100100", "100101", "100102"})
    assert result.referenced_rule_ids == frozenset({"100100", "100101"})
    assert result.test_function_count == 2
    assert result.uncovered_rule_ids == frozenset({"100102"})
    assert result.coverage_percent == pytest.approx(200 / 3)


def test_collect_test_references_supports_reverse_compare_and_unittest(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_mixed.py").write_text(
        """
def test_reverse(send_log):
    response = send_log("one")
    assert "222000" == response.rule_id

class Legacy:
    def test_old(self):
        response = object()
        self.assertEqual(response.rule_id, "222001")
""",
        encoding="utf-8",
    )

    referenced, count = collect_test_references(tests)

    assert referenced == {"222000", "222001"}
    assert count == 2


def test_parametrize_accepts_comma_separated_argnames(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_param.py").write_text(
        """
import pytest

@pytest.mark.parametrize(
    "log,rule_id",
    [
        ("one", "300001"),
        ("two", "300002"),
    ],
)
def test_rules(log, rule_id):
    pass
""",
        encoding="utf-8",
    )

    referenced, count = collect_test_references(tests)

    assert referenced == {"300001", "300002"}
    assert count == 1


def test_non_equality_rule_id_comparisons_do_not_count_as_coverage(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_comparisons.py").write_text(
        """
def test_comparisons(response):
    assert response.rule_id != "400001"
    assert response.rule_id < "400002"
    assert "400003" > response.rule_id
    assert "400004" == response.rule_id != "400005"
""",
        encoding="utf-8",
    )

    referenced, count = collect_test_references(tests)

    assert referenced == {"400004"}
    assert count == 1


def test_unrelated_literals_are_not_counted_as_rule_ids(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_noise.py").write_text(
        """
def test_noise():
    expected = "999999"
    assert expected == "999999"
""",
        encoding="utf-8",
    )

    referenced, count = collect_test_references(tests)

    assert referenced == set()
    assert count == 1


def test_rule_files_may_contain_xml_declaration(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "declared.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<group><rule id="410" level="1"/></group>\n',
        encoding="utf-8",
    )

    assert collect_rule_ids(rules) == {"410"}


def test_malformed_rule_file_fails_instead_of_underreporting(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    path = rules / "broken.xml"
    path.write_text('<group><rule id="410"></group>', encoding="utf-8")

    with pytest.raises(CoverageError, match="cannot parse rule file"):
        collect_rule_ids(rules)


def test_malformed_test_file_fails_instead_of_underreporting(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_broken.py").write_text("def test_broken(:\n", encoding="utf-8")

    with pytest.raises(CoverageError, match="cannot parse test file"):
        collect_test_references(tests)


def test_format_report_matches_original_coverage_semantics(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    (workspace / "rules/custom.xml").write_text(
        '<group><rule id="222000" level="3"/><rule id="222016" level="3"/></group>',
        encoding="utf-8",
    )
    (workspace / "tests/test_custom.py").write_text(
        'def test_one(response):\n    assert response.rule_id == "222000"\n',
        encoding="utf-8",
    )

    report = format_report(analyze_workspace(workspace))

    assert "Total rules defined: 2" in report
    assert "Total test functions: 1" in report
    assert "Rules referenced in tests: 1" in report
    assert "Coverage: 50.00%" in report
    assert "  - 222016" in report
