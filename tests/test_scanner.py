from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner import (
    Finding,
    ScannerError,
    finding_fingerprint,
    load_rules,
    scan_target,
    summary_to_dict,
    summary_to_sarif,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = PROJECT_ROOT / "rules" / "rules.yaml"
SAMPLE_PY = PROJECT_ROOT / "sample_vulnerable.py"


def test_load_rules_success() -> None:
    rules_by_lang = load_rules(RULES_FILE)

    assert "python" in rules_by_lang
    assert "javascript" in rules_by_lang
    assert len(rules_by_lang["python"]) >= 2
    assert len(rules_by_lang["javascript"]) >= 2

    py_rule = rules_by_lang["python"][0]
    assert py_rule.cwe is not None
    assert py_rule.confidence is not None
    assert isinstance(py_rule.references, tuple)
    assert py_rule.match_mode == "semantic"


def test_scan_summary_contains_fingerprints() -> None:
    summary = scan_target(SAMPLE_PY, RULES_FILE, max_workers=1)
    payload = summary_to_dict(summary)

    assert payload["total_findings"] == 2
    assert "suppressed_findings" not in payload
    assert len(payload["findings"]) == 2
    for item in payload["findings"]:
        assert "fingerprint" in item
        assert isinstance(item["fingerprint"], str)
        assert len(item["fingerprint"]) == 16


def test_finding_fingerprint_is_stable() -> None:
    finding = Finding(
        file_path=Path("x.py"),
        line_number=10,
        language="python",
        vulnerability_type="Command Injection Risk",
        severity="critical",
        rule_id="PY002",
        description="desc",
        cwe="CWE-78",
        confidence="high",
        remediation="fix",
        references=("https://example.com",),
    )

    assert finding_fingerprint(finding) == finding_fingerprint(finding)


def test_scan_target_rejects_invalid_workers() -> None:
    with pytest.raises(ScannerError, match="max_workers must be >= 1"):
        scan_target(SAMPLE_PY, RULES_FILE, max_workers=0)


def test_summary_to_sarif_contains_results() -> None:
    summary = scan_target(SAMPLE_PY, RULES_FILE, max_workers=1)
    sarif = summary_to_sarif(summary)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"]
    assert sarif["runs"][0]["results"]


def test_scan_include_exclude_filters() -> None:
    summary_included = scan_target(
        target=PROJECT_ROOT,
        rules_file=RULES_FILE,
        max_workers=1,
        include_patterns=["*sample_vulnerable.py"],
    )
    assert len(summary_included.findings) == 2

    summary_excluded = scan_target(
        target=PROJECT_ROOT,
        rules_file=RULES_FILE,
        max_workers=1,
        include_patterns=["*sample_vulnerable.py"],
        exclude_patterns=["*sample_vulnerable.py"],
    )
    assert len(summary_excluded.findings) == 0


def test_incremental_cache_file_created(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"

    first = scan_target(
        target=SAMPLE_PY,
        rules_file=RULES_FILE,
        max_workers=1,
        incremental=True,
        cache_file=cache_file,
    )
    second = scan_target(
        target=SAMPLE_PY,
        rules_file=RULES_FILE,
        max_workers=1,
        incremental=True,
        cache_file=cache_file,
    )

    assert len(first.findings) == 2
    assert len(second.findings) == 2
    assert cache_file.exists()

    payload = json.loads(cache_file.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert "files" in payload
