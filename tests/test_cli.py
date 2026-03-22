from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_PY = PROJECT_ROOT / "main.py"
SAMPLE_PY = PROJECT_ROOT / "sample_vulnerable.py"
SAMPLE_JS = PROJECT_ROOT / "sample_vulnerable.js"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(MAIN_PY), *args]
    return subprocess.run(cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, check=False)


def test_cli_json_output_file(tmp_path: Path) -> None:
    out = tmp_path / "scan.json"
    proc = _run_cli(str(SAMPLE_JS), "--format", "json", "--output", str(out), "--no-fail-on-findings")

    assert proc.returncode == 0
    assert out.exists()

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["total_findings"] >= 1
    assert "findings" in payload


def test_cli_ci_profile_returns_nonzero_for_findings(tmp_path: Path) -> None:
    out = tmp_path / "ci.json"
    proc = _run_cli(str(SAMPLE_PY), "--profile", "ci", "--output", str(out))

    assert proc.returncode == 1
    assert out.exists()


def test_cli_baseline_new_findings_only(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    out_new = tmp_path / "new_only.sarif"

    create_baseline = _run_cli(
        str(SAMPLE_PY),
        "--format",
        "json",
        "--write-baseline",
        str(baseline),
        "--output",
        str(tmp_path / "full.json"),
        "--no-fail-on-findings",
    )
    assert create_baseline.returncode == 0
    assert baseline.exists()

    proc = _run_cli(
        str(SAMPLE_PY),
        "--baseline",
        str(baseline),
        "--new-findings-only",
        "--profile",
        "ci",
        "--output",
        str(out_new),
    )
    assert proc.returncode == 0

    payload = json.loads(out_new.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []


def test_cli_safe_file_returns_zero(tmp_path: Path) -> None:
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("print('ok')\n", encoding="utf-8")

    proc = _run_cli(str(safe_file), "--format", "json", "--output", str(tmp_path / "safe.json"))
    assert proc.returncode == 0


def test_cli_suppression_ignore_file_reduces_findings(tmp_path: Path) -> None:
    ignore_file = tmp_path / "ignore.yaml"
    out_file = tmp_path / "suppressed.json"
    ignore_file.write_text(
        "suppressions:\n"
        "  - rule_id: \"PY001\"\n"
        "    path_glob: \"*sample_vulnerable.py\"\n"
        "    expires_on: \"2099-12-31\"\n",
        encoding="utf-8",
    )

    proc = _run_cli(
        str(SAMPLE_PY),
        "--format",
        "json",
        "--ignore-file",
        str(ignore_file),
        "--output",
        str(out_file),
        "--no-fail-on-findings",
    )

    assert proc.returncode == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["total_findings"] == 1
    assert payload["suppressed_findings"] == 1


def test_cli_sarif_output_file(tmp_path: Path) -> None:
    out = tmp_path / "scan.sarif"
    proc = _run_cli(str(SAMPLE_JS), "--format", "sarif", "--output", str(out), "--no-fail-on-findings")

    assert proc.returncode == 0
    assert out.exists()

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"]
    assert payload["runs"][0]["results"]


def test_cli_include_exclude_filters(tmp_path: Path) -> None:
    out = tmp_path / "filtered.json"
    proc = _run_cli(
        str(PROJECT_ROOT),
        "--format",
        "json",
        "--include",
        "*sample_vulnerable.py",
        "--exclude",
        "*sample_vulnerable.py",
        "--output",
        str(out),
        "--no-fail-on-findings",
    )

    assert proc.returncode == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["total_findings"] == 0
