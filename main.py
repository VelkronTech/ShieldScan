from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import yaml

from rich.console import Console
from rich.table import Table

from scanner import ScannerError, ScanSummary, default_max_workers, finding_fingerprint, scan_target, summary_to_dict


console = Console()
DEFAULT_CONFIG_FILES = (".shieldscan.yaml", ".shieldscan.yml")


def _load_config(path: Path | None) -> dict[str, Any]:
    if path is not None:
        if not path.exists():
            raise ScannerError(f"Config file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ScannerError(f"Invalid YAML in config file: {path}") from exc
        if not isinstance(data, dict):
            raise ScannerError("Config file must contain a top-level mapping")
        return data

    for name in DEFAULT_CONFIG_FILES:
        candidate = Path(name)
        if candidate.exists():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ScannerError(f"Invalid YAML in config file: {candidate}") from exc
            if not isinstance(data, dict):
                raise ScannerError("Config file must contain a top-level mapping")
            return data

    return {}


def _resolve_setting(cli_value: Any, config: dict[str, Any], key: str, default: Any) -> Any:
    if cli_value is not None:
        return cli_value
    return config.get(key, default)


def _load_baseline_fingerprints(path: Path) -> set[str]:
    if not path.exists():
        raise ScannerError(f"Baseline report not found: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Invalid JSON baseline report: {path}") from exc

    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ScannerError("Baseline report must contain a top-level findings list")

    fingerprints: set[str] = set()
    for finding in findings:
        if isinstance(finding, dict):
            value = finding.get("fingerprint")
            if isinstance(value, str) and value.strip():
                fingerprints.add(value.strip())

    return fingerprints


def _filter_new_findings(summary: ScanSummary, baseline_fingerprints: set[str]) -> ScanSummary:
    filtered = [f for f in summary.findings if finding_fingerprint(f) not in baseline_fingerprints]
    return replace(summary, findings=filtered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ShieldScan",
        description="Local multi-language static security scanner powered by Tree-sitter.",
    )

    parser.add_argument("target", nargs="?", type=Path, default=None, help="File or directory to scan (default: .)")
    parser.add_argument(
        "legacy_target",
        nargs="?",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Path to YAML rules file (default: rules/rules.yaml)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=f"Maximum concurrent worker threads (default: {default_max_workers()})",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default=None,
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON report path (only used with --format json)",
    )
    parser.add_argument(
        "--profile",
        choices=("local", "ci"),
        default=None,
        help="Execution profile. ci enforces json output, fail on findings, and supports baseline comparison",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Previous JSON report used to identify only new findings",
    )
    parser.add_argument(
        "--new-findings-only",
        action="store_true",
        default=None,
        help="Show only findings not present in baseline report (requires --baseline)",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        help="Write the current full JSON report to a baseline file",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional config file path (default auto-detects .shieldscan.yaml/.shieldscan.yml)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        default=None,
        help="Return exit code 1 when findings are detected (default: enabled)",
    )
    parser.add_argument(
        "--no-fail-on-findings",
        action="store_true",
        default=None,
        help="Always return exit code 0 even when findings exist",
    )

    return parser


def render_results(summary) -> None:
    table = Table(title="ShieldScan Findings", show_lines=False)
    table.add_column("File", style="cyan", overflow="fold")
    table.add_column("Line Number", justify="right")
    table.add_column("Language", style="magenta")
    table.add_column("Vulnerability Type", style="yellow")
    table.add_column("Rule ID", style="cyan")
    table.add_column("CWE", style="blue")
    table.add_column("Severity", style="bold")

    if not summary.findings:
        console.print("[green]No findings detected.[/green]")
    else:
        for finding in summary.findings:
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "orange3",
                "low": "green",
                "info": "cyan",
            }.get(finding.severity, "white")
            table.add_row(
                str(finding.file_path),
                str(finding.line_number),
                finding.language,
                finding.vulnerability_type,
                finding.rule_id,
                finding.cwe or "-",
                f"[{sev_style}]{finding.severity.upper()}[/]",
            )

        console.print(table)

    severity_counts = Counter(f.severity for f in summary.findings)
    sev_summary = ", ".join(f"{k}:{v}" for k, v in sorted(severity_counts.items())) or "none"
    console.print(
        f"\n[bold]Summary[/bold] scanned={summary.files_scanned} skipped={summary.files_skipped} findings={len(summary.findings)} severities={sev_summary}"
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = _load_config(args.config)

        if args.target is not None and str(args.target).lower() == "scan":
            target = args.legacy_target if args.legacy_target is not None else Path(config.get("target", "."))
        else:
            target = args.target if args.target is not None else Path(config.get("target", "."))

        rules = Path(_resolve_setting(args.rules, config, "rules", Path("rules") / "rules.yaml"))
        workers = _resolve_setting(args.workers, config, "workers", default_max_workers())
        output_format = _resolve_setting(args.format, config, "format", "table")
        output = _resolve_setting(args.output, config, "output", None)
        profile = _resolve_setting(args.profile, config, "profile", "local")
        baseline = _resolve_setting(args.baseline, config, "baseline", None)
        new_findings_only = _resolve_setting(args.new_findings_only, config, "new_findings_only", False)
        write_baseline = _resolve_setting(args.write_baseline, config, "write_baseline", None)

        cli_fail_on = True if args.fail_on_findings else None
        cli_no_fail_on = False if args.no_fail_on_findings else None
        fail_on_findings = _resolve_setting(
            cli_fail_on if cli_fail_on is not None else cli_no_fail_on,
            config,
            "fail_on_findings",
            True,
        )

        try:
            workers = int(workers)
        except (TypeError, ValueError) as exc:
            raise ScannerError("workers must be an integer") from exc

        if not isinstance(fail_on_findings, bool):
            raise ScannerError("fail_on_findings must be a boolean")

        if profile not in {"local", "ci"}:
            raise ScannerError("profile must be local or ci")

        if profile == "ci":
            output_format = "json"
            fail_on_findings = True

        if output_format not in {"table", "json"}:
            raise ScannerError(f"Unsupported format '{output_format}'. Allowed: table, json")

        if output is not None and output_format != "json":
            raise ScannerError("--output is only valid when format is json")

        if new_findings_only and baseline is None:
            raise ScannerError("--new-findings-only requires --baseline")

        summary = scan_target(target=target, rules_file=rules, max_workers=workers)

        if baseline is not None:
            baseline_path = Path(baseline)
            baseline_fingerprints = _load_baseline_fingerprints(baseline_path)
            if new_findings_only:
                summary = _filter_new_findings(summary, baseline_fingerprints)
    except ScannerError as exc:
        console.print(f"[bold red]Scanner error:[/bold red] {exc}")
        return 2

    payload = summary_to_dict(summary)

    if write_baseline is not None:
        baseline_out = Path(write_baseline)
        try:
            baseline_out.parent.mkdir(parents=True, exist_ok=True)
            baseline_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Wrote baseline:[/green] {baseline_out}")
        except OSError as exc:
            console.print(f"[bold red]Failed to write baseline:[/bold red] {exc}")
            return 2

    if output_format == "json":
        text = json.dumps(payload, indent=2)
        if output is None:
            console.print(text)
        else:
            output_path = Path(output)
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(text + "\n", encoding="utf-8")
                console.print(f"[green]Wrote JSON report:[/green] {output_path}")
            except OSError as exc:
                console.print(f"[bold red]Failed to write output:[/bold red] {exc}")
                return 2
    else:
        render_results(summary)

    if fail_on_findings and summary.findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
