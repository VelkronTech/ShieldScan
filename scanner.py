from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import threading
from typing import Any

import yaml
from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_python

from shieldscan.constants import DEFAULT_IGNORED_DIRS, SEVERITY_ORDER, detect_language


SUPPORTED_LANGUAGES = {"python", "javascript"}
_PARSER_TLS = threading.local()


@dataclass(frozen=True)
class Rule:
    id: str
    language: str
    vulnerability_type: str
    severity: str
    description: str
    node_types: tuple[str, ...]
    match_regex: str
    cwe: str | None = None
    confidence: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    file_path: Path
    line_number: int
    language: str
    vulnerability_type: str
    severity: str
    rule_id: str
    description: str
    cwe: str | None
    confidence: str | None
    remediation: str | None
    references: tuple[str, ...]


@dataclass(frozen=True)
class ScanSummary:
    files_scanned: int
    files_skipped: int
    findings: list[Finding]


class ScannerError(Exception):
    pass


def default_max_workers() -> int:
    return min(32, (os.cpu_count() or 1) * 2)


def _load_language() -> dict[str, Language]:
    # Wrap parser package handles for py-tree-sitter compatibility.
    return {
        "python": Language(tree_sitter_python.language()),
        "javascript": Language(tree_sitter_javascript.language()),
    }


def _new_parser(language: Language) -> Parser:
    try:
        return Parser(language)
    except TypeError:
        parser = Parser()
        parser.set_language(language)
        return parser


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_str_tuple(value: Any, index: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScannerError(f"Rule #{index} field 'references' must be a list[str]")
    return tuple(v.strip() for v in value if v.strip())


def load_rules(rules_file: Path) -> dict[str, list[Rule]]:
    if not rules_file.exists():
        raise ScannerError(f"Rules file not found: {rules_file}")

    try:
        data = yaml.safe_load(rules_file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScannerError(f"Invalid YAML in rules file: {rules_file}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ScannerError("Rules file must contain a top-level 'rules' list")

    rules_by_language: dict[str, list[Rule]] = {"python": [], "javascript": []}

    required_fields = {
        "id",
        "language",
        "vulnerability_type",
        "severity",
        "description",
        "node_types",
        "match_regex",
    }

    for index, raw_rule in enumerate(data["rules"], start=1):
        if not isinstance(raw_rule, dict):
            raise ScannerError(f"Rule #{index} is not an object")

        missing = required_fields - raw_rule.keys()
        if missing:
            raise ScannerError(f"Rule #{index} missing required fields: {sorted(missing)}")

        language = str(raw_rule["language"]).lower().strip()
        if language not in SUPPORTED_LANGUAGES:
            raise ScannerError(
                f"Rule #{index} has unsupported language '{language}'. Supported: {sorted(SUPPORTED_LANGUAGES)}"
            )

        node_types = raw_rule["node_types"]
        if not isinstance(node_types, list) or not all(isinstance(v, str) for v in node_types):
            raise ScannerError(f"Rule #{index} field 'node_types' must be a list[str]")

        severity = str(raw_rule["severity"]).lower().strip()
        if severity not in SEVERITY_ORDER:
            raise ScannerError(f"Rule #{index} has invalid severity '{severity}'")

        pattern = str(raw_rule["match_regex"])
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ScannerError(f"Rule #{index} has invalid regex: {pattern}") from exc

        rule = Rule(
            id=str(raw_rule["id"]),
            language=language,
            vulnerability_type=str(raw_rule["vulnerability_type"]),
            severity=severity,
            description=str(raw_rule["description"]),
            node_types=tuple(node_types),
            match_regex=pattern,
            cwe=_optional_str(raw_rule.get("cwe")),
            confidence=_optional_str(raw_rule.get("confidence")),
            remediation=_optional_str(raw_rule.get("remediation")),
            references=_optional_str_tuple(raw_rule.get("references"), index=index),
        )
        rules_by_language[language].append(rule)

    return rules_by_language


def _iter_files(target: Path) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0

    if target.is_file():
        language = detect_language(target)
        if language is None:
            return [], 1
        return [target], 0

    for path in target.rglob("*"):
        if not path.is_file():
            continue

        if any(part in DEFAULT_IGNORED_DIRS for part in path.parts):
            skipped += 1
            continue

        if detect_language(path) is None:
            skipped += 1
            continue

        files.append(path)

    return files, skipped


def _scan_ast_nodes(
    tree: Any,
    source_bytes: bytes,
    language: str,
    rules: list[Rule],
    file_path: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    compiled: list[tuple[Rule, re.Pattern[str]]] = [(rule, re.compile(rule.match_regex)) for rule in rules]

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)

        for rule, pattern in compiled:
            if node.type not in rule.node_types:
                continue

            snippet = source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")
            if not pattern.search(snippet):
                continue

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=node.start_point[0] + 1,
                    language=language,
                    vulnerability_type=rule.vulnerability_type,
                    severity=rule.severity,
                    rule_id=rule.id,
                    description=rule.description,
                    cwe=rule.cwe,
                    confidence=rule.confidence,
                    remediation=rule.remediation,
                    references=rule.references,
                )
            )

    return findings


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.severity, -1),
            str(item.file_path).lower(),
            item.line_number,
            item.rule_id,
        ),
    )


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "fingerprint": finding_fingerprint(finding),
        "file_path": str(finding.file_path),
        "line_number": finding.line_number,
        "language": finding.language,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity,
        "rule_id": finding.rule_id,
        "description": finding.description,
        "cwe": finding.cwe,
        "confidence": finding.confidence,
        "remediation": finding.remediation,
        "references": list(finding.references),
    }


def finding_fingerprint(finding: Finding) -> str:
    # Fingerprints let CI focus on new findings compared with a previous baseline report.
    raw = "|".join(
        [
            finding.rule_id,
            finding.language,
            str(finding.file_path).replace("\\", "/").lower(),
            str(finding.line_number),
            finding.vulnerability_type,
            finding.severity,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def summary_to_dict(summary: ScanSummary) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}
    for finding in summary.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    severity_counts_sorted = dict(
        sorted(severity_counts.items(), key=lambda kv: (-SEVERITY_ORDER.get(kv[0], -1), kv[0]))
    )

    return {
        "files_scanned": summary.files_scanned,
        "files_skipped": summary.files_skipped,
        "total_findings": len(summary.findings),
        "severity_counts": severity_counts_sorted,
        "findings": [finding_to_dict(f) for f in summary.findings],
    }


def _get_thread_parser(language_name: str, language_map: dict[str, Language]) -> Parser | None:
    cache = getattr(_PARSER_TLS, "parsers", None)
    if cache is None:
        cache = {}
        _PARSER_TLS.parsers = cache

    parser = cache.get(language_name)
    if parser is not None:
        return parser

    language = language_map.get(language_name)
    if language is None:
        return None

    parser = _new_parser(language)
    cache[language_name] = parser
    return parser


def _scan_file(
    file_path: Path,
    rules_by_language: dict[str, list[Rule]],
    language_map: dict[str, Language],
) -> tuple[int, int, list[Finding]]:
    language = detect_language(file_path)
    if language is None:
        return 0, 1, []

    parser = _get_thread_parser(language_name=language, language_map=language_map)
    rules = rules_by_language.get(language, [])
    if parser is None or not rules:
        return 0, 1, []

    try:
        source_bytes = file_path.read_bytes()
    except OSError:
        return 0, 1, []

    tree = parser.parse(source_bytes)
    findings = _scan_ast_nodes(
        tree=tree,
        source_bytes=source_bytes,
        language=language,
        rules=rules,
        file_path=file_path,
    )
    return 1, 0, findings


def scan_target(target: Path, rules_file: Path, max_workers: int | None = None) -> ScanSummary:
    if not target.exists():
        raise ScannerError(f"Target does not exist: {target}")

    language_map = _load_language()
    rules_by_language = load_rules(rules_file)
    files, skipped = _iter_files(target)

    findings: list[Finding] = []
    scanned = 0

    workers = default_max_workers() if max_workers is None else max_workers
    if workers < 1:
        raise ScannerError(f"max_workers must be >= 1, got {workers}")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_scan_file, file_path, rules_by_language, language_map) for file_path in files]
        for future in as_completed(futures):
            file_scanned, file_skipped, file_findings = future.result()
            scanned += file_scanned
            skipped += file_skipped
            findings.extend(file_findings)

    return ScanSummary(files_scanned=scanned, files_skipped=skipped, findings=_sort_findings(findings))
