from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import fnmatch
import hashlib
import json
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
CACHE_VERSION = 1


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
    match_mode: str = "regex"


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
            match_mode=str(raw_rule.get("match_mode", "regex")).strip().lower(),
        )
        rules_by_language[language].append(rule)

    return rules_by_language


def _iter_files(target: Path) -> tuple[list[Path], int]:
    return _iter_files_with_filters(target=target, include_patterns=None, exclude_patterns=None)


def _normalize_patterns(patterns: list[str] | None) -> list[str]:
    if not patterns:
        return []
    return [p.strip().replace("\\", "/") for p in patterns if p and p.strip()]


def _path_matches_any_pattern(path_text: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    return any(fnmatch.fnmatch(path_text, pattern) for pattern in patterns)


def _iter_files_with_filters(
    target: Path,
    include_patterns: list[str] | None,
    exclude_patterns: list[str] | None,
) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    include = _normalize_patterns(include_patterns)
    exclude = _normalize_patterns(exclude_patterns)

    if target.is_file():
        language = detect_language(target)
        if language is None:
            return [], 1
        rel = target.name.replace("\\", "/")
        if include and not _path_matches_any_pattern(rel, include):
            return [], 1
        if _path_matches_any_pattern(rel, exclude):
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

        rel = str(path.relative_to(target)).replace("\\", "/")
        if include and not _path_matches_any_pattern(rel, include):
            skipped += 1
            continue
        if _path_matches_any_pattern(rel, exclude):
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
            matches = _rule_matches(rule=rule, snippet=snippet, pattern=pattern)
            if not matches:
                continue

            confidence = _derive_confidence(rule=rule, snippet=snippet)

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
                    confidence=confidence,
                    remediation=rule.remediation,
                    references=rule.references,
                )
            )

    return findings


def _rule_matches(rule: Rule, snippet: str, pattern: re.Pattern[str]) -> bool:
    if rule.match_mode == "semantic":
        return _semantic_match(rule=rule, snippet=snippet)
    return bool(pattern.search(snippet))


def _semantic_match(rule: Rule, snippet: str) -> bool:
    normalized = snippet.replace("\n", " ").replace("\r", " ").strip()

    if rule.id == "PY001":
        return _python_named_bool_arg_match(
            call_text=normalized,
            callees={"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"},
            arg_name="verify",
            expected_false=True,
        )

    if rule.id == "PY002":
        return _python_named_bool_arg_match(
            call_text=normalized,
            callees={
                "subprocess.run",
                "subprocess.popen",
                "subprocess.call",
                "subprocess.check_output",
                "subprocess.check_call",
            },
            arg_name="shell",
            expected_false=False,
        )

    if rule.id == "JS001":
        callee = _extract_js_callee(normalized)
        return callee in {"eval", "window.eval", "global.eval", "globalThis.eval"}

    if rule.id == "JS002":
        callee = _extract_js_callee(normalized)
        return callee in {"child_process.exec", "cp.exec"}

    return bool(re.search(rule.match_regex, normalized))


def _extract_python_callee(call_text: str) -> str | None:
    match = re.match(r"\s*([A-Za-z_][\w\.]*)\s*\(", call_text)
    if not match:
        return None
    return match.group(1).lower()


def _extract_js_callee(call_text: str) -> str | None:
    match = re.match(r"\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(", call_text)
    if not match:
        return None
    return match.group(1)


def _python_named_bool_arg_match(call_text: str, callees: set[str], arg_name: str, expected_false: bool) -> bool:
    callee = _extract_python_callee(call_text)
    if callee is None:
        return False
    if callee not in callees:
        return False

    arg_match = re.search(rf"\b{re.escape(arg_name)}\s*=\s*([A-Za-z_][\w]*)", call_text)
    if not arg_match:
        return False

    token = arg_match.group(1).strip().lower()
    if expected_false:
        return token == "false"
    return token == "true"


def _derive_confidence(rule: Rule, snippet: str) -> str | None:
    if rule.match_mode == "semantic":
        return rule.confidence or "high"

    if rule.confidence is not None:
        return rule.confidence

    # Regex-only rules without explicit confidence default to medium to avoid over-claiming precision.
    return "medium"


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


def _severity_to_sarif_level(severity: str) -> str:
    normalized = severity.lower().strip()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def summary_to_sarif(summary: ScanSummary, tool_name: str = "ShieldScan", tool_version: str = "0.2.0") -> dict[str, Any]:
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in summary.findings:
        if finding.rule_id not in rules_by_id:
            rule_entry: dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.vulnerability_type,
                "shortDescription": {"text": finding.description},
                "properties": {
                    "tags": [finding.language, finding.severity],
                    "problem.severity": finding.severity,
                    "precision": finding.confidence or "medium",
                },
            }
            if finding.cwe:
                rule_entry["properties"]["cwe"] = finding.cwe
            rules_by_id[finding.rule_id] = rule_entry

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {
                "text": f"{finding.vulnerability_type}: {finding.description}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.file_path).replace('\\\\', '/')},
                        "region": {"startLine": finding.line_number},
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding_fingerprint(finding),
            },
            "properties": {
                "severity": finding.severity,
                "language": finding.language,
                "confidence": finding.confidence,
                "cwe": finding.cwe,
                "remediation": finding.remediation,
                "references": list(finding.references),
            },
        }
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": sorted(rules_by_id.values(), key=lambda r: r["id"]),
                    }
                },
                "results": results,
            }
        ],
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
) -> tuple[Path, int, int, list[Finding]]:
    language = detect_language(file_path)
    if language is None:
        return file_path, 0, 1, []

    parser = _get_thread_parser(language_name=language, language_map=language_map)
    rules = rules_by_language.get(language, [])
    if parser is None or not rules:
        return file_path, 0, 1, []

    try:
        source_bytes = file_path.read_bytes()
    except OSError:
        return file_path, 0, 1, []

    tree = parser.parse(source_bytes)
    findings = _scan_ast_nodes(
        tree=tree,
        source_bytes=source_bytes,
        language=language,
        rules=rules,
        file_path=file_path,
    )
    return file_path, 1, 0, findings


def _serialize_finding_for_cache(finding: Finding) -> dict[str, Any]:
    return {
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


def _deserialize_finding_from_cache(payload: dict[str, Any]) -> Finding:
    refs = payload.get("references", [])
    if not isinstance(refs, list):
        refs = []
    return Finding(
        file_path=Path(str(payload.get("file_path", ""))),
        line_number=int(payload.get("line_number", 1)),
        language=str(payload.get("language", "unknown")),
        vulnerability_type=str(payload.get("vulnerability_type", "Unknown")),
        severity=str(payload.get("severity", "info")),
        rule_id=str(payload.get("rule_id", "UNKNOWN")),
        description=str(payload.get("description", "")),
        cwe=payload.get("cwe") if isinstance(payload.get("cwe"), str) or payload.get("cwe") is None else None,
        confidence=payload.get("confidence")
        if isinstance(payload.get("confidence"), str) or payload.get("confidence") is None
        else None,
        remediation=payload.get("remediation")
        if isinstance(payload.get("remediation"), str) or payload.get("remediation") is None
        else None,
        references=tuple(str(v) for v in refs),
    )


def _rules_digest(rules_by_language: dict[str, list[Rule]]) -> str:
    payload: dict[str, list[dict[str, Any]]] = {}
    for language, rules in sorted(rules_by_language.items(), key=lambda item: item[0]):
        payload[language] = []
        for rule in sorted(rules, key=lambda r: r.id):
            payload[language].append(
                {
                    "id": rule.id,
                    "match_mode": rule.match_mode,
                    "match_regex": rule.match_regex,
                    "node_types": list(rule.node_types),
                    "severity": rule.severity,
                    "vulnerability_type": rule.vulnerability_type,
                }
            )
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_cache(cache_file: Path) -> dict[str, Any]:
    if not cache_file.exists():
        return {"version": CACHE_VERSION, "rules_digest": "", "files": {}}

    try:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": CACHE_VERSION, "rules_digest": "", "files": {}}

    if not isinstance(payload, dict):
        return {"version": CACHE_VERSION, "rules_digest": "", "files": {}}

    if payload.get("version") != CACHE_VERSION:
        return {"version": CACHE_VERSION, "rules_digest": "", "files": {}}

    files = payload.get("files")
    if not isinstance(files, dict):
        files = {}

    digest = payload.get("rules_digest")
    if not isinstance(digest, str):
        digest = ""

    return {"version": CACHE_VERSION, "rules_digest": digest, "files": files}


def _save_cache(cache_file: Path, payload: dict[str, Any]) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def scan_target(
    target: Path,
    rules_file: Path,
    max_workers: int | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    incremental: bool = False,
    cache_file: Path | None = None,
) -> ScanSummary:
    if not target.exists():
        raise ScannerError(f"Target does not exist: {target}")

    language_map = _load_language()
    rules_by_language = load_rules(rules_file)
    files, skipped = _iter_files_with_filters(
        target=target,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )

    findings: list[Finding] = []
    scanned = 0

    workers = default_max_workers() if max_workers is None else max_workers
    if workers < 1:
        raise ScannerError(f"max_workers must be >= 1, got {workers}")

    normalized_cache_file = cache_file if cache_file is not None else Path(".shieldscan-cache.json")
    rules_digest = _rules_digest(rules_by_language)
    cached_payload = _load_cache(normalized_cache_file) if incremental else {"version": CACHE_VERSION, "rules_digest": "", "files": {}}
    cached_files = cached_payload.get("files", {}) if cached_payload.get("rules_digest") == rules_digest else {}

    pending_files: list[Path] = []
    next_cache_files: dict[str, Any] = {}

    for file_path in files:
        cache_key = str(file_path.resolve()).replace("\\", "/")
        if incremental:
            try:
                st = file_path.stat()
            except OSError:
                pending_files.append(file_path)
                continue

            existing = cached_files.get(cache_key)
            if isinstance(existing, dict):
                cached_mtime = existing.get("mtime_ns")
                cached_size = existing.get("size")
                cached_findings = existing.get("findings")
                if (
                    isinstance(cached_mtime, int)
                    and isinstance(cached_size, int)
                    and cached_mtime == st.st_mtime_ns
                    and cached_size == st.st_size
                    and isinstance(cached_findings, list)
                ):
                    scanned += 1
                    parsed = [
                        _deserialize_finding_from_cache(item)
                        for item in cached_findings
                        if isinstance(item, dict)
                    ]
                    findings.extend(parsed)
                    next_cache_files[cache_key] = {
                        "mtime_ns": st.st_mtime_ns,
                        "size": st.st_size,
                        "findings": cached_findings,
                    }
                    continue

        pending_files.append(file_path)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_scan_file, file_path, rules_by_language, language_map)
            for file_path in pending_files
        ]
        for future in as_completed(futures):
            scanned_file_path, file_scanned, file_skipped, file_findings = future.result()
            scanned += file_scanned
            skipped += file_skipped
            findings.extend(file_findings)

            if incremental and file_scanned:
                try:
                    st = scanned_file_path.stat()
                except OSError:
                    continue

                cache_key = str(scanned_file_path.resolve()).replace("\\", "/")
                next_cache_files[cache_key] = {
                    "mtime_ns": st.st_mtime_ns,
                    "size": st.st_size,
                    "findings": [_serialize_finding_for_cache(item) for item in file_findings],
                }

    if incremental:
        _save_cache(
            normalized_cache_file,
            {
                "version": CACHE_VERSION,
                "rules_digest": rules_digest,
                "files": next_cache_files,
            },
        )

    return ScanSummary(files_scanned=scanned, files_skipped=skipped, findings=_sort_findings(findings))
