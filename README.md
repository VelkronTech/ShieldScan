# ShieldScan MVP

ShieldScan is a local, CPU-friendly security scanner for Python and JavaScript codebases.

## Project Structure

```text
shieldscan/
  main.py
  scanner.py
  requirements.txt
  README.md
  rules/
    rules.yaml
  shieldscan/
    __init__.py
    constants.py
```

## Install

```powershell
cd c:\VelkronTech\shieldscan
python -m pip install --upgrade pip
python -m pip install -e .
```

or install globally with `pipx`:

```powershell
pipx install .
```

## Usage

```powershell
shieldscan <directory_or_file>
shieldscan .
shieldscan <directory_or_file> --rules rules\rules.yaml
shieldscan <directory_or_file> --workers 8
shieldscan <directory_or_file> --format json
shieldscan <directory_or_file> --format json --output reports\scan-report.json
shieldscan <directory_or_file> --format sarif --output reports\scan.sarif
shieldscan <directory_or_file> --include "src/**/*.py" --exclude "tests/**"
shieldscan <directory_or_file> --incremental --cache-file .shieldscan-cache.json
shieldscan <directory_or_file> --profile ci --output reports\ci-report.sarif
shieldscan <directory_or_file> --write-baseline reports\baseline.json
shieldscan <directory_or_file> --baseline reports\baseline.json --new-findings-only --profile ci --output reports\new-only.json
shieldscan <directory_or_file> --ignore-file .shieldscanignore.yaml
```

Legacy compatibility is still accepted:

```powershell
python main.py scan <directory_or_file>
```

### Output modes

- `--format table` (default): Rich table output in terminal.
- `--format json`: machine-readable JSON report.
- `--format sarif`: SARIF 2.1.0 report for code scanning platforms.
- `--output <path>`: write JSON/SARIF report to file (with `--format json` or `--format sarif`). If omitted, output is printed to stdout.

### Exit code behavior

- Default behavior: returns `1` when findings are detected.
- Returns `0` when no findings are detected.
- Use `--no-fail-on-findings` to force success exit code.

### CI profile and baseline workflow

- `--profile ci` forces SARIF output and fail-on-findings behavior.
- `--write-baseline <path>` writes a baseline report with finding fingerprints.
- `--baseline <path> --new-findings-only` filters output to only findings not present in the baseline.
- This is useful for PR gating on newly introduced security issues.

### GitHub code scanning (SARIF)

- CI writes SARIF at `reports/shieldscan.sarif`.
- GitHub Actions uploads SARIF using `github/codeql-action/upload-sarif`.
- Findings appear in the repository Security tab and pull request checks.

### Threaded scanning

- Scans run concurrently with a thread pool.
- Default worker count is `min(32, (os.cpu_count() or 1) * 2)`.
- Override with `--workers <int>`.

### Incremental scanning and path filters

- `--incremental` enables cached scans for unchanged files.
- Cache location defaults to `.shieldscan-cache.json` and can be overridden with `--cache-file`.
- `--include` and `--exclude` accept repeatable glob filters.
- These controls are available in both CLI flags and `.shieldscan.yaml` config.

### Configuration file

- ShieldScan auto-loads `.shieldscan.yaml` or `.shieldscan.yml` from the current directory.
- You can also provide a file directly with `--config <path>`.
- See `.shieldscan.yaml.example` for supported keys.

### Rule metadata schema

Each rule in `rules/rules.yaml` supports:

- `id` (required)
- `language` (required)
- `vulnerability_type` (required)
- `severity` (required)
- `description` (required)
- `node_types` (required list[str])
- `match_regex` (required regex string)
- `cwe` (optional string)
- `confidence` (optional string)
- `remediation` (optional string)
- `references` (optional list[str], defaults to empty)
- `match_mode` (optional: `regex` or `semantic`, defaults to `regex`)

### Suppression workflow

- ShieldScan auto-loads `.shieldscanignore.yaml` or `.shieldscanignore.yml` if present.
- You can also pass `--ignore-file <path>`.
- Suppression entries support either:
  - `fingerprint` exact match, or
  - `rule_id` + `path_glob`
- Optional `expires_on` (YYYY-MM-DD) disables suppression after expiry.

Example suppression file: `.shieldscanignore.yaml.example`

Suppression count appears in JSON reports as `suppressed_findings`.

## Local Tree-sitter Grammar Compilation on Windows

This project uses `tree-sitter-python` and `tree-sitter-javascript`. On many systems pip installs prebuilt wheels, but you can force local compilation if you want native binaries built on your machine.

### 1) Prerequisites

- Python 3.10+
- Git
- Microsoft C++ Build Tools (MSVC) or Visual Studio Build Tools
- Optional: Rust toolchain (`rustup`) for crates that require it during build

### 2) Upgrade build tooling

```powershell
python -m pip install --upgrade pip setuptools wheel
```

### 3) Force local source builds (no wheel)

```powershell
pip install --no-binary tree-sitter tree-sitter
pip install --no-binary tree-sitter-python tree-sitter-python
pip install --no-binary tree-sitter-javascript tree-sitter-javascript
```

### 4) Verify grammar availability

```powershell
python -c "import tree_sitter_python, tree_sitter_javascript; print('python/js grammars ready')"
```

### 5) Run a scan

```powershell
shieldscan .
```

## Troubleshooting

- `error: Microsoft Visual C++ 14.x is required`: install Visual Studio Build Tools with C++ workload.
- `Failed building wheel`: upgrade pip/setuptools/wheel, then retry with a clean virtual environment.
- Import errors for parser modules: ensure you installed in the active environment (`where python` in PowerShell).

## Quality Gates

### Automated tests

```powershell
python -m pip install -e .[dev]
pytest -q
```

Test coverage includes:

- Rule loading validation
- CLI behavior (exit codes, baseline filtering, profile handling)
- Deterministic fingerprint generation
- JSON report structure checks

### CI pipeline

- GitHub Actions workflow: `.github/workflows/ci.yml`
- Runs on push and pull requests
- Matrix: Python 3.10, 3.11, 3.12
- Steps: install, syntax check, unit tests

### Versioned schemas

- Report schema v1: `schemas/report-v1.schema.json`
- Config schema v1: `schemas/config-v1.schema.json`

## Benchmarking

Run the benchmark harness:

```powershell
python benchmarks/benchmark_scan.py .
```

It compares worker counts and incremental warm/hot runs.

## Release and security

- Changelog: `CHANGELOG.md`
- Security policy: `SECURITY.md`
- Release build workflow: `.github/workflows/release.yml`
