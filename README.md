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
shieldscan <directory_or_file> --profile ci --output reports\ci-report.json
shieldscan <directory_or_file> --write-baseline reports\baseline.json
shieldscan <directory_or_file> --baseline reports\baseline.json --new-findings-only --profile ci --output reports\new-only.json
```

Legacy compatibility is still accepted:

```powershell
python main.py scan <directory_or_file>
```

### Output modes

- `--format table` (default): Rich table output in terminal.
- `--format json`: machine-readable JSON report.
- `--output <path>`: write JSON report to file (only with `--format json`). If omitted, JSON is printed to stdout.

### Exit code behavior

- Default behavior: returns `1` when findings are detected.
- Returns `0` when no findings are detected.
- Use `--no-fail-on-findings` to force success exit code.

### CI profile and baseline workflow

- `--profile ci` forces JSON output and fail-on-findings behavior.
- `--write-baseline <path>` writes a baseline report with finding fingerprints.
- `--baseline <path> --new-findings-only` filters output to only findings not present in the baseline.
- This is useful for PR gating on newly introduced security issues.

### Threaded scanning

- Scans run concurrently with a thread pool.
- Default worker count is `min(32, (os.cpu_count() or 1) * 2)`.
- Override with `--workers <int>`.

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
