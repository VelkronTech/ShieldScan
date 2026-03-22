# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-03-22

### Added
- Incremental scanning with cache file support (`--incremental`, `--cache-file`).
- Include/exclude glob filtering (`--include`, `--exclude`).
- Semantic rule matching path with dynamic confidence behavior.
- Suppression workflow with ignore files and expiry support.
- SARIF output mode and GitHub code scanning upload in CI.
- Benchmark harness at `benchmarks/benchmark_scan.py`.
- Versioned config/report schemas and expanded test coverage.
- `SECURITY.md` policy and release workflow scaffolding.

### Changed
- CI profile now uses SARIF output by default.
- Package version updated from `0.1.0` to `0.2.0`.
