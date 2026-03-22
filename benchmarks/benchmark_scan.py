from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

from scanner import scan_target


def run_once(target: Path, rules: Path, workers: int, incremental: bool, cache_file: Path) -> dict[str, object]:
    start = perf_counter()
    summary = scan_target(
        target=target,
        rules_file=rules,
        max_workers=workers,
        incremental=incremental,
        cache_file=cache_file,
    )
    elapsed = perf_counter() - start
    return {
        "workers": workers,
        "incremental": incremental,
        "elapsed_seconds": round(elapsed, 6),
        "files_scanned": summary.files_scanned,
        "findings": len(summary.findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark ShieldScan throughput")
    parser.add_argument("target", type=Path, help="Directory or file to benchmark")
    parser.add_argument("--rules", type=Path, default=Path("rules") / "rules.yaml")
    parser.add_argument("--cache-file", type=Path, default=Path(".shieldscan-benchmark-cache.json"))
    args = parser.parse_args()

    worker_sets = [1, 2, 4, 8]
    runs: list[dict[str, object]] = []

    for workers in worker_sets:
        runs.append(run_once(args.target, args.rules, workers, False, args.cache_file))

    # Incremental warm + hot run profile.
    runs.append(run_once(args.target, args.rules, 4, True, args.cache_file))
    runs.append(run_once(args.target, args.rules, 4, True, args.cache_file))

    print(json.dumps({"target": str(args.target), "runs": runs}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
