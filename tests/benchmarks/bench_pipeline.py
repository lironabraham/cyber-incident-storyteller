"""
Pipeline performance benchmarks.

Measures wall time and peak memory for the full ingest → hunt → report
pipeline at three log scales: 1k, 10k, and 50k lines.

Usage:
    py tests/benchmarks/bench_pipeline.py
"""

import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from hunter import build_attack_chains
from ingest import ingest
from reporter import generate_report


def _generate_auth_log(n_lines: int, path: Path) -> Path:
    """
    Generate a synthetic auth.log of exactly n_lines lines.

    Pattern repeats: 10 failed logins from a unique IP, then 1 accepted
    password — so every IP crosses the brute-force threshold and the hunter
    has real chains to build.
    """
    base = datetime(2024, 4, 23, 0, 0, 0)
    lines: list[str] = []
    ip_idx = 0

    while len(lines) < n_lines:
        ip = f'10.{(ip_idx >> 8) & 0xFF}.{ip_idx & 0xFF}.1'
        ip_idx += 1
        t = base + timedelta(seconds=ip_idx * 120)

        batch = min(11, n_lines - len(lines))
        for i in range(min(10, batch)):
            lines.append(
                f"{t.strftime('%b %d %H:%M:%S')} server1 sshd[{2000 + i}]: "
                f"Failed password for root from {ip} port {22000 + i} ssh2"
            )
            t += timedelta(seconds=5)

        if len(lines) < n_lines:
            lines.append(
                f"{t.strftime('%b %d %H:%M:%S')} server1 sshd[3000]: "
                f"Accepted password for admin from {ip} port 23000 ssh2"
            )

    path.write_text('\n'.join(lines[:n_lines]) + '\n', encoding='utf-8')
    return path


def _run(n_lines: int, tmp: Path) -> dict:
    log_path = tmp / f'bench_{n_lines}.log'
    _generate_auth_log(n_lines, log_path)

    processed_dir = tmp / f'proc_{n_lines}'
    report_path = tmp / f'report_{n_lines}.md'

    tracemalloc.start()
    t0 = time.perf_counter()

    events = ingest(log_path, fmt='auth_log', processed_dir=processed_dir)
    chains = build_attack_chains(events)
    generate_report(chains, events, report_path)

    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        'lines':         n_lines,
        'events':        len(events),
        'chains':        len(chains),
        'elapsed_s':     round(elapsed, 3),
        'lines_per_sec': int(n_lines / elapsed),
        'peak_mb':       round(peak / 1024 / 1024, 1),
    }


def main() -> None:
    scales = [1_000, 10_000, 50_000]

    print(f"{'Lines':>8}  {'Events':>8}  {'Chains':>7}  "
          f"{'Time (s)':>9}  {'Lines/s':>9}  {'Peak MB':>8}")
    print('-' * 65)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for n in scales:
            r = _run(n, tmp)
            print(
                f"{r['lines']:>8,}  {r['events']:>8,}  {r['chains']:>7,}  "
                f"{r['elapsed_s']:>9.3f}  {r['lines_per_sec']:>9,}  "
                f"{r['peak_mb']:>7.1f}M"
            )


if __name__ == '__main__':
    main()
