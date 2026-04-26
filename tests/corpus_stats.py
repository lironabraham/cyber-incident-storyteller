"""
EVTX corpus stats — quick summary table.

Runs the ingest → build_attack_chains pipeline once against every *.evtx file
under tests/fixtures/evtx/ and prints a summary table.  Results are printed to
stdout; exit code is 0 on pass, 1 if any threshold is breached.

Usage:
    py tests/corpus_stats.py
    py tests/corpus_stats.py --verbose    # also lists every PARSED_MISS filename
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

# Make sure src/ is importable when run directly (mirrors pytest conftest behaviour).
_SRC = Path(__file__).parent.parent / 'src'
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ingest import ingest               # noqa: E402
from hunter import build_attack_chains  # noqa: E402

FIXTURE_ROOT = Path(__file__).parent / 'fixtures' / 'evtx'

MIN_DETECTION_RATE = 0.84
MAX_PARSED_MISS    = 4
MAX_ZERO_PARSE     = 45


def run_corpus() -> dict:
    files = sorted(FIXTURE_ROOT.rglob('*.evtx'))
    if not files:
        print(f'No EVTX files found under {FIXTURE_ROOT}')
        print('Run: py tests/download_evtx_fixtures.py')
        sys.exit(1)

    detected: list[str] = []
    parsed_miss: list[str] = []
    zero_parse: list[str] = []

    for i, f in enumerate(files, 1):
        print(f'\r  [{i:3d}/{len(files)}] {f.name[:60]:<60}', end='', flush=True)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:
                events = ingest(str(f), 'evtx')
            except Exception:
                zero_parse.append(f.name)
                continue

        if not events:
            zero_parse.append(f.name)
            continue

        chains = build_attack_chains(events)
        (detected if chains else parsed_miss).append(f.name)

    print()  # newline after progress line
    total_parseable = len(detected) + len(parsed_miss)
    rate = len(detected) / total_parseable if total_parseable else 0.0
    return {
        'total':           len(files),
        'detected':        detected,
        'parsed_miss':     parsed_miss,
        'zero_parse':      zero_parse,
        'total_parseable': total_parseable,
        'detection_rate':  rate,
    }


def _tick(ok: bool) -> str:
    return 'PASS' if ok else 'FAIL'


def print_table(r: dict, verbose: bool = False) -> bool:
    rate       = r['detection_rate']
    n_detected = len(r['detected'])
    n_miss     = len(r['parsed_miss'])
    n_zero     = len(r['zero_parse'])
    total      = r['total']
    parseable  = r['total_parseable']

    rate_ok  = rate   >= MIN_DETECTION_RATE
    miss_ok  = n_miss <= MAX_PARSED_MISS
    zero_ok  = n_zero <= MAX_ZERO_PARSE
    all_pass = rate_ok and miss_ok and zero_ok

    sep = '─' * 52
    print(sep)
    print(f'  EVTX corpus — {total} files')
    print(sep)
    print(f'  {"Total files":<28} {total:>6}')
    print(f'  {"Parseable (events > 0)":<28} {parseable:>6}')
    print(f'  {"Detected (≥1 chain)":<28} {n_detected:>6}')
    print(f'  {"PARSED_MISS (0 chains)":<28} {n_miss:>6}   limit ≤{MAX_PARSED_MISS}  [{_tick(miss_ok)}]')
    print(f'  {"ZERO_PARSE (parse error)":<28} {n_zero:>6}   limit ≤{MAX_ZERO_PARSE} [{_tick(zero_ok)}]')
    print(sep)
    print(f'  {"Detection rate":<28} {rate:>6.1%}   need  ≥{MIN_DETECTION_RATE:.0%}  [{_tick(rate_ok)}]')
    print(sep)

    if n_miss and verbose:
        print('\nPARSED_MISS files (parsed but produced 0 chains):')
        for name in sorted(r['parsed_miss']):
            print(f'  • {name}')

    if not all_pass:
        print('\n[!] One or more thresholds breached — see above.')

    return all_pass


def main() -> None:
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    print(f'Running corpus pipeline against {FIXTURE_ROOT} …\n')
    r = run_corpus()
    ok = print_table(r, verbose=verbose)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
