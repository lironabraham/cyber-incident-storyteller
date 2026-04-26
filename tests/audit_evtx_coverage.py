"""
Audit tool: run every EVTX sample from sbousseaden/EVTX-ATTACK-SAMPLES through
our full ingest → hunter pipeline and report which chains we detect, which we
parse but miss, and which we can't parse at all (Sysmon/ETW-only files).

Usage:
    py tests/audit_evtx_coverage.py [--download] [--out results.json]

Options:
    --download   Fetch all 278 samples first (delegates to download_evtx_fixtures.py)
    --out PATH   Write JSON results to PATH in addition to stdout

Fixtures live at tests/fixtures/evtx/<Category>/<file>.evtx — persistent on
this machine, gitignored. Download once with:

    py tests/download_evtx_fixtures.py

The audit classifies each file into one of four buckets:
    DETECTED        ≥1 attack chain found
    PARSED_MISS     Events parsed but no chain (hunter gap to investigate)
    ZERO_PARSE      0 events parsed (Sysmon/ETW-only, no Security/System channel)
    NOT_DOWNLOADED  File absent locally — run download_evtx_fixtures.py first
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

_TESTS_DIR = Path(__file__).parent
_SRC = str(_TESTS_DIR.parent / 'src')
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

# Sample list and local path helper live in download_evtx_fixtures — single source of truth.
from download_evtx_fixtures import ALL_SAMPLES, download_all, local_path  # noqa: E402


def _audit_file(local: Path, tmp_dir: Path) -> dict:
    from hunter import build_attack_chains
    from ingest import ingest

    try:
        events = ingest(local, fmt='evtx', processed_dir=tmp_dir / local.stem)
    except Exception as exc:
        return {'status': 'PARSE_ERROR', 'error': str(exc), 'events': 0, 'chains': 0,
                'chain_types': [], 'event_types': []}

    if not events:
        return {'status': 'ZERO_PARSE', 'events': 0, 'chains': 0,
                'chain_types': [], 'event_types': []}

    event_types = sorted({e.event_type for e in events})
    try:
        chains = build_attack_chains(events)
    except Exception as exc:
        return {'status': 'HUNTER_ERROR', 'error': str(exc), 'events': len(events),
                'chains': 0, 'chain_types': [], 'event_types': event_types}

    return {
        'status': 'DETECTED' if chains else 'PARSED_MISS',
        'events': len(events),
        'chains': len(chains),
        'chain_types': [c.chain_type for c in chains],
        'event_types': event_types,
    }


def run_audit(download: bool = False) -> dict[str, dict]:
    try:
        import Evtx  # noqa: F401
    except ImportError:
        print('ERROR: python-evtx not installed — pip install python-evtx', file=sys.stderr)
        sys.exit(1)

    if download:
        print('Downloading fixtures ...')
        download_all()
        print()

    results: dict[str, dict] = {}
    icons = {'DETECTED': 'v', 'PARSED_MISS': '?', 'ZERO_PARSE': '.', 'PARSE_ERROR': '!',
             'HUNTER_ERROR': '!', 'NOT_DOWNLOADED': '-'}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for repo_path in ALL_SAMPLES:
            dest = local_path(repo_path)
            if not dest.exists():
                results[repo_path] = {'status': 'NOT_DOWNLOADED', 'events': 0,
                                      'chains': 0, 'chain_types': [], 'event_types': []}
                print(f'  - NOT_DOWNLOADED    {dest.name}')
                continue

            result = _audit_file(dest, tmp_path)
            results[repo_path] = result
            icon = icons.get(result['status'], ' ')
            chain_summary = ','.join(result['chain_types']) or '-'
            print(f'  {icon} {result["status"]:<16} {dest.name}  [{chain_summary}]')

    return results


def _print_summary(results: dict[str, dict]) -> None:
    from collections import Counter
    buckets: Counter = Counter(r['status'] for r in results.values())
    audited = sum(v for k, v in buckets.items() if k != 'NOT_DOWNLOADED')
    total = len(results)

    print()
    print('=' * 72)
    print('AUDIT SUMMARY')
    print('=' * 72)
    print(f'  Total files in repo   : {total}')
    print(f'  Audited (present)     : {audited}')
    pct = f'  ({buckets["DETECTED"] / audited * 100:.0f}% of audited)' if audited else ''
    print(f'  DETECTED              : {buckets["DETECTED"]}{pct}')
    print(f'  PARSED_MISS           : {buckets["PARSED_MISS"]}  (hunter gap)')
    print(f'  ZERO_PARSE            : {buckets["ZERO_PARSE"]}  (Sysmon/ETW-only)')
    print(f'  NOT_DOWNLOADED        : {buckets["NOT_DOWNLOADED"]}')
    errors = buckets['PARSE_ERROR'] + buckets['HUNTER_ERROR']
    if errors:
        print(f'  ERRORS                : {errors}')
    print()

    if buckets['PARSED_MISS']:
        print('-- PARSED_MISS: events present but hunter produced 0 chains --')
        for path, r in sorted(results.items()):
            if r['status'] == 'PARSED_MISS':
                print(f'  {Path(path).name}')
                print(f'    event_types: {r["event_types"]}')
        print()

    if buckets['ZERO_PARSE']:
        print('-- ZERO_PARSE: no Security/System channel events (Sysmon/ETW scope) --')
        for path, r in sorted(results.items()):
            if r['status'] == 'ZERO_PARSE':
                print(f'  {Path(path).name}')
        print()

    if errors:
        print('-- ERRORS --')
        for path, r in sorted(results.items()):
            if r['status'] in ('PARSE_ERROR', 'HUNTER_ERROR'):
                print(f'  {Path(path).name}: {r.get("error", "")}')
        print()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('--download', action='store_true',
                    help='Download missing samples before auditing')
    ap.add_argument('--out', metavar='PATH',
                    help='Write JSON results to this file')
    args = ap.parse_args()

    print(f'Auditing {len(ALL_SAMPLES)} EVTX samples ...\n')
    results = run_audit(download=args.download)
    _print_summary(results)

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding='utf-8')
        print(f'Results written to {args.out}')


if __name__ == '__main__':
    main()
