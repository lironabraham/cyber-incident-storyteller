"""
EVTX corpus regression test.

Runs the full ingest → build_attack_chains pipeline against every *.evtx file
under tests/fixtures/evtx/ and asserts detection thresholds don't regress.

Skipped automatically when fewer than 100 fixture files are present (CI without
the downloaded corpus).  To download the full corpus run:

    py tests/download_evtx_fixtures.py

Then run this test with:

    py -m pytest tests/test_evtx_corpus.py -v
    py -m pytest tests/test_evtx_corpus.py -v -m slow
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).parent / 'fixtures' / 'evtx'

# Thresholds — tighten as detection improves, never loosen without a reason.
MIN_DETECTION_RATE = 0.84   # ≥84% of parseable files must produce ≥1 chain
MAX_PARSED_MISS    = 4      # hard cap on parse-but-no-chain files
MAX_ZERO_PARSE     = 45     # guard against parser crashes silently dropping events

# Floor for the skip gate: below this the corpus hasn't been downloaded.
_MIN_FILES_TO_RUN  = 100


def _corpus_files() -> list[Path]:
    if not FIXTURE_ROOT.exists():
        return []
    return sorted(FIXTURE_ROOT.rglob('*.evtx'))


def _needs_corpus(func):
    """Skip decorator: skip if the corpus hasn't been downloaded."""
    files = _corpus_files()
    reason = (
        f'EVTX corpus not downloaded ({len(files)} files found, need ≥{_MIN_FILES_TO_RUN}). '
        f'Run: py tests/download_evtx_fixtures.py'
    )
    return pytest.mark.skipif(len(files) < _MIN_FILES_TO_RUN, reason=reason)(func)


# ── Corpus audit helper ────────────────────────────────────────────────────────

def _run_corpus() -> dict:
    """Run every EVTX file through the pipeline and return a results dict."""
    from ingest import ingest
    from hunter import build_attack_chains

    detected: list[str] = []
    parsed_miss: list[str] = []
    zero_parse: list[str] = []

    for f in _corpus_files():
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
        if chains:
            detected.append(f.name)
        else:
            parsed_miss.append(f.name)

    total_parseable = len(detected) + len(parsed_miss)
    rate = len(detected) / total_parseable if total_parseable else 0.0
    return {
        'detected': detected,
        'parsed_miss': parsed_miss,
        'zero_parse': zero_parse,
        'total': len(detected) + len(parsed_miss) + len(zero_parse),
        'total_parseable': total_parseable,
        'detection_rate': rate,
    }


# Cache results so the pipeline runs once per session, not once per assertion.
_cached_results: dict | None = None


def _get_results() -> dict:
    global _cached_results
    if _cached_results is None:
        _cached_results = _run_corpus()
    return _cached_results


# ── Tests ──────────────────────────────────────────────────────────────────────

@pytest.mark.slow
@_needs_corpus
def test_corpus_detection_rate() -> None:
    """At least MIN_DETECTION_RATE of parseable EVTX files must produce a chain."""
    r = _get_results()
    rate = r['detection_rate']
    assert rate >= MIN_DETECTION_RATE, (
        f'Detection rate {rate:.1%} is below threshold {MIN_DETECTION_RATE:.0%}.\n'
        f'PARSED_MISS ({len(r["parsed_miss"])} files): {r["parsed_miss"]}'
    )


@pytest.mark.slow
@_needs_corpus
def test_corpus_parsed_miss_count() -> None:
    """PARSED_MISS count must not exceed MAX_PARSED_MISS."""
    r = _get_results()
    miss = r['parsed_miss']
    assert len(miss) <= MAX_PARSED_MISS, (
        f'{len(miss)} files parsed but produced no chain (limit {MAX_PARSED_MISS}).\n'
        f'Regressions: {miss}'
    )


@pytest.mark.slow
@_needs_corpus
def test_corpus_zero_parse_count() -> None:
    """ZERO_PARSE count must not exceed MAX_ZERO_PARSE (guards against parser crashes)."""
    r = _get_results()
    zp = r['zero_parse']
    assert len(zp) <= MAX_ZERO_PARSE, (
        f'{len(zp)} files produced zero events (limit {MAX_ZERO_PARSE}).\n'
        f'Check for parser regressions in: {zp[:10]}'
    )


@pytest.mark.slow
@_needs_corpus
def test_corpus_specific_known_detections() -> None:
    """Spot-check that key named attack scenarios are always detected."""
    r = _get_results()
    detected_set = set(r['detected'])

    # These files represent high-value scenarios that must never regress.
    # Add more as new attack types are covered.
    required = [
        'sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx',     # LSASS credential dump
        'NTLM2SelfRelay-med0x2e-security_4624_4688.evtx',            # NTLM relay / local privilege
        'smb_bi_auth_conn_spoolsample.evtx',                         # SMB lateral movement
    ]
    missing = [f for f in required if f not in detected_set]
    assert not missing, (
        f'Required detections regressed — these files must always produce a chain: {missing}'
    )
