"""
MORDOR APT29 Day 1 regression test.

Validates the full ingest -> build_attack_chains pipeline against the OTRF
APT29 evaluation dataset (Day 1), which contains a realistic mix of benign
Windows system activity alongside documented APT29 TTPs.

Dataset: https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29/day1
APT29 Day 1 techniques covered: T1003.001, T1021.006, T1047, T1053.005,
  T1059.001, T1548.002, T1566.001, T1204.002, T1071.001

To generate the required fixture:
    py src/convert_mordor_to_evtx.py \\
        data/mordor/apt29_evals_day1_manual_2020-05-01225525.json \\
        data/mordor/apt29_day1.evtx.xml

Then run:
    py -m pytest tests/test_mordor_apt29.py -v
    py -m pytest tests/test_mordor_apt29.py -v -m slow

──────────────────────────────────────────────────────────────────────────────
BASELINE (observed 2026-05-08, pipeline v4.6)
──────────────────────────────────────────────────────────────────────────────
The OTRF/MORDOR repo documents *techniques exercised* (9 TTPs, 4 hosts),
not how many chains a detection tool should produce.  Chain counts are an
emergent property of our grouping logic.  The numbers below are our observed
output after all noise-reduction passes; they serve as regression guards,
not external ground truth.

  Raw EVTX records:            ~196,000
  Parsed events (post-filter): ~16,000+
  Total chains:                    139
    lateral_movement:               56   (Pass 1/2/3 network logon pivots — T1021.006/T1047)
    post_exploitation:              38   (Pass 4 Sysmon EID 1 + 4.5 LOLBin — T1059.001)
    brute_force:                    20   (Pass 1 failure-threshold trigger — T1110)
    defense_evasion:                13   (Pass 4 Sysmon EID 12/13 registry — T1548.002)
    unauthorized_access:             6   (Pass 2 silent-access pivot — T1078)
    credential_access:               5   (Pass 5 LSASS EID 10 — T1003.001)
    credential_stuffing:             1   (Pass 3 probe trigger — T1110.004)

Noise regressions to watch:
  - credential_access > 50:  EID-10 access-mask filter broken (was 23,460 before fix)
  - total chains > 300:      PS EID 4104 content filter or Pass 4 grouping broken
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).parent.parent / 'data' / 'mordor' / 'apt29_day1.evtx.xml'

_SKIP = pytest.mark.skipif(
    not _FIXTURE.exists(),
    reason=(
        'APT29 Day 1 fixture not found. Generate it with:\n'
        '  py src/convert_mordor_to_evtx.py '
        'data/mordor/apt29_evals_day1_manual_2020-05-01225525.json '
        'data/mordor/apt29_day1.evtx.xml'
    ),
)


# ── Shared pipeline run (cached per session) ───────────────────────────────────

_cached: dict | None = None


def _run() -> dict:
    global _cached
    if _cached is not None:
        return _cached

    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
    from ingest import ingest
    from hunter import build_attack_chains
    import collections

    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        events = ingest(str(_FIXTURE), fmt='evtx')

    chains = build_attack_chains(events)
    chain_types = collections.Counter(c.chain_type for c in chains)

    _cached = {
        'events': events,
        'chains': chains,
        'chain_types': chain_types,
        'n_events': len(events),
        'n_chains': len(chains),
    }
    return _cached


# ── Tests ──────────────────────────────────────────────────────────────────────

@pytest.mark.slow
@_SKIP
def test_apt29_parses_events() -> None:
    """Dataset must produce a substantial number of parsed events.

    APT29 Day 1 has ~196k raw records; after noise filtering ~16k should pass.
    """
    r = _run()
    assert r['n_events'] >= 5_000, (
        f'Only {r["n_events"]:,} events parsed — expected >=5,000 from APT29 Day 1'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_produces_chains() -> None:
    """Total chain count must stay within the observed baseline range.

    Floor (90): catches lost-detection regressions (~65% of baseline 139).
    Ceiling (300): catches FP explosions from broken PS EID 4104 content filter
    or Pass 4 grouping regression.
    """
    r = _run()
    n = r['n_chains']
    assert n >= 90, (
        f'Only {n} chains — expected >=90. Baseline was 139; check for lost detections.'
    )
    assert n <= 300, (
        f'{n} chains — expected <=300. Baseline was 139; likely a noise regression '
        f'(broken PS content filter or Pass 4 grouping).'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_eid10_noise_contained() -> None:
    """credential_access chains must not flood from PSM/svchost process-query noise.

    Before the EID-10 access-mask tightening, svchost->svchost (GrantedAccess=0x1000
    = PROCESS_QUERY_LIMITED_INFORMATION) generated 23,460 false credential_access
    chains. Observed post-fix baseline: 5. Ceiling is 10x headroom.
    """
    r = _run()
    ca = r['chain_types'].get('credential_access', 0)
    assert ca <= 50, (
        f'{ca:,} credential_access chains — likely EID-10 noise regression. '
        f'Baseline: 5 (was 23,460 before access-mask fix).'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_credential_access_detected() -> None:
    """credential_access chains must reach baseline floor (T1003.001 LSASS dump).

    APT29 Step 6 uses Mimikatz and python.exe to dump LSASS memory.
    Evidence: Sysmon EID 10 with TargetImage=lsass.exe and GrantedAccess
    including PROCESS_VM_READ (0x0010). Observed baseline: 5.
    """
    r = _run()
    ca = r['chain_types'].get('credential_access', 0)
    assert ca >= 3, (
        f'Only {ca} credential_access chains — expected >=3 (baseline: 5). '
        f'LSASS dump (T1003.001) may no longer be detected.'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_lateral_movement_detected() -> None:
    """lateral_movement chains must reach baseline floor (T1021.006 / T1047).

    APT29 Steps 8-9 pivot to NASHUA, NEWYORK, SCRANTON via WMI and WinRM,
    producing Windows EID 4624 LogonType 3 network logons. Observed baseline: 56.
    """
    r = _run()
    lm = r['chain_types'].get('lateral_movement', 0)
    assert lm >= 35, (
        f'Only {lm} lateral_movement chains — expected >=35 (baseline: 56). '
        f'APT29 WMI/WinRM pivots (T1021.006/T1047) may be under-detected.'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_post_exploitation_detected() -> None:
    """post_exploitation chains must reach baseline floor (T1059.001).

    APT29 uses PowerShell extensively for discovery and C2, producing
    Sysmon EID 1 process creation and PowerShell EID 4104 script blocks.
    Observed baseline: 38.
    """
    r = _run()
    pe = r['chain_types'].get('post_exploitation', 0)
    assert pe >= 25, (
        f'Only {pe} post_exploitation chains — expected >=25 (baseline: 38). '
        f'PowerShell execution (T1059.001) may be under-detected.'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_defense_evasion_detected() -> None:
    """defense_evasion chains must reach baseline floor (T1548.002).

    APT29 Step 3 uses sdclt.exe UAC bypass, writing AppCompatFlags registry keys
    captured by Sysmon EID 12/13 and matched by the persistence key filter.
    Observed baseline: 13.
    """
    r = _run()
    de = r['chain_types'].get('defense_evasion', 0)
    assert de >= 8, (
        f'Only {de} defense_evasion chains — expected >=8 (baseline: 13). '
        f'UAC bypass (T1548.002) via AppCompatFlags may no longer be detected.'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_brute_force_detected() -> None:
    """brute_force chains must reach baseline floor (T1110).

    APT29 Day 1 generates failed logon sequences captured by Pass 1
    (failure-threshold trigger on Windows EID 4625). Observed baseline: 20.
    """
    r = _run()
    bf = r['chain_types'].get('brute_force', 0)
    assert bf >= 12, (
        f'Only {bf} brute_force chains — expected >=12 (baseline: 20). '
        f'Failed logon detection (T1110) may be broken.'
    )


@pytest.mark.slow
@_SKIP
def test_apt29_multi_host_coverage() -> None:
    """Events must span multiple hosts (APT29 compromised 4 hosts in Day 1)."""
    r = _run()
    hostnames = {e.target_system['hostname'] for e in r['events'] if e.target_system['hostname']}
    assert len(hostnames) >= 2, (
        f'Only {len(hostnames)} host(s) seen — APT29 Day 1 spans UTICA, NASHUA, '
        f'NEWYORK, SCRANTON'
    )
