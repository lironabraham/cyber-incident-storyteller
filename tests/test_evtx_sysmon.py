"""
Integration tests for the Windows Sysmon EVTX parser.

Fixtures: tests/fixtures/evtx/<Category>/<file>.evtx
Download once with:  py tests/download_evtx_fixtures.py

Tests skip automatically when:
  - the fixture file is missing (run the download script first)
  - python-evtx is not installed (pip install python-evtx)

Run only these tests:
    pytest tests/test_evtx_sysmon.py -v
"""

import sys
from pathlib import Path

import pytest

_src = str(Path(__file__).parent.parent / 'src')
if _src not in sys.path:
    sys.path.insert(0, _src)

pytest.importorskip('Evtx', reason='python-evtx not installed — pip install python-evtx')

sys.path.insert(0, str(Path(__file__).parent))
from download_evtx_fixtures import local_path as _local_path  # noqa: E402

from ingest import ingest  # noqa: E402
from hunter import build_attack_chains  # noqa: E402


# ── Ground truth ───────────────────────────────────────────────────────────────
# Each entry: (repo_path, expected_event_types, expect_chain)
# expected_event_types: subset that MUST appear in the parsed event list
# expect_chain: True if we expect >= 1 AttackChain from hunter

_SYSMON_SAMPLES: list[tuple[str, set[str], bool]] = [
    (
        'Credential Access/sysmon_10_11_lsass_memdump.evtx',
        {'Sysmon Process Access'},
        True,
    ),
    (
        'Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx',
        {'Sysmon Process Access'},
        True,
    ),
    (
        'Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx',
        {'Sysmon Process Created'},
        True,
    ),
    (
        'Other/emotet/exec_emotet_sysmon_1.evtx',
        {'Sysmon Process Created'},
        False,  # single anonymous process creation — insufficient signal for a chain
    ),
    (
        'Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx',
        {'Sysmon WMI Subscription'},
        True,
    ),
]


def _fixture(repo_path: str) -> Path:
    path = _local_path(repo_path)
    if not path.exists():
        pytest.skip(
            f'{Path(repo_path).name} not found — run: py tests/download_evtx_fixtures.py'
        )
    return path


def _sample_id(sample: tuple) -> str:
    return Path(sample[0]).stem


# ── Parser + ingest tests ──────────────────────────────────────────────────────

@pytest.mark.parametrize('repo_path,expected_types,expect_chain', _SYSMON_SAMPLES,
                         ids=[_sample_id(s) for s in _SYSMON_SAMPLES])
class TestSysmonParser:

    def test_parser_does_not_raise(self, repo_path, expected_types, expect_chain, tmp_path):
        ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')

    def test_returns_non_empty_event_list(self, repo_path, expected_types, expect_chain, tmp_path):
        events = ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')
        assert events, (
            f'{Path(repo_path).name}: ingest returned 0 events — '
            f'Sysmon provider dispatch may not be wired up in parser.py.'
        )

    def test_expected_event_types_present(self, repo_path, expected_types, expect_chain, tmp_path):
        events = ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')
        found = {e.event_type for e in events}
        missing = expected_types - found
        assert not missing, (
            f'{Path(repo_path).name}: missing event types {missing}. Found: {found}'
        )

    def test_all_events_have_required_fields(self, repo_path, expected_types, expect_chain, tmp_path):
        events = ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')
        for ev in events:
            assert ev.event_id
            assert ev.timestamp is not None
            assert ev.event_type
            assert ev.severity in ('info', 'low', 'medium', 'high', 'critical'), (
                f'unexpected severity {ev.severity!r} on {ev.event_type}'
            )

    def test_timestamps_are_utc_aware(self, repo_path, expected_types, expect_chain, tmp_path):
        events = ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')
        if not events:
            pytest.skip('No events')
        for ev in events[:5]:
            assert ev.timestamp.tzinfo is not None, 'timestamps must be tz-aware'
            assert ev.timestamp.utcoffset().total_seconds() == 0

    def test_hunter_produces_chain_when_expected(self, repo_path, expected_types, expect_chain, tmp_path):
        if not expect_chain:
            pytest.skip('No chain expected for this sample')
        events = ingest(_fixture(repo_path), fmt='evtx', processed_dir=tmp_path / 'proc')
        if not events:
            pytest.skip('No events parsed — covered by test_returns_non_empty_event_list')
        chains = build_attack_chains(events)
        assert chains, (
            f'{Path(repo_path).name}: expected >= 1 attack chain, got 0. '
            f'Event types found: {sorted({e.event_type for e in events})}'
        )


# ── LSASS credential access (Pass 5) ──────────────────────────────────────────

class TestSysmonLsassChain:
    """LSASS memory access must produce a credential_access chain via Pass 5."""

    def test_lsass_memdump_produces_credential_access_chain(self, tmp_path):
        events = ingest(
            _fixture('Credential Access/sysmon_10_11_lsass_memdump.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        lsass_events = [e for e in events if e.event_type == 'Sysmon Process Access']
        assert lsass_events, 'No Sysmon Process Access events parsed from LSASS memdump sample'

        chains = build_attack_chains(events)
        cred_chains = [c for c in chains if c.chain_type == 'credential_access']
        assert cred_chains, (
            f'Expected credential_access chain. '
            f'Chain types found: {[c.chain_type for c in chains]}'
        )
        assert all(c.compromised for c in cred_chains)

    def test_lsass_events_are_critical_severity(self, tmp_path):
        events = ingest(
            _fixture('Credential Access/sysmon_10_11_lsass_memdump.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        lsass_events = [e for e in events if e.event_type == 'Sysmon Process Access']
        if not lsass_events:
            pytest.skip('No Sysmon Process Access events')
        for ev in lsass_events:
            assert ev.severity == 'critical', (
                f'LSASS memory access must be critical, got {ev.severity!r}'
            )

    def test_lsass_events_map_to_t1003_001(self, tmp_path):
        events = ingest(
            _fixture('Credential Access/sysmon_10_11_lsass_memdump.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        lsass_events = [e for e in events if e.event_type == 'Sysmon Process Access']
        if not lsass_events:
            pytest.skip('No Sysmon Process Access events')
        for ev in lsass_events:
            assert ev.mitre_technique['id'] == 'T1003.001', (
                f'Expected T1003.001, got {ev.mitre_technique["id"]!r}'
            )


# ── WMI persistence (Pass 4) ──────────────────────────────────────────────────

class TestSysmonWmiPersistence:
    """WMI subscription events must produce a chain and map to T1546.003."""

    def test_wmi_subscription_produces_chain(self, tmp_path):
        events = ingest(
            _fixture('Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        wmi_events = [e for e in events if e.event_type == 'Sysmon WMI Subscription']
        assert wmi_events, 'No Sysmon WMI Subscription events parsed'

        chains = build_attack_chains(events)
        assert chains, (
            'Expected >= 1 chain from WMI subscription sample. '
            f'Event types: {sorted({e.event_type for e in events})}'
        )
        assert any(c.compromised for c in chains)

    def test_wmi_events_map_to_t1546_003(self, tmp_path):
        events = ingest(
            _fixture('Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        wmi_events = [e for e in events if e.event_type == 'Sysmon WMI Subscription']
        if not wmi_events:
            pytest.skip('No WMI Subscription events')
        for ev in wmi_events:
            assert ev.mitre_technique['id'] == 'T1546.003', (
                f'Expected T1546.003, got {ev.mitre_technique["id"]!r}'
            )
