"""
Integration tests against real EVTX attack samples from
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

These tests are the "cyber logic" regression suite — they verify that the
full ingest → hunter → report pipeline detects the correct attack chains,
MITRE techniques, and severity from real-world attacker tooling output.
If any of these fail after a code change, attack detection has regressed.

Fixtures live in tests/fixtures/evtx/ (gitignored binary blobs).
Pre-populate them once with:

    py tests/download_evtx_fixtures.py

Tests skip automatically when:
  - a fixture file is missing (run the download script first)
  - python-evtx is not installed (pip install python-evtx)

Run only these tests:
    pytest tests/test_evtx_real_samples.py -v
"""

import sys
from pathlib import Path

import pytest

_src = str(Path(__file__).parent.parent / 'src')
if _src not in sys.path:
    sys.path.insert(0, _src)

# Skip the entire module if python-evtx is not installed.
pytest.importorskip('Evtx', reason='python-evtx not installed — pip install python-evtx')

from parser import parse_log  # noqa: E402

# ── Fixture registry ───────────────────────────────────────────────────────────

_FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'evtx'

# Each entry: (filename, expected_event_types, description)
_SAMPLES: list[tuple[str, set[str], str]] = [
    (
        'CA_4624_4625_LogonType2_LogonProc_chrome.evtx',
        {'Windows Logon Success', 'Windows Logon Failure'},
        'Interactive logon success/failure (4624 type 2, 4625)',
    ),
    (
        'kerberos_pwd_spray_4771.evtx',
        {'Windows Kerberos PreAuth Failure'},
        'Kerberos password spray — pre-auth failures (4771)',
    ),
    (
        'temp_scheduled_task_4698_4699.evtx',
        {'Windows Scheduled Task'},
        'Scheduled task created via LOLBin execution (4698)',
    ),
    (
        'NTLM2SelfRelay-med0x2e-security_4624_4688.evtx',
        {'Windows Remote Logon', 'Windows Process Creation'},
        'NTLM self-relay PrivEsc — network logon + process creation (4624/4688)',
    ),
    (
        'PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx',
        {'Windows Share Access'},
        'Local SMB share access during privilege escalation (5145)',
    ),
    (
        'LM_Remote_Service02_7045.evtx',
        {'Windows Service Installed'},
        'Remote service installation via lateral movement (7045)',
    ),
    (
        'Network_Service_Guest_added_to_admins_4732.evtx',
        {'Windows Group Member Added'},
        'Guest account added to Administrators group (4732)',
    ),
]


def _fixture(filename: str) -> Path:
    """Return fixture path, skipping the test if the file is not present."""
    path = _FIXTURE_DIR / filename
    if not path.exists():
        pytest.skip(
            f'{filename} not found — run: py tests/download_evtx_fixtures.py'
        )
    return path


def _sample_id(sample: tuple) -> str:
    return Path(sample[0]).stem


# ── Parametrized schema + content tests ───────────────────────────────────────

@pytest.mark.parametrize('filename,expected_types,description', _SAMPLES,
                         ids=[_sample_id(s) for s in _SAMPLES])
class TestRealEvtxSamples:

    def test_parser_does_not_raise(self, filename, expected_types, description):
        parse_log(_fixture(filename), fmt='evtx')

    def test_returns_non_empty_dataframe(self, filename, expected_types, description):
        df = parse_log(_fixture(filename), fmt='evtx')
        assert len(df) > 0, (
            f'{description}: parser returned 0 rows — sample may contain only '
            f'unsupported EventIDs or the format is unrecognised.'
        )

    def test_expected_event_types_present(self, filename, expected_types, description):
        df = parse_log(_fixture(filename), fmt='evtx')
        found = set(df['event_type'].unique())
        missing = expected_types - found
        assert not missing, (
            f'{description}: missing expected event types {missing}. Found: {found}'
        )

    def test_dataframe_has_required_columns(self, filename, expected_types, description):
        df = parse_log(_fixture(filename), fmt='evtx')
        required = {'timestamp', 'hostname', 'process', 'event_type',
                    'source_ip', 'user', 'raw'}
        assert required.issubset(df.columns), (
            f'Missing columns: {required - set(df.columns)}'
        )

    def test_timestamps_are_utc_aware(self, filename, expected_types, description):
        df = parse_log(_fixture(filename), fmt='evtx')
        if df.empty:
            pytest.skip('No rows to validate timestamps against')
        assert df['timestamp'].dt.tz is not None, 'timestamps must be tz-aware'
        assert df['timestamp'].iloc[0].utcoffset().total_seconds() == 0

    def test_sorted_ascending_by_timestamp(self, filename, expected_types, description):
        df = parse_log(_fixture(filename), fmt='evtx')
        if len(df) < 2:
            pytest.skip('Need at least 2 rows to verify sort order')
        assert df['timestamp'].is_monotonic_increasing


# ── MITRE mapping spot-checks ──────────────────────────────────────────────────

class TestRealEvtxMitreMapping:

    def test_kerberos_spray_maps_to_t1110(self, tmp_path):
        from ingest import ingest
        events = ingest(
            _fixture('kerberos_pwd_spray_4771.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        kerberos = [e for e in events if e.event_type == 'Windows Kerberos PreAuth Failure']
        assert kerberos, 'No Kerberos PreAuth Failure events parsed'
        for ev in kerberos:
            assert ev.mitre_technique['id'] == 'T1110', (
                f'Expected T1110, got {ev.mitre_technique["id"]!r}'
            )

    def test_scheduled_task_maps_to_t1053(self, tmp_path):
        from ingest import ingest
        events = ingest(
            _fixture('temp_scheduled_task_4698_4699.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        tasks = [e for e in events if e.event_type == 'Windows Scheduled Task']
        assert tasks, 'No Windows Scheduled Task events parsed'
        for ev in tasks:
            assert ev.mitre_technique['id'] == 'T1053.005', (
                f'Expected T1053.005, got {ev.mitre_technique["id"]!r}'
            )

    def test_lateral_movement_service_maps_to_t1543(self, tmp_path):
        from ingest import ingest
        events = ingest(
            _fixture('LM_Remote_Service02_7045.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        svcs = [e for e in events if e.event_type == 'Windows Service Installed']
        assert svcs, 'No Windows Service Installed events parsed'
        for ev in svcs:
            assert ev.mitre_technique['id'] == 'T1543.003', (
                f'Expected T1543.003, got {ev.mitre_technique["id"]!r}'
            )


# ── Full-pipeline smoke test ───────────────────────────────────────────────────

class TestRealEvtxFullPipeline:

    def test_ntlm_relay_full_pipeline(self, tmp_path):
        from hunter import build_attack_chains
        from ingest import ingest
        from reporter import generate_report

        events = ingest(
            _fixture('NTLM2SelfRelay-med0x2e-security_4624_4688.evtx'),
            fmt='evtx',
            processed_dir=tmp_path / 'proc',
        )
        assert events, 'ingest returned no events'

        chains = build_attack_chains(events)
        report_path = tmp_path / 'report.md'
        generate_report(chains, events, report_path)

        content = report_path.read_text(encoding='utf-8')
        assert len(content) > 100, 'report appears empty'
        assert '## ' in content, 'report has no sections'


# ── Cyber-logic regression suite ──────────────────────────────────────────────
# Ground truth locked from verified detection run (2026-04-25).
# These tests exist to catch regressions in hunter.py, ingest.py, and parser.py.
# A failure here means an attack that was previously detected is now being missed.

# Per-sample ground truth:
#   chain_type   — expected AttackChain.chain_type
#   compromised  — expected AttackChain.compromised
#   techniques   — MITRE IDs that must appear in the chain (subset check)
#   note         — known detection gap / why certain real techniques are absent
_CHAIN_GROUND_TRUTH: dict[str, dict] = {
    'CA_4624_4625_LogonType2_LogonProc_chrome.evtx': {
        'chain_type':  'credential_stuffing',
        'compromised': True,
        'techniques':  {'T1110.001', 'T1078'},
        'note': (
            'Real technique is T1555.003 (Chrome credential access) but EventID '
            '4624/4625 alone cannot prove browser origin — logon events classify '
            'as credential stuffing, which is the correct conservative assessment.'
        ),
    },
    'kerberos_pwd_spray_4771.evtx': {
        'chain_type':  'brute_force',
        'compromised': False,
        'techniques':  {'T1558', 'T1110'},
        'note': (
            'Probe trigger (TGT requests) detects the spray; T1110.003 '
            '(Password Spraying sub-technique) is the precise label but T1110 '
            '(Brute Force parent) is what 4771 pre-auth failures map to.'
        ),
    },
    'LM_Remote_Service02_7045.evtx': {
        'chain_type':  'lateral_movement',
        'compromised': True,
        'techniques':  {'T1543.003'},
        'note': 'Actor has no IP attribution in this sample — anonymous chain.',
    },
    'Network_Service_Guest_added_to_admins_4732.evtx': {
        'chain_type':  'lateral_movement',
        'compromised': True,
        'techniques':  {'T1098'},
        'note': 'T1098 (Account Manipulation) — group membership change.',
    },
    'NTLM2SelfRelay-med0x2e-security_4624_4688.evtx': {
        'chain_type':  'unauthorized_access',
        'compromised': True,
        'techniques':  {'T1021'},
        'note': (
            'Real technique is T1134.001 (Token Impersonation) but the EVTX '
            'events only surface as Remote Logon (T1021) + Privilege Assigned. '
            'T1134 requires correlating LogonType 9 or ANONYMOUS LOGON — '
            'not yet implemented.'
        ),
    },
    'PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx': {
        'chain_type':  'lateral_movement',
        'compromised': True,
        'techniques':  {'T1021.002'},
        'note': 'SMB share access by machine account — lateral movement indicator.',
    },
    'temp_scheduled_task_4698_4699.evtx': {
        'chain_type':  'lateral_movement',
        'compromised': True,
        'techniques':  {'T1053.005'},
        'note': 'Scheduled task created quickly and deleted — Atexec indicator.',
    },
}


class TestRealEvtxAttackChainDetection:
    """Cyber-logic regression tests.

    Each test locks in the chain detection behaviour for a real attack sample.
    Failures indicate a regression in hunter.py, ingest.py, or parser.py that
    causes a previously-detected attack to be missed or misclassified.
    """

    def _chains_for(self, filename: str, tmp_path) -> list:
        from hunter import build_attack_chains
        from ingest import ingest
        return build_attack_chains(
            ingest(_fixture(filename), fmt='evtx', processed_dir=tmp_path / 'proc')
        )

    @pytest.mark.parametrize('filename', list(_CHAIN_GROUND_TRUTH.keys()))
    def test_at_least_one_chain_detected(self, filename, tmp_path):
        chains = self._chains_for(filename, tmp_path)
        gt = _CHAIN_GROUND_TRUTH[filename]
        assert chains, (
            f'{filename}: 0 attack chains detected — '
            f'expected chain_type={gt["chain_type"]!r}. '
            f'Note: {gt["note"]}'
        )

    @pytest.mark.parametrize('filename', list(_CHAIN_GROUND_TRUTH.keys()))
    def test_primary_chain_type(self, filename, tmp_path):
        chains = self._chains_for(filename, tmp_path)
        if not chains:
            pytest.skip('No chains — covered by test_at_least_one_chain_detected')
        gt = _CHAIN_GROUND_TRUTH[filename]
        primary = chains[0]
        assert primary.chain_type == gt['chain_type'], (
            f'{filename}: chain_type={primary.chain_type!r}, '
            f'expected {gt["chain_type"]!r}. Note: {gt["note"]}'
        )

    @pytest.mark.parametrize('filename', list(_CHAIN_GROUND_TRUTH.keys()))
    def test_compromised_flag(self, filename, tmp_path):
        chains = self._chains_for(filename, tmp_path)
        if not chains:
            pytest.skip('No chains — covered by test_at_least_one_chain_detected')
        gt = _CHAIN_GROUND_TRUTH[filename]
        primary = chains[0]
        assert primary.compromised == gt['compromised'], (
            f'{filename}: compromised={primary.compromised}, '
            f'expected {gt["compromised"]}.'
        )

    @pytest.mark.parametrize('filename', list(_CHAIN_GROUND_TRUTH.keys()))
    def test_expected_techniques_present(self, filename, tmp_path):
        chains = self._chains_for(filename, tmp_path)
        if not chains:
            pytest.skip('No chains — covered by test_at_least_one_chain_detected')
        gt = _CHAIN_GROUND_TRUTH[filename]
        all_technique_ids = {
            t['id'] for c in chains for t in c.mitre_techniques if t['id']
        }
        missing = gt['techniques'] - all_technique_ids
        assert not missing, (
            f'{filename}: missing expected MITRE techniques {missing}. '
            f'Found: {all_technique_ids}. Note: {gt["note"]}'
        )
