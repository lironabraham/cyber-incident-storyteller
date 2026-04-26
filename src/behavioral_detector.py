"""
Pass 4.6: Behavioral anomaly detection.

Detects suspicious process execution patterns that don't rely on command-name
matching against SUSPICIOUS_COMMANDS. Catches attackers using random binary
names, custom PoC tools, and living-off-the-land techniques that bypass
signature-based detection.

Three detection heuristics (applied to uncovered Sysmon/Windows Process Created events):
  1. Temp-path execution   — process spawned from AppData\\Local\\Temp,
                             Windows\\Temp, Users\\Public, or similar staging dirs
  2. Parent-child anomaly  — Office/browser/service process spawning a shell
                             (requires parent_process field from Sysmon EID 1)
  3. CLI obfuscation       — base64 blobs, ^ escape sequences, PS IEX/EncodedCommand,
                             or cmd /c chaining in the command line

Public API
----------
find_behavioral_chains(events, covered_ids) -> list[AttackChain]
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from schema import StandardEvent
    from hunter import AttackChain


# ── Temp/staging path patterns ─────────────────────────────────────────────────
_TEMP_PATH_RE = re.compile(
    r'\\(?:'
    r'AppData\\Local\\Temp|'
    r'AppData\\Roaming\\(?!Microsoft\\)|'   # Roaming (Emotet, etc.) — exclude MS subdirs
    r'Windows\\Temp|'
    r'Users\\Public\\|'                      # Public staging
    r'ProgramData\\(?!Microsoft\\Windows\\)' # ProgramData non-Windows subdirs
    r')',
    re.IGNORECASE,
)

# ── Suspicious parent → child spawn relationships ─────────────────────────────
_OFFICE_PARENTS: frozenset[str] = frozenset({
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
    'onenote.exe', 'msaccess.exe', 'mspub.exe', 'visio.exe',
})
_BROWSER_PARENTS: frozenset[str] = frozenset({
    'iexplore.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe', 'opera.exe',
})
_SERVICE_PARENTS: frozenset[str] = frozenset({
    'svchost.exe', 'services.exe', 'spoolsv.exe', 'lsass.exe',
})
_SUSPICIOUS_CHILDREN: frozenset[str] = frozenset({
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'wmic.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
    'bitsadmin.exe', 'msiexec.exe', 'installutil.exe', 'cmstp.exe',
})

# ── Command-line obfuscation markers ─────────────────────────────────────────
_OBFUSCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}(?:\s|$)', re.IGNORECASE),  # base64 blob (40+ chars)
    re.compile(r'(?:\^[a-zA-Z]){4,}'),                                  # cmd ^ escape sequences
    re.compile(r'cmd(?:\.exe)?\s+/[vc]\s+', re.IGNORECASE),            # cmd /c or /v chaining
    re.compile(r'\biex\b|\binvoke-expression\b', re.IGNORECASE),        # PowerShell IEX
    re.compile(r'frombase64string', re.IGNORECASE),                     # PS base64 decode
    re.compile(r'-en(?:c|codedcommand)\s+[A-Za-z0-9+/]{20,}', re.IGNORECASE),  # PS -enc
    re.compile(r'-(?:w(?:indowstyle)?)\s+h(?:idden)?.*-(?:nop|noprofile)', re.IGNORECASE),  # PS hidden
]

# MITRE mappings for each behavioral pattern
_MITRE_TEMP_EXEC  = ('T1059',     'Command and Script Interpreter')
_MITRE_PARENT     = ('T1204.002', 'User Execution: Malicious File')
_MITRE_OBFUSCATE  = ('T1027',     'Obfuscated Files or Information')

_PROCESS_EVENT_TYPES = frozenset({
    'Sysmon Process Created',
    'Process Execution',
    'Windows Process Creation',
})


def _is_temp_path(command_line: str | None, process: str | None) -> bool:
    """Return True if the command or process path indicates temp/staging dir execution."""
    target = command_line or process or ''
    return bool(_TEMP_PATH_RE.search(target))


def _is_suspicious_parent_child(parent: str | None, child: str | None) -> bool:
    """Return True if the parent→child spawn relationship is anomalous."""
    if not parent or not child:
        return False
    p = parent.lower()
    c = child.lower()
    return (
        (p in _OFFICE_PARENTS   and c in _SUSPICIOUS_CHILDREN)
        or (p in _BROWSER_PARENTS  and c in _SUSPICIOUS_CHILDREN)
        or (p in _SERVICE_PARENTS  and c in _SUSPICIOUS_CHILDREN)
    )


def _has_obfuscation(command_line: str | None) -> bool:
    """Return True if the command line contains known obfuscation markers."""
    if not command_line:
        return False
    return any(pat.search(command_line) for pat in _OBFUSCATION_PATTERNS)


def find_behavioral_chains(
    events: list[StandardEvent],
    covered_ids: set[str],
) -> list[AttackChain]:
    """Pass 4.6: detect behavioral anomalies in uncovered process-execution events.

    Runs after the LOLBin pass (4.5) so known LOLBins are already claimed.
    Each matched event produces a single-event chain tagged with the matching
    MITRE technique. Chain type is 'post_exploitation' for temp-path and
    parent-child patterns, 'defense_evasion' for obfuscation.
    """
    # Import here to avoid circular import at module load time.
    from hunter import AttackChain, _primary_user, _unique_techniques
    from dataclasses import replace

    new_covered: set[str] = set()
    chains: list[AttackChain] = []

    for e in events:
        if e.event_id in covered_ids or e.event_id in new_covered:
            continue
        if e.event_type not in _PROCESS_EVENT_TYPES:
            continue

        process   = (e.target_system.get('process') or '').lower()
        cmd_line  = e.command_line or e.source_actor.get('user') or ''
        parent    = e.parent_process

        mitre_id: str | None = None
        mitre_name: str | None = None
        chain_type: str | None = None

        if _is_temp_path(cmd_line, process):
            mitre_id, mitre_name = _MITRE_TEMP_EXEC
            chain_type = 'post_exploitation'
        elif _is_suspicious_parent_child(parent, process):
            mitre_id, mitre_name = _MITRE_PARENT
            chain_type = 'post_exploitation'
        elif _has_obfuscation(cmd_line):
            mitre_id, mitre_name = _MITRE_OBFUSCATE
            chain_type = 'defense_evasion'

        if chain_type is None:
            continue

        enriched = replace(
            e,
            severity='high' if e.severity in ('info', 'low') else e.severity,
            mitre_technique={'id': mitre_id, 'name': mitre_name},
        )
        new_covered.add(e.event_id)
        chains.append(AttackChain(
            actor_ip=e.source_actor.get('ip'),
            actor_user=_primary_user([enriched]),
            severity=enriched.severity,
            mitre_techniques=[{
                'id': mitre_id,
                'name': mitre_name,
                'event_type': e.event_type,
            }],
            events=[enriched],
            chain_type=chain_type,
            compromised=True,
        ))

    covered_ids.update(new_covered)
    return chains
