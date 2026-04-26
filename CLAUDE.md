# Cyber Incident Storyteller — CLAUDE.md

Autonomous DFIR tool: ingests Linux + Windows logs → correlates attack chains → maps MITRE ATT&CK → Markdown report with Mermaid diagram. No cloud, no LLM.

---

## Architecture

| Module | Role |
|---|---|
| `parser.py` | Regex + EVTX binary/XML parsers → unified `pd.DataFrame`; auto-detects `.evtx` magic bytes; dispatches Sysmon channel to `sysmon_evtx.py` |
| `sysmon_evtx.py` | Windows Sysmon EVTX parser — 12 EventIDs (1/3/7/8/10/11/12/13/17/18/20/21), LSASS PROCESS_VM_READ filter, SUSPICIOUS_DLLS noise filter, persistence key regex |
| `schema.py` | `StandardEvent` dataclass + `SourceActor` / `TargetSystem` / `MitreTechnique` TypedDicts |
| `ingest.py` | DataFrame → `list[StandardEvent]` + context-aware severity + SHA-256 hash |
| `mitre.py` | MITRE lookup by event type or command name (53 commands, 7 tactic categories); `SUSPICIOUS_DLLS` frozenset for EID 7 noise filter |
| `hunter.py` | 6-pass Trigger-Pivot engine; chain types: `brute_force` `credential_stuffing` `post_exploitation` `unauthorized_access` `lateral_movement` `credential_access` `defense_evasion` |
| `reporter.py` | Markdown + Mermaid.js report generator |
| `storyteller.py` | CLI — `analyze`, `verify`, `demo` subcommands |
| `generate_lab.py` | Synthetic log generators incl. `generate_evtx_attack_log()` |

---

## Supported Formats

| `fmt` key | Coverage |
|---|---|
| `auth_log` | SSH logins, sudo, PAM |
| `syslog` | systemd services, cron, OOM, USB |
| `audit_log` | process execution, shell spawn, file access |
| `web_access` | HTTP attacks, scanning, web shells |
| `sysmon_linux` | process create/terminate, network connections, file create/delete |
| `evtx` | **Security/System channel:** 4624/4625/4648/4672/4688/4697/4698/4699/4702/4720/4728/4732/4768/4769/4771/5145/7045 |
| | **Sysmon channel (via `sysmon_evtx.py`):** EID 1/3/7/8/10/11/12/13/17/18/20/21 |

---

## Coding Standards

- **Type hints** on every function signature — no bare `Any` without justification
- **Docstrings** on all public API functions and forensic-critical logic
- **NEVER modify files in `/logs/`** — read-only evidence; tampering breaks SHA-256 verification
- **Severity is context-aware** — single failed login = `low`; 20 from one IP = `high`; success after 5+ failures = `critical`
- **No mocking parsers or DataFrame pipeline in tests** — use real synthetic files from `generate_lab.py`
- **Trigger engine uses all failure types** (`Failed Login`, `Invalid User`, `Auth Failure`, `Audit Auth Failure`) — not just `Failed Login`
- **Add MITRE command entries to `SUSPICIOUS_COMMANDS` in `mitre.py`** — never inline in parsers
- **Sysmon EventID 5 and Windows EventID 4689** (Process Terminated) are always skipped — noise
- **TypedDicts** (`SourceActor`, `TargetSystem`, `MitreTechnique`) on all dict fields — never bare `dict`
- **EVTX process field** strips full Windows path → basename, lowercased (e.g. `lsass.exe`)
- **hunter.py Pass 4** groups uncovered `_HIGH_VALUE_TYPES` by user into anonymous lateral-movement chains; `AttackChain.actor_ip` is `str | None`
- **hunter.py Pass 2.5** fires when a local/null-IP 4624 is correlated with a 4672 within 60 s (same user) — catches UAC-bypass and relay logons invisible to IP-based passes
- **hunter.py Pass 5** creates single-event `credential_access` chains for `Sysmon Process Access` (LSASS memdump) and `Windows Object Access`
- **LogonType 9** (CreateProcessWithLogonW) → `Windows NewCredentials Logon` event type → T1078; always suspicious, no IP needed
- **LogonType 3/10 from localhost** (127.0.0.1/::1) → `Windows Local Relay Logon` event type → T1021; catches KrbRelayUp and NTLM self-relay
- **New chain type `credential_access`** — LSASS memory dump or object access; `compromised=True`; does not require a prior logon event

---

## Common Commands

```bash
py src/generate_lab.py                                        # regenerate synthetic fixtures
py tests/download_evtx_fixtures.py                           # one-time: fetch real EVTX samples
py src/storyteller.py analyze logs/auth.log --fmt auth_log   # run pipeline
py src/storyteller.py analyze logs/security.evtx --fmt evtx  # Windows EVTX
py src/storyteller.py verify logs/auth.log                   # integrity check
py -m pytest tests/                                          # full test suite
py -m pytest tests/ --collect-only -q | tail -1              # current test count
py -m pytest tests/ --cov=src                                # with coverage
```

---

> **Public roadmap:** `docs/roadmap.md` (Phases 4–10). Private VC strategy in `ROADMAP.md` (gitignored).
