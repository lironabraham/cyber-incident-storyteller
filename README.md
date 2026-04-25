# Cyber Incident Storyteller

[![Tests](https://github.com/lironabraham/cyber-incident-storyteller/actions/workflows/test.yml/badge.svg)](https://github.com/lironabraham/cyber-incident-storyteller/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/ais-storyteller)](https://pypi.org/project/ais-storyteller/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/lironabraham/cyber-incident-storyteller/pkgs/container/ais-storyteller)

An autonomous DFIR tool that turns raw Linux and Windows host logs into a readable incident report — no cloud dependency, no LLM, no SIEM required.

Drop in a log file, get back a Markdown report with a timeline, MITRE ATT&CK technique mapping, and a sequence diagram showing exactly what the attacker did and when.

---

## What it does

1. **Parses** Linux host logs into a normalized event stream
2. **Hunts** for attacker IPs using a Trigger-Pivot algorithm — finds brute-force sources, then follows everything they touched
3. **Correlates** events into ranked attack chains with severity scoring
4. **Reports** a human-readable incident document with MITRE mappings and a Mermaid.js sequence diagram

```
logs/auth.log  ──►  parse  ──►  ingest  ──►  hunt  ──►  report.md
```

---

## Quickstart

**Requirements:** Python 3.12+

```bash
pip install ais-storyteller
```

> **Windows note:** if `ais` is not found after install, either add Python's Scripts folder to PATH (`setx PATH "%PATH%;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"` then restart your terminal), or use `py -m storyteller` in place of `ais` throughout.

**Install from source (development):**

```bash
git clone https://github.com/lironabraham/cyber-incident-storyteller
cd cyber-incident-storyteller
pip install -e ".[dev]"
```

**See it work immediately (no log file needed):**

```bash
ais demo
# Windows fallback: py src/storyteller.py demo
```

Generates a synthetic multi-stage attack, runs the full pipeline, and prints the report.

**Analyze your own log:**

```bash
ais analyze logs/auth.log --fmt auth_log --output reports/incident.md
```

Open `reports/incident.md` in any Markdown viewer that renders Mermaid diagrams (GitHub, VS Code with Mermaid plugin, Obsidian).

**Docker:**

```bash
# Pull the pre-built image from GHCR (no build step needed)
docker run --rm ghcr.io/lironabraham/ais-storyteller:latest demo

# Mount your own logs:
docker run --rm -v $(pwd)/logs:/workspace/logs ghcr.io/lironabraham/ais-storyteller:latest analyze /workspace/logs/auth.log
```

**Build locally:**

```bash
docker build -t ais .
docker run --rm ais demo
```

---

## CLI reference

```
ais analyze <log_path>
    --fmt           auth_log|syslog|audit_log|web_access|sysmon_linux|evtx  (default: auth_log)
    --output        path to write the Markdown report                   (default: reports/incident.md)
    --processed-dir directory for SHA-256 hashes and event cache        (default: data/processed)
    --threshold     min failed logins to flag an IP as attacker         (default: 5)

ais verify <log_path>
    --processed-dir directory containing the stored SHA-256 hash        (default: data/processed)

ais demo    — self-contained demo with synthetic attack log

Exit codes: 0 success · 1 error · 2 integrity verification failure
```

---

## Supported log formats

| Format key | Source | What it covers |
|---|---|---|
| `auth_log` | `/var/log/auth.log` | SSH brute force, logins, sudo, PAM failures |
| `syslog` | `/var/log/syslog` | Service start/stop, cron jobs, OOM kills, USB |
| `audit_log` | `/var/log/audit/audit.log` | Process execution, shell spawns, credential file access |
| `web_access` | `/var/log/nginx/access.log` | HTTP attacks, web shells, scanning, admin access |
| `sysmon_linux` | Linux Sysmon XML | Process creation, network connections, file deletion |
| `evtx` | Windows `.evtx` / `wevtutil` XML | Logon/logoff, process creation, scheduled tasks, services, Kerberos, group changes, share access |

> **Windows EVTX support** requires `python-evtx` for binary `.evtx` files: `pip install python-evtx`. Standard `wevtutil` XML exports work without it.

---

## Report structure

Every generated report contains:

- **Executive Summary (BLUF)** — one paragraph, board-readable
- **Attack Timeline** — chronological table of every attacker action with MITRE technique and severity
- **Sequence Diagram** — Mermaid.js diagram showing attacker -> server interactions
- **Threat Actor Detail** — per-IP breakdown of tactics used
- **Recommendations** — prioritised response actions
- **Forensic Integrity** — SHA-256 hash of every source log, stored in `data/processed/`

---

## MITRE ATT&CK coverage

The tool maps events to 40+ ATT&CK techniques across all major tactics:

**Linux (auth.log / audit.log / syslog / Sysmon):**

| Tactic | Example techniques |
|---|---|
| Initial Access | T1078 Valid Accounts, T1190 Exploit Public-Facing Application |
| Execution | T1059.004 Unix Shell, T1059.006 Python |
| Persistence | T1053.003 Cron, T1543.002 Systemd Service, T1136.001 Create Account |
| Privilege Escalation | T1548.003 Sudo |
| Defense Evasion | T1070.002 Clear Logs, T1070.003 Clear History, T1070.004 File Deletion |
| Credential Access | T1003.008 /etc/shadow, T1110 Brute Force, T1110.002 Password Cracking |
| Discovery | T1082 System Info, T1057 Process Discovery, T1049 Network Connections |
| Lateral Movement | T1021.004 SSH |
| Collection | T1560.001 Archive, T1025 Removable Media |
| Exfiltration | T1048 Alt Protocol (scp/ftp/rsync) |
| C2 | T1071 Application Layer Protocol |

**Windows EVTX (4624/4625/4688/4698/4699/4702/4720/4728/4732/4768/4769/4771/5145/7045):**

| Tactic | Example techniques |
|---|---|
| Initial Access | T1078 Valid Accounts |
| Credential Access | T1110 Brute Force, T1110.001 Password Guessing, T1558 Steal/Forge Kerberos Tickets |
| Execution | T1053.005 Scheduled Task/Job, T1059 Command Interpreter |
| Persistence | T1053.005 Scheduled Task, T1543.003 Windows Service, T1136.001 Create Account |
| Privilege Escalation | T1098 Account Manipulation, T1548 Abuse Elevation |
| Lateral Movement | T1021 Remote Services, T1021.002 SMB/Windows Admin Shares |

Command-level mapping covers 53 tools including `wget`, `curl`, `nc`, `nmap`, `hydra`, `hashcat`, `john`, `useradd`, `tar`, `scp`, and more.

---

## Severity model

Severity is context-aware, not static:

| Condition | Severity |
|---|---|
| 1-4 failed logins from an IP | `low` |
| 5-19 failed logins from an IP | `medium` |
| 20+ failed logins from an IP | `high` |
| Successful login after 5+ failures | `critical` |
| Web shell (POST to .php/.asp returning 200) | `critical` |
| Web attack pattern in URL | `high` |
| Sudo command | `high` |
| Shell spawned (bash/sh) | `high` |
| /etc/shadow or /etc/passwd access | `high` |
| Service stopped (auditd/ufw/fail2ban) | `medium` |

---

## Forensic integrity

Every log file ingested gets a SHA-256 hash written to `data/processed/<stem>.sha256`. Verify a log hasn't been tampered with after ingestion:

```bash
ais verify logs/auth.log
# exit 0 = intact, exit 2 = tampered or not yet ingested
```

---

## Running tests

```bash
# Download real Windows EVTX attack samples once (required for EVTX integration tests)
py tests/download_evtx_fixtures.py

py -m pytest tests/
py -m pytest tests/ --collect-only -q | tail -1   # check current count
py -m pytest tests/ --cov=src
```

---

## Project layout

```
src/
  storyteller.py   — CLI entrypoint (ais analyze / verify / demo)
  parser.py        — log parsers (6 formats, incl. Windows EVTX)
  schema.py        — StandardEvent dataclass + TypedDicts
  ingest.py        — normalization, severity scoring, SHA-256 hashing
  mitre.py         — MITRE ATT&CK lookup (40+ techniques, 53 commands)
  hunter.py        — Trigger-Pivot engine (4 detection pathways)
  reporter.py      — Markdown + Mermaid report generator
  generate_lab.py  — synthetic attack log generators (Linux + Windows)
  __init__.py      — public library API

pyproject.toml     — pip-installable package (ais-storyteller)
Dockerfile         — multi-stage build, ENTRYPOINT ais
tests/
  test_*.py                — unit + integration tests
  test_evtx_real_samples.py — cyber-logic regression suite (real attack samples)
  download_evtx_fixtures.py — fetch EVTX samples from sbousseaden/EVTX-ATTACK-SAMPLES
  fixtures/evtx/           — EVTX binary samples (gitignored, download separately)
logs/              — input log files (read-only, never modified)
data/processed/    — normalized JSON + SHA-256 hashes (generated)
reports/           — generated incident reports (generated)
docs/              — MkDocs site (detection coverage, roadmap, CLI reference)
```
