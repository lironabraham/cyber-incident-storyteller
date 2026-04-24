# Cyber Incident Storyteller

An autonomous DFIR tool that turns raw Linux host logs into a readable incident report — no cloud dependency, no LLM, no SIEM required.

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

## Supported log formats

| Format key | Source | What it covers |
|---|---|---|
| `auth_log` | `/var/log/auth.log` | SSH brute force, logins, sudo, PAM failures |
| `syslog` | `/var/log/syslog` | Service start/stop, cron jobs, OOM kills, USB |
| `audit_log` | `/var/log/audit/audit.log` | Process execution, shell spawns, credential file access |
| `web_access` | `/var/log/nginx/access.log` | HTTP attacks, web shells, scanning, admin access |
| `sysmon_linux` | Linux Sysmon XML | Process creation, network connections, file deletion |

---

## Quickstart

**Requirements:** Python 3.12+

```bash
git clone https://github.com/lironabraham/cyber-incident-storyteller
cd cyber-incident-storyteller
pip install -r requirements.txt
```

**Run on your own log:**

```bash
py -c "
import sys; sys.path.insert(0, 'src')
from ingest import ingest
from hunter import build_attack_chains
from reporter import generate_report
from pathlib import Path

events = ingest('logs/auth.log', fmt='auth_log', processed_dir=Path('data/processed'))
chains = build_attack_chains(events)
generate_report(chains, events, output_path=Path('reports/incident.md'))
"
```

Open `reports/incident.md` in any Markdown viewer that renders Mermaid diagrams (GitHub, VS Code with Mermaid plugin, Obsidian).

**Try it with a generated lab attack:**

```bash
py src/generate_lab.py          # generates logs/lab_attack.log
```

Then run the pipeline on `logs/lab_attack.log` with `fmt='auth_log'`.

---

## Report structure

Every generated report contains:

- **Executive Summary (BLUF)** — one paragraph, board-readable
- **Attack Timeline** — chronological table of every attacker action with MITRE technique and severity
- **Sequence Diagram** — Mermaid.js diagram showing attacker → server interactions
- **Threat Actor Detail** — per-IP breakdown of tactics used
- **Recommendations** — prioritised response actions
- **Forensic Integrity** — SHA-256 hash of every source log, stored in `data/processed/`

---

## MITRE ATT&CK coverage

The tool maps events to 40+ ATT&CK techniques across all major tactics:

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

Command-level mapping covers 53 tools including `wget`, `curl`, `nc`, `nmap`, `hydra`, `hashcat`, `john`, `useradd`, `tar`, `scp`, and more.

---

## Severity model

Severity is context-aware, not static:

| Condition | Severity |
|---|---|
| 1–4 failed logins from an IP | `low` |
| 5–19 failed logins from an IP | `medium` |
| 20+ failed logins from an IP | `high` |
| Successful login after 5+ failures | `critical` |
| Web shell (POST to .php/.asp returning 200) | `critical` |
| Web attack pattern in URL | `high` |
| Sudo command | `high` |
| Shell spawned (bash/sh) | `high` |
| /etc/shadow or /etc/passwd access | `high` |
| Service stopped (auditd/ufw/fail2ban) | `medium` |

---

## Running tests

```bash
py -m pytest tests/          # 271 tests
py -m pytest tests/ --cov=src
```

---

## Forensic integrity

Every log file ingested gets a SHA-256 hash written to `data/processed/<stem>.sha256`. Verify a log hasn't been tampered with after ingestion:

```bash
py -c "
import sys; sys.path.insert(0, 'src')
from ingest import verify_integrity
print(verify_integrity('logs/auth.log'))   # True = intact, False = modified or not ingested
"
```

---

## Project layout

```
src/
  parser.py        — log parsers (5 formats)
  schema.py        — StandardEvent dataclass
  ingest.py        — normalization, severity scoring, SHA-256 hashing
  mitre.py         — MITRE ATT&CK lookup (40+ techniques, 53 commands)
  hunter.py        — Trigger-Pivot attack chain engine
  reporter.py      — Markdown + Mermaid report generator
  generate_lab.py  — synthetic attack log generators

tests/             — 271 tests across all modules
logs/              — input log files (read-only, never modified)
data/processed/    — normalized JSON + SHA-256 hashes (generated)
reports/           — generated incident reports (generated)
```
