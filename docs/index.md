# Cyber Incident Storyteller

**Autonomous DFIR — turns raw Linux and Windows host logs into MITRE-mapped attack narratives.**  
No cloud. No LLM. No SIEM required.

[![Tests](https://github.com/lironabraham/cyber-incident-storyteller/actions/workflows/test.yml/badge.svg)](https://github.com/lironabraham/cyber-incident-storyteller/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/ais-storyteller)](https://pypi.org/project/ais-storyteller/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/lironabraham/cyber-incident-storyteller/pkgs/container/ais-storyteller)

---

## What it does

Drop in a log file, get back a complete incident report in seconds:

```
logs/auth.log  ──►  parse  ──►  ingest  ──►  hunt  ──►  report.md
```

1. **Parses** Linux and Windows host logs into a normalized event stream
2. **Hunts** for attacker IPs using a 4-pass Trigger-Pivot algorithm — brute-force, NTLM relay, Kerberoasting, and high-value persistence events
3. **Correlates** events into ranked attack chains with severity scoring
4. **Reports** a human-readable document with MITRE ATT&CK mappings and a Mermaid.js sequence diagram

---

## Install

```bash
pip install ais-storyteller
```

Or pull the Docker image:

```bash
docker run --rm ghcr.io/lironabraham/ais-storyteller:latest demo
```

---

## See it in 10 seconds

```bash
ais demo
```

Generates a synthetic multi-stage attack, runs the full pipeline, and prints a MITRE-mapped report — no log file needed.

---

## Analyze a real log

```bash
ais analyze /var/log/auth.log --fmt auth_log --output incident.md
```

Open `incident.md` in any Markdown viewer that renders Mermaid diagrams (GitHub, VS Code, Obsidian).

---

## What you get

Every report contains:

| Section | Content |
|---|---|
| Executive Summary | One paragraph, board-readable BLUF |
| Attack Timeline | Chronological table with MITRE technique + severity per event |
| Sequence Diagram | Mermaid.js attacker → server interaction map |
| Threat Actor Detail | Per-IP breakdown of tactics, active window, chain type |
| Recommendations | Prioritised response actions |
| Forensic Integrity | SHA-256 hash of every source log for chain-of-custody |

→ [See a full sample report](sample-report.md)

---

## Supported log formats

| Format | Source |
|---|---|
| `auth_log` | `/var/log/auth.log` — SSH, sudo, PAM |
| `syslog` | `/var/log/syslog` — services, cron, OOM |
| `audit_log` | `/var/log/audit/audit.log` — process execution, shell spawns |
| `web_access` | `/var/log/nginx/access.log` — HTTP attacks, web shells |
| `sysmon_linux` | Linux Sysmon XML — process creation, network connections |
| `evtx` | Windows `.evtx` / `wevtutil` XML — logon, process, Kerberos, services, scheduled tasks |

→ [Full format reference](supported-formats.md)

---

## Designed for field responders

- **Offline-first** — works on air-gapped hosts, no internet connection required
- **Forensically defensible** — SHA-256 chain-of-custody, source logs never modified
- **Zero dependencies on cloud or AI** — runs on any Python 3.12+ host in under a minute
- **MITRE ATT&CK mapped** — 40+ techniques, 53 commands, Linux and Windows coverage out of the box
