# Quickstart

## Install

**Requirements:** Python 3.12+

```bash
pip install ais-storyteller
```

!!! note "Windows PATH"
    If `ais` is not found after install, add Python's Scripts folder to PATH:
    ```
    setx PATH "%PATH%;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
    ```
    Then restart your terminal. Or use `py -m storyteller` in place of `ais`.

---

## Run the built-in demo

No log file needed — this generates a synthetic multi-stage attack and runs the full pipeline:

```bash
ais demo
```

You'll see a MITRE-mapped incident report printed to stdout, including:

- Brute-force detection (15 failed logins → T1110)
- Credential stuffing success (T1078)
- Post-exploitation sudo commands (T1548.003)
- A Mermaid.js sequence diagram of the full attack

---

## Analyze your own log

=== "auth.log (SSH)"

    ```bash
    ais analyze /var/log/auth.log --fmt auth_log --output incident.md
    ```

=== "syslog"

    ```bash
    ais analyze /var/log/syslog --fmt syslog --output incident.md
    ```

=== "audit.log"

    ```bash
    ais analyze /var/log/audit/audit.log --fmt audit_log --output incident.md
    ```

=== "nginx access.log"

    ```bash
    ais analyze /var/log/nginx/access.log --fmt web_access --output incident.md
    ```

=== "Linux Sysmon"

    ```bash
    ais analyze /var/log/sysmon.xml --fmt sysmon_linux --output incident.md
    ```

Open `incident.md` in any Markdown viewer that renders Mermaid diagrams — GitHub, VS Code (with Mermaid plugin), or Obsidian.

---

## Verify forensic integrity

After ingestion, verify a log hasn't been tampered with:

```bash
ais verify /var/log/auth.log
```

| Exit code | Meaning |
|---|---|
| `0` | Hash matches — log is intact |
| `2` | Hash mismatch — log may have been modified |
| `1` | Log was never ingested (no hash on record) |

---

## Docker

```bash
# Demo — no log file needed
docker run --rm ghcr.io/lironabraham/ais-storyteller:latest demo

# Analyze logs from the host
docker run --rm \
  -v /var/log:/logs:ro \
  -v $(pwd)/reports:/workspace/reports \
  ghcr.io/lironabraham/ais-storyteller:latest \
  analyze /logs/auth.log --fmt auth_log --output /workspace/reports/incident.md
```

---

## Next steps

- [CLI Reference](cli-reference.md) — all flags and options
- [Supported Formats](supported-formats.md) — what each log format covers
- [Sample Report](sample-report.md) — see what the output looks like
