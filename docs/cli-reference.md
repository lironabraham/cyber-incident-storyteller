# CLI Reference

## `ais analyze`

Parse a log file, hunt attack chains, and write a Markdown incident report.

```
ais analyze <log_path> [options]
```

| Option | Default | Description |
|---|---|---|
| `--fmt` | `auth_log` | Log format: `auth_log` \| `syslog` \| `audit_log` \| `web_access` \| `sysmon_linux` |
| `--output` | `reports/incident.md` | Path to write the Markdown report |
| `--processed-dir` | `data/processed` | Directory for SHA-256 hashes and serialized event cache |
| `--threshold` | `5` | Minimum failed logins to flag an IP as a threat actor |

**Examples:**

```bash
# SSH brute-force investigation
ais analyze /var/log/auth.log --fmt auth_log --output reports/ssh_incident.md

# Web attack investigation
ais analyze /var/log/nginx/access.log --fmt web_access --output reports/web_incident.md

# Lower threshold — flag IPs after just 3 failures
ais analyze /var/log/auth.log --threshold 3

# Custom output directories
ais analyze /var/log/auth.log \
  --output /tmp/reports/incident.md \
  --processed-dir /tmp/processed
```

---

## `ais verify`

Verify a log file's SHA-256 hash matches the record stored at ingest time.

```
ais verify <log_path> [options]
```

| Option | Default | Description |
|---|---|---|
| `--processed-dir` | `data/processed` | Directory containing the stored SHA-256 hash |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Hash matches — log is intact |
| `1` | Error (log file not found, or never ingested) |
| `2` | Hash mismatch — log may have been tampered with |

**Example:**

```bash
ais verify /var/log/auth.log
# exit 0 → chain of custody intact
# exit 2 → log was modified after ingestion
```

---

## `ais demo`

Generate synthetic attack logs, run the full pipeline, and print the report to stdout. No log file or arguments required.

```
ais demo
```

Useful for:

- Verifying the install worked correctly
- Live demos without needing a real compromised host
- Testing pipeline changes during development

---

## Global behavior

- **Source logs are never modified.** All writes go to `--processed-dir` and `--output`.
- **SHA-256 hashes** are written to `<processed-dir>/<stem>_<hash>.sha256` at ingest time.
- **Exit code `0`** on success, **`1`** on any error, **`2`** on integrity failure.
