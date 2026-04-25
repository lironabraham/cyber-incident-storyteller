# Forensic Integrity Design

## Overview

Cyber Incident Storyteller is built around a core forensic guarantee: **the original log file is never modified**. Every analysis operation is read-only against source evidence. This document describes how integrity is established, preserved, and verified throughout the pipeline.

---

## The Guarantee

```
Source log file  ──read-only──▶  ingest()  ──writes──▶  data/processed/
                                                          ├── <stem>.sha256
                                                          └── <stem>.json
```

- `ingest()` opens log files with `open(path, 'r')` — never `'w'` or `'a'`
- Processed output goes exclusively to `data/processed/` — a separate directory
- The source file's SHA-256 hash is computed **before** any parsing begins
- No tool in the pipeline has write access to the `logs/` directory

---

## SHA-256 Chain of Custody

### How it works

When `ingest()` processes a log file it:

1. Computes `SHA-256(source_log)` by reading the file in 64 KB chunks
2. Writes the hex digest to `data/processed/<stem>.sha256`
3. Parses and normalises the log into `StandardEvent` objects
4. Serialises those events to `data/processed/<stem>.json`

The hash is stored **before** parsing so that even a parse error mid-file does not prevent the integrity record from being created.

### Verifying integrity

```bash
# CLI
ais verify logs/auth.log

# Python
from ais import verify_integrity
ok = verify_integrity('logs/auth.log')   # True = hash matches; False = tampered or not ingested
```

`verify_integrity()` recomputes the SHA-256 of the current file and compares it to the stored digest. A mismatch means the file was modified after ingestion — a forensically significant event.

Exit codes from `ais verify`:
- `0` — hash matches; evidence is intact
- `2` — hash mismatch or no hash file found (log never ingested, or tampered)

---

## Processed Event Schema

`data/processed/<stem>.json` contains a JSON array of serialised `StandardEvent` objects. Each object has the following fields:

| Field | Type | Description |
|---|---|---|
| `event_id` | `string` (UUID4) | Unique identifier for this parsed event |
| `timestamp` | `string` (ISO 8601 UTC) | e.g. `"2024-04-23T10:00:00+00:00"` |
| `event_type` | `string` | e.g. `"Failed Login"`, `"Accepted Password"` |
| `source_actor` | `object` | `{"ip": string\|null, "user": string\|null}` |
| `target_system` | `object` | `{"hostname": string, "process": string}` |
| `action_taken` | `string` | Human-readable description of the event |
| `severity` | `string` | `"info"` \| `"low"` \| `"medium"` \| `"high"` \| `"critical"` |
| `mitre_technique` | `object` | `{"id": string\|null, "name": string\|null}` |
| `raw` | `string` | The original unmodified log line |
| `source_log` | `string` | Filename of the origin log (e.g. `"auth.log"`) |
| `log_format` | `string` | Parser used: `auth_log`, `syslog`, `audit_log`, `web_access`, `sysmon_linux`, `evtx` |
| `pid` | `string\|null` | Process ID extracted from syslog-style lines |

The `raw` field preserves the exact original log line byte-for-byte, enabling independent verification that the parsed event faithfully represents the source evidence.

---

## Severity Model

Severity is **context-aware**, not static per event type:

| Condition | Severity |
|---|---|
| Single failed login from an IP | `low` |
| 5+ failed logins from one IP | `medium` |
| 20+ failed logins from one IP | `high` |
| Successful login after 5+ failures from same IP | `critical` |
| Sudo command execution | `high` |
| Web shell access | `critical` |
| Normal session lifecycle events | `info` |

This means severity reflects the **investigation context**, not just the individual event — consistent with how experienced analysts triage logs.

---

## Evidentiary Considerations

- **Chain of custody:** The `.sha256` file alongside the `.json` file constitutes a timestamped integrity record. Store `data/processed/` on write-protected or append-only storage for maximum evidentiary value.
- **UUID event IDs:** Every `StandardEvent` carries a UUID4 `event_id`. These are stable identifiers for referencing specific events in reports, tickets, or legal proceedings.
- **Raw line preservation:** The `raw` field means the processed JSON can be used to reconstruct the exact original log entry without re-accessing the source file.
- **No enrichment mutation:** Threat intelligence enrichment (Phase 3) will augment events with additional context but must never modify the `raw`, `timestamp`, or `event_id` fields.
