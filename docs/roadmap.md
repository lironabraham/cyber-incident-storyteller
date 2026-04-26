# Roadmap

Planned feature phases for Cyber Incident Storyteller. The tool is production-ready today
for single-host Linux and Windows EVTX analysis. The roadmap expands coverage toward
multi-host campaign correlation and cloud-native log sources.

---

## Phase 4 — Living-off-the-Land (LOLBin) Detection ✓ DONE

Detect and correlate suspicious Living-off-the-Land (LOLBin) process executions with follow-on attacker activity.

**Completed:**
- Pass 4.5 LOLBin correlation engine in `hunter.py` — correlates Sysmon Process Created events (EID 1) where `is_lolbin=True` with follow-on events (network, registry write, process access, child process) within 60-second window
- `is_lolbin` field on `StandardEvent` — set when MITRE technique is T1218.*, T1021.*, T1140, T1197, T1220, or T1047
- Expanded `SUSPICIOUS_COMMANDS` in `mitre.py` with 20+ LOLBin entries: `sharprdp`, `pcalua`, `wuauclt`, `msxsl`, `appcmd`, `wsmprovhost`, `sqlcmd`, and more
- Expanded `_PERSISTENCE_KEY_RE` in `sysmon_evtx.py` covering 20+ registry key patterns (IFEO, KnownDLLs, COM hijacking, CLR profiler, GPO scripts, LSA packages, UAC policies, input hooks)
- EID 10 code-injection detection — passes events with `PROCESS_VM_WRITE (0x0020)` to catch shellcode injection into arbitrary targets
- Coverage improvement: 240/285 samples detected (84%), up from 179/278 (65%)

---

## Phase 5 — Expanded Windows EventID Coverage

Add the Windows EventIDs most commonly seen in enterprise DFIR engagements that are not
yet in the EVTX parser.

**Key additions:**
- 4740 Account Lockout — detects automated spraying locking accounts
- 4776 NTLM Authentication — catches NTLM relay without Kerberos
- 4663 Object Access — detects sensitive file reads (SAM, NTDS.dit)
- 4670 Permission Change — detects ACL modification on sensitive objects
- 4946/4947/4950 Firewall Rule Change — detects defense evasion via firewall

---

## Phase 6 — Advanced Windows Attack Techniques

Improve detection fidelity for techniques that require correlating multiple EventIDs
rather than mapping individual events.

**Key additions:**
- T1134 Token Impersonation (correlating LogonType 9 + ANONYMOUS LOGON)
- Pass-the-Ticket detection via 4768/4769 anomaly patterns
- DCSync detection via 4662 Directory Service Access
- Living-off-the-Land (LOLBin) behavioral chain detection

---

## Phase 7 — Cloud Log Sources

Ingest cloud provider audit logs and surface attack chains spanning on-premises to cloud.

**Key additions:**
- AWS CloudTrail (`fmt=cloudtrail`)
- Azure Activity Log / Azure AD Sign-in Log (`fmt=azure_activity`)
- GCP Cloud Audit Logs (`fmt=gcp_audit`)
- Cross-cloud MITRE mapping (T1078.004 Cloud Accounts, T1530 Data from Cloud Storage)

---

## Phase 8 — Network Log Sources

Add network-layer telemetry to correlate host-based events with observed traffic.

**Key additions:**
- Zeek / Bro logs (`fmt=zeek`)
- Suricata / Snort alerts (`fmt=suricata`)
- Firewall logs — pfSense, Cisco ASA (`fmt=firewall`)
- DNS query logs (`fmt=dns`) — detects C2 beaconing patterns

---

## Phase 9 — Container and Kubernetes

Extend coverage to containerized workloads — the fastest-growing DFIR surface.

**Key additions:**
- Docker daemon logs (`fmt=docker`)
- Kubernetes audit log (`fmt=k8s_audit`)
- Container escape detection (privileged pod, hostPath mount, nsenter)
- K8s RBAC abuse chains (ClusterRoleBinding creation → lateral movement)

---

## Phase 10 — SOAR Integration and Alerting

Push incident reports into security orchestration workflows and alerting pipelines.

**Key additions:**
- Webhook output — POST generated report to Slack, Teams, PagerDuty
- STIX 2.1 export — machine-readable threat intelligence output
- Splunk / Elastic index writer — stream `StandardEvent` objects to SIEM
- Scheduled watch mode — `ais watch <log_path>` tails a live log and alerts on new chains

---

> See the [Detection Coverage](detection-coverage.md) page for what's implemented today.
