# Roadmap

Planned feature phases for Cyber Incident Storyteller. The tool is production-ready today
for single-host Linux and Windows EVTX analysis. The roadmap expands coverage toward
multi-host campaign correlation and cloud-native log sources.

---

## Phase 4 — Multi-Log Correlation

Correlate events across multiple log files from the same host into a single unified attack
timeline. Today each `ais analyze` run operates on one file; Phase 4 merges auth.log,
audit.log, and syslog into one campaign view.

**Key additions:**
- Single `ais analyze --multi` flag accepting a directory of log files
- Cross-source event deduplication and timeline merging
- Unified attack chain spanning SSH brute-force (auth.log) → shell (audit.log) → persistence (syslog)

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
