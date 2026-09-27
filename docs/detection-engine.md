# Detection, anomaly and correlation engines

## Event schema

All telemetry is normalized to: `event_id, timestamp, event_type, user, source_ip, destination_ip, host, process, command, action, status, severity, bytes, resource, source, metadata` plus the untouched `raw` record. `event_type` is one of `authentication, process, file, network, privilege, other`. The full alias list is served at `/api/ingest/schema` and downloadable as Markdown from the upload page.

## Rules

Each rule receives the workspace's normalized events (time-sorted), its parameters and a context (business hours, indicators, users that received privileged logons). It returns candidates whose `explanation` is written from the matching evidence. Candidates are deduplicated with a `dedupe_key`, so re-running the pipeline never duplicates detections.

| Key | Rule | Logic (defaults, all tunable) | ATT&CK |
|---|---|---|---|
| SX-001 | Brute force | Failed logins grouped by source IP (or user); bursts split on 5-minute gaps; fires when any 5-minute window holds ≥10 failures. ≥10 distinct accounts ⇒ password spraying | T1110.001 / T1110.003 |
| SX-002 | Success after failures | Successful login preceded by ≥5 failures for that user in 30 minutes. Critical when the success comes from an external IP after ≥20 failures | T1110, T1078 |
| SX-003 | Suspicious privileged login | Privileged account (name pattern, config list, or Windows 4672) logs in outside business hours, from an external IP, or from a never-seen source after ≥3 prior logins | T1078 |
| SX-004 | Privilege escalation | Group-add to a privileged group (Administrators, Domain/Enterprise Admins, sudo, wheel...) via event or command line (`net localgroup ... /add`, `Add-ADGroupMember`, `usermod -aG`), or `sudo` to a root shell. Self-assignment and domain-level groups raise severity | T1098.007, T1548.003 |
| SX-005 | Suspicious PowerShell | Weighted indicators (encoded command, FromBase64String, download cradle, IEX, hidden window, bypass, Mimikatz modules, AMSI bypass, Office parent). Base64 payloads are decoded and re-scanned. Score ≥2.5 fires | T1059.001 (+T1027.010, T1105, T1564.003, T1562.001, T1003.001 when evidenced) |
| SX-006 | Internal discovery | ≥3 distinct discovery commands (whoami, net user/group/localgroup, nltest, ipconfig, netstat, systeminfo, tasklist, AD cmdlets, nmap) by one user/host in 15 minutes; or one source contacting ≥25 internal hosts in 5 minutes | T1033, T1087(.002), T1069.001/.002, T1018, T1016, T1049, T1082, T1057, T1046 |
| SX-007 | Suspicious process | Offensive tooling / LOLBin patterns: Mimikatz, LSASS dumps, NTDS extraction, shadow-copy deletion, PsExec, certutil, mshta, regsvr32, rundll32, WMI process create, password-protected archives, scheduled tasks, Run keys, account creation | per pattern (T1003.001, T1003.003, T1490, T1569.002, T1105, T1140, T1218.x, T1047, T1560.001, T1053.005, T1547.001, T1136.001) |
| SX-008 | Sensitive file access | ≥5 distinct sensitive files (path keywords) by one user in 30 minutes, or any credential store (ntds.dit, SAM, .kdbx, id_rsa, "passwords"). Off-hours majority raises severity | T1039 / T1005, T1003.003, T1552.001 |
| SX-009 | Data exfiltration | Outbound bytes to one external destination (IP outside private ranges, or a domain) ≥100 MB within 60 minutes. Internal destinations (e.g. backup servers) and sanctioned destinations are excluded | T1567.002 (cloud storage), T1048.002 (HTTPS/SFTP), T1048.003 (FTP/HTTP), T1048 (unknown, low confidence) |
| SX-010 | Threat-intel match | Event IP/domain/hash/hostname/username equals an active indicator with confidence ≥0.5 | none — an indicator match alone does not identify a technique |

### Why the mappings are conservative

A technique is attached only when the evidence shows it: SX-010 maps nothing; SX-009 distinguishes cloud storage from encrypted and unencrypted protocols and lowers mapping confidence when the protocol is unknown; SX-003 maps `T1078` with *medium* confidence. Incident technique rows keep the reason, the detection ids and example event ids.

### False positives

The normal Nova Bank dataset deliberately contains activity that naive rules would flag: nightly multi-GB backups (internal destination), administrators using `-ExecutionPolicy Bypass` scripts and `Get-ADUser`, IT staff running `ipconfig`, privileged logins from the jump host during business hours, routine group changes to non-privileged groups, VPN logins from home IPs, and occasional mistyped passwords. The test suite asserts that this dataset produces **zero** detections.

## Behavioral anomaly detection

Windows: one row per (user, UTC day) and per (host, UTC day).

Features: successful logins, failed logins, distinct source IPs, distinct hosts (or users for hosts), total events, bytes sent to external destinations, process executions, suspicious-command count, privilege events, sensitive-file accesses, off-hours ratio. Counts and bytes are `log1p`-transformed.

**Layer 1 — statistical baseline.** Robust z-scores `(x − median) / (1.4826·MAD)` against all windows in the workspace, plus against the entity's own other days when it has ≥3 of them. Deviations ≥2 are recorded as explanations; ≥3.5 counts as a baseline flag.

**Layer 2 — Isolation Forest.** `sklearn.ensemble.IsolationForest(n_estimators=200, contamination="auto", random_state=42)` fitted on the same matrix when there are at least 10 windows (otherwise it is skipped and the UI says so). Score = `-score_samples` (≈0.5 typical, higher is more unusual).

**Decision.** A window is anomalous when the IF score exceeds the workspace threshold (default 0.60, configurable) **and** at least one feature deviates with robust z ≥3, or when ≥3 features deviate with z ≥3.5 (≥2 when the forest could not run). IsolationForest does not attribute scores to features; the explanation shown is the Layer-1 deviations.

On the demo dataset this flags 18 of 283 windows, concentrated on the attack participants (for example `t.nguyen` on the day of the intrusion: IF 0.83, external bytes z≈14.7 vs own history, failed logins z≈12).

## Correlation

1. Load detections that are not yet in an incident and not dismissed, ordered by time.
2. Entity keys per detection: `user:`, `host:`, `ip:` (source, and destination when external). The host of an SX-001 burst is the *targeted* service (e.g. a VPN gateway shared by unrelated attacks), so it is not a key.
3. Union-find: a detection joins the most recent detection with the same key if it starts within the correlation window (default 120 minutes) after that detection's last event.
4. A cluster attaches to an open incident that shares a key and overlaps in time; otherwise it becomes a new incident if it has ≥2 detections or any high/critical detection. Remaining medium/low singletons stay as standalone detections that an analyst can promote.
5. `rebuild_incident` recomputes entities, stages (in observed order), title, correlation reason, evidence events and ±15-minute context events, MITRE techniques, anomaly summary, risk score and checklist. Severity escalations notify workspace members.

## SentinelX Risk Score

Additive, capped at 100, every factor shown to the analyst:

| Factor | Max |
|---|---|
| Highest detection severity (critical 30 / high 22 / medium 12 / low 5) | 30 |
| Average detection confidence × 10 | 10 |
| Attack-chain breadth (4 per distinct stage beyond the first) | 16 |
| Privilege escalation (10) or suspicious privileged login (5) | 10 |
| External data transfer (≥1 GB: 10, ≥100 MB: 7) | 10 |
| Distinct ATT&CK techniques (1 each) | 6 |
| Affected entities (2 per user/host, up to 8) + host criticality (critical 6 / high 4) | 12 |
| Behavioral anomaly (IF-confirmed 8, baseline only 4) | 8 |
| Threat-intelligence match | 6 |
| Evidence volume (≥100 events: 4, ≥20: 2) | 4 |

Bands: Low <25, Medium 25–49, High 50–74, Critical ≥75. It is a triage aid, not a probability.
