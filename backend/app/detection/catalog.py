"""Default SentinelX detection rules. Each workspace receives its own editable copy."""

DEFAULT_RULES: list[dict] = [
    {
        "rule_key": "SX-001", "name": "Brute Force Authentication",
        "description": "Many failed authentication attempts from the same source (or against the same account) "
                       "within a short window. Detects password guessing and password spraying.",
        "severity": "medium", "stage": "Credential Access", "mitre_techniques": ["T1110.001", "T1110.003"],
        "parameters": {"failure_threshold": 10, "window_minutes": 5, "spray_account_threshold": 10},
    },
    {
        "rule_key": "SX-002", "name": "Successful Login After Repeated Failures",
        "description": "A successful login for an account that recently accumulated many failed attempts - "
                       "a strong signal that a guessing attack succeeded.",
        "severity": "high", "stage": "Initial Access", "mitre_techniques": ["T1110", "T1078"],
        "parameters": {"failure_threshold": 5, "lookback_minutes": 30},
    },
    {
        "rule_key": "SX-003", "name": "Suspicious Privileged Login",
        "description": "Successful login by a privileged account outside business hours, from an external "
                       "address, or from a source never seen before for that account.",
        "severity": "medium", "stage": "Initial Access", "mitre_techniques": ["T1078"],
        "parameters": {"privileged_name_patterns": ["admin", "adm.", "adm_", "administrator", "root", "da-"],
                       "privileged_accounts": [], "min_history_logins": 3},
    },
    {
        "rule_key": "SX-004", "name": "Privilege Escalation",
        "description": "An account is added to a privileged group (Administrators, Domain Admins, sudo/wheel) or "
                       "uses elevation to obtain a root shell.",
        "severity": "high", "stage": "Privilege Escalation", "mitre_techniques": ["T1098.007", "T1548.003"],
        "parameters": {"privileged_groups": ["administrators", "domain admins", "enterprise admins",
                                             "schema admins", "account operators", "backup operators",
                                             "sudo", "wheel", "root", "admins"]},
    },
    {
        "rule_key": "SX-005", "name": "Suspicious PowerShell",
        "description": "PowerShell command lines combining obfuscation, download cradles, hidden windows, "
                       "AMSI bypasses or credential-theft modules.",
        "severity": "high", "stage": "Execution",
        "mitre_techniques": ["T1059.001", "T1027.010", "T1105", "T1564.003", "T1562.001", "T1003.001"],
        "parameters": {"score_threshold": 2.5, "cluster_minutes": 15},
    },
    {
        "rule_key": "SX-006", "name": "Internal Discovery",
        "description": "Several distinct reconnaissance commands in quick succession from one account/host, or "
                       "one host connecting to many internal systems (scanning).",
        "severity": "medium", "stage": "Discovery",
        "mitre_techniques": ["T1033", "T1087", "T1087.002", "T1069.001", "T1069.002", "T1018", "T1016",
                             "T1049", "T1082", "T1057", "T1046"],
        "parameters": {"distinct_command_threshold": 3, "window_minutes": 15, "scan_host_threshold": 25,
                       "scan_window_minutes": 5},
    },
    {
        "rule_key": "SX-007", "name": "Suspicious Process Execution",
        "description": "Execution of known offensive tools and abused system binaries: credential dumping, "
                       "PsExec, shadow-copy deletion, LOLBin proxy execution, persistence creation.",
        "severity": "high", "stage": "Execution",
        "mitre_techniques": ["T1003.001", "T1003.003", "T1569.002", "T1490", "T1105", "T1140", "T1218.005",
                             "T1218.010", "T1218.011", "T1047", "T1560.001", "T1053.005", "T1547.001",
                             "T1136.001"],
        "parameters": {"cluster_minutes": 30},
    },
    {
        "rule_key": "SX-008", "name": "Sensitive File Access",
        "description": "An account accesses an unusual number of sensitive files in a short window, or touches "
                       "credential stores (NTDS.dit, password vaults, private keys).",
        "severity": "medium", "stage": "Collection", "mitre_techniques": ["T1005", "T1039", "T1003.003", "T1552.001"],
        "parameters": {"distinct_file_threshold": 5, "window_minutes": 30,
                       "sensitive_patterns": ["confidential", "restricted", "payroll", "salary", "customer",
                                              "pii", "wire_transfer", "swift", "board", "merger", "secret",
                                              "\\finance\\", "\\hr\\", "cardholder", "account_numbers"],
                       "credential_patterns": ["ntds.dit", "\\config\\sam", ".kdbx", "id_rsa", "passwords",
                                               "credentials", ".pfx"]},
    },
    {
        "rule_key": "SX-009", "name": "Potential Data Exfiltration",
        "description": "Large outbound data transfer from an account or host to an external destination within "
                       "a short window.",
        "severity": "high", "stage": "Exfiltration", "mitre_techniques": ["T1048", "T1048.002", "T1048.003", "T1567.002"],
        "parameters": {"bytes_threshold": 100_000_000, "window_minutes": 60,
                       "cloud_storage_domains": ["mega.nz", "mega.io", "dropbox.com", "wetransfer.com",
                                                 "drive.google.com", "box.com", "pastebin.com", "transfer.sh",
                                                 "anonfiles.com", "gofile.io"],
                       "sanctioned_destinations": []},
    },
    {
        "rule_key": "SX-010", "name": "Threat Intelligence Match",
        "description": "Telemetry references an indicator (IP, domain, hash, hostname or username) present in "
                       "the workspace threat-intelligence store.",
        "severity": "medium", "stage": "Threat Intelligence", "mitre_techniques": [],
        "parameters": {"min_confidence": 0.5},
    },
]

RULE_GUIDANCE: dict[str, dict[str, list[str]]] = {
    "SX-001": {
        "false_positives": [
            "A user repeatedly entering an expired or mistyped password (usually a handful of attempts, not dozens).",
            "Misconfigured service, mapped drive or mobile mail client retrying stale credentials.",
            "Authorized penetration test or vulnerability scanner.",
        ],
        "recommendations": [
            "Check whether any of the targeted accounts later authenticated successfully (see SX-002).",
            "Determine whether the source address {source_ip} is internal, a VPN egress, or unknown external infrastructure.",
            "Consider blocking {source_ip} at the perimeter and enforcing MFA / lockout on targeted accounts.",
        ],
    },
    "SX-002": {
        "false_positives": [
            "A user who forgot their password, reset it, and then logged in (verify with helpdesk tickets).",
            "Service account with a recently rotated password and stale clients retrying.",
        ],
        "recommendations": [
            "Contact {user} out-of-band to confirm whether they performed this login.",
            "Review all activity by {user} after the successful login, especially privilege changes and data access.",
            "If unconfirmed: disable or reset the account, revoke sessions, and require MFA re-enrolment.",
        ],
    },
    "SX-003": {
        "false_positives": [
            "Planned maintenance or on-call administration outside business hours.",
            "Administrator working from a new device, VPN node or location.",
        ],
        "recommendations": [
            "Validate the login against change-management records and the on-call schedule.",
            "Review commands and group changes performed by {user} in the session.",
            "Confirm that privileged access is restricted to jump hosts / PAW devices.",
        ],
    },
    "SX-004": {
        "false_positives": [
            "Approved access request fulfilled by IT (check the ticketing system).",
            "Automated provisioning or break-glass procedure.",
        ],
        "recommendations": [
            "Verify there is an approved change for the group membership change by {user}.",
            "Remove unauthorized membership immediately and review what the elevated account did afterwards.",
            "Hunt for other privileged group changes by the same actor or from the same host ({host}).",
        ],
    },
    "SX-005": {
        "false_positives": [
            "Administrative or software-deployment scripts that use -EncodedCommand legitimately (e.g. SCCM, Intune).",
            "Security tooling that downloads signatures or modules with PowerShell.",
        ],
        "recommendations": [
            "Decode and review the full command line and any downloaded script content.",
            "Identify the parent process on {host} (Office documents spawning PowerShell are high risk).",
            "Isolate {host} if the script downloaded or executed remote code; collect memory for analysis.",
        ],
    },
    "SX-006": {
        "false_positives": [
            "IT staff troubleshooting (ipconfig, whoami, systeminfo) - usually on their own systems.",
            "Inventory or vulnerability-management scanners (should run from known scanner hosts).",
        ],
        "recommendations": [
            "Establish whether {user} normally runs administrative commands on {host}.",
            "Look for preceding initial-access activity and subsequent lateral movement from {host}.",
            "Check whether scanning originated from an approved scanner address.",
        ],
    },
    "SX-007": {
        "false_positives": [
            "Administrators using PsExec or WMI for sanctioned remote management.",
            "Backup or recovery tooling that manipulates shadow copies.",
        ],
        "recommendations": [
            "Treat credential-dumping activity as a confirmed compromise until disproven: reset exposed credentials.",
            "Isolate {host} and acquire forensic artefacts (memory, prefetch, event logs).",
            "Search for the same command lines on other hosts.",
        ],
    },
    "SX-008": {
        "false_positives": [
            "Finance, HR or legal staff performing month-end, audit or reporting tasks.",
            "Backup, indexing or DLP scanning services reading many files.",
        ],
        "recommendations": [
            "Confirm whether {user}'s role requires access to the listed files and whether the timing is normal.",
            "Check for archive creation or outbound transfers after the access (possible staging for exfiltration).",
            "Review share permissions on the accessed paths.",
        ],
    },
    "SX-009": {
        "false_positives": [
            "Sanctioned cloud backup, large software uploads or video conferencing.",
            "Transfers to a partner or cloud service that is not yet in the sanctioned-destination list.",
        ],
        "recommendations": [
            "Identify the destination {destination} (ownership, reputation, whether it is sanctioned).",
            "Correlate with preceding sensitive-file access and archive creation by {user}.",
            "Block the destination and preserve proxy/firewall logs; assess regulatory notification obligations.",
        ],
    },
    "SX-010": {
        "false_positives": [
            "Stale or low-quality indicators (shared hosting, CDN or cloud IPs reassigned since listing).",
            "Security tooling or analysts intentionally contacting the indicator.",
        ],
        "recommendations": [
            "Review the indicator's source, confidence and age before acting.",
            "Check what data was exchanged with the indicator and which hosts/users were involved.",
            "Block the indicator if confirmed malicious and hunt for other occurrences.",
        ],
    },
}
