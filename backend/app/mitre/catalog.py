"""Subset of MITRE ATT&CK (Enterprise) techniques that SentinelX rules can map to.

Descriptions are short SentinelX summaries written for analysts; the authoritative
definitions live at attack.mitre.org (linked per technique).
"""

from sqlalchemy.orm import Session

from app.models import MITRETechnique

TACTIC_ORDER = [
    "Reconnaissance", "Credential Access", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# (id, name, tactic, description, detection guidance)
TECHNIQUES: list[tuple[str, str, str, str, str]] = [
    ("T1110", "Brute Force", "Credential Access",
     "Adversaries guess or systematically try passwords to gain access to accounts when credentials are unknown.",
     "Monitor authentication logs for many failures from one source or against one account in a short period."),
    ("T1110.001", "Brute Force: Password Guessing", "Credential Access",
     "Repeated password attempts against a single account or small set of accounts.",
     "Alert on bursts of failed logons for the same account, especially followed by a success."),
    ("T1110.003", "Brute Force: Password Spraying", "Credential Access",
     "A small number of common passwords is tried against many accounts to avoid per-account lockouts.",
     "Alert when one source fails authentication against many distinct accounts in a short window."),
    ("T1078", "Valid Accounts", "Initial Access",
     "Adversaries use legitimate credentials to log in, blending in with normal activity and bypassing controls.",
     "Baseline where and when accounts log in; investigate logins from unusual sources, times, or after failures."),
    ("T1098", "Account Manipulation", "Persistence",
     "Changes to accounts (permissions, group membership, credentials) to maintain or elevate access.",
     "Monitor group membership and permission changes, particularly to privileged groups."),
    ("T1098.007", "Account Manipulation: Additional Local or Domain Groups", "Privilege Escalation",
     "Adding an account to local or domain groups (e.g. Administrators, Domain Admins) to gain their privileges.",
     "Alert on additions to privileged groups (Windows events 4728/4732/4756) and verify against change tickets."),
    ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
     "Circumventing mechanisms that control privilege elevation to gain higher-level permissions.",
     "Monitor elevation events (sudo, runas, UAC) that are unusual for the user or host."),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation",
     "Using sudo (or cached sudo credentials) to execute commands as root.",
     "Review sudo usage by accounts that do not normally administer the system."),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
     "Abuse of PowerShell to execute commands, download payloads, and run code in memory.",
     "Enable script-block logging (event 4104) and alert on encoded, hidden, or download-cradle command lines."),
    ("T1027.010", "Obfuscated Files or Information: Command Obfuscation", "Defense Evasion",
     "Obfuscating command lines (e.g. Base64-encoded PowerShell) to evade detection and analysis.",
     "Decode encoded command lines and alert on -EncodedCommand / FromBase64String usage."),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
     "Decoding obfuscated payloads on the target, e.g. with certutil -decode.",
     "Alert on certutil -decode and similar built-in decoding utilities."),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     "Transferring tools or files from an external system into the environment.",
     "Monitor download cradles (DownloadString, Invoke-WebRequest, certutil -urlcache, bitsadmin)."),
    ("T1564.003", "Hide Artifacts: Hidden Window", "Defense Evasion",
     "Running processes with hidden windows (e.g. PowerShell -WindowStyle Hidden) to conceal activity.",
     "Alert on -WindowStyle Hidden / -w hidden combined with other suspicious flags."),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
     "Disabling or tampering with security tools such as AMSI or antivirus.",
     "Alert on AMSI bypass strings and attempts to stop security services."),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
     "Reading LSASS process memory to extract credential material (e.g. Mimikatz, procdump of lsass).",
     "Alert on access to lsass.exe by non-system tools and known credential-dumping command lines."),
    ("T1003.003", "OS Credential Dumping: NTDS", "Credential Access",
     "Copying the Active Directory database (NTDS.dit) to extract domain password hashes.",
     "Alert on ntdsutil IFM creation, shadow-copy access to ntds.dit, and reads of ntds.dit."),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access",
     "Searching files (password vaults, text files, keys) for stored credentials.",
     "Monitor access to credential stores such as .kdbx files, id_rsa keys and files named like passwords."),
    ("T1033", "System Owner/User Discovery", "Discovery",
     "Identifying the current user and logged-on users (e.g. whoami).",
     "Discovery commands are common individually; alert on several distinct discovery commands in quick succession."),
    ("T1087", "Account Discovery", "Discovery",
     "Enumerating local or domain accounts (e.g. net user, Get-ADUser).",
     "Alert on account enumeration combined with other discovery activity."),
    ("T1087.002", "Account Discovery: Domain Account", "Discovery",
     "Enumerating domain accounts (e.g. net user /domain, dsquery user).",
     "Alert on domain account enumeration from workstations of non-administrators."),
    ("T1069.001", "Permission Groups Discovery: Local Groups", "Discovery",
     "Enumerating local groups and their members (e.g. net localgroup administrators).",
     "Correlate with other discovery commands from the same session."),
    ("T1069.002", "Permission Groups Discovery: Domain Groups", "Discovery",
     "Enumerating domain groups and their members (e.g. net group \"Domain Admins\" /domain).",
     "Alert on enumeration of privileged domain groups."),
    ("T1018", "Remote System Discovery", "Discovery",
     "Listing other systems on the network (e.g. nltest /dclist, net view).",
     "Alert on domain controller discovery and network browsing from unusual hosts."),
    ("T1016", "System Network Configuration Discovery", "Discovery",
     "Collecting network configuration (ipconfig, route print, arp -a).",
     "Correlate with other discovery commands from the same session."),
    ("T1049", "System Network Connections Discovery", "Discovery",
     "Listing network connections (e.g. netstat).",
     "Correlate with other discovery commands from the same session."),
    ("T1082", "System Information Discovery", "Discovery",
     "Collecting OS and hardware details (e.g. systeminfo).",
     "Correlate with other discovery commands from the same session."),
    ("T1057", "Process Discovery", "Discovery",
     "Listing running processes (e.g. tasklist).",
     "Correlate with other discovery commands from the same session."),
    ("T1046", "Network Service Discovery", "Discovery",
     "Scanning hosts and ports to identify services (e.g. port scanning many internal hosts).",
     "Alert when one host connects to many distinct internal destinations in a short time."),
    ("T1569.002", "System Services: Service Execution", "Execution",
     "Executing commands via services, commonly with PsExec.",
     "Alert on psexec/psexesvc usage outside approved administration."),
    ("T1047", "Windows Management Instrumentation", "Execution",
     "Using WMI (e.g. wmic process call create) to execute commands locally or remotely.",
     "Alert on wmic process creation, especially with /node: targeting remote hosts."),
    ("T1218.005", "System Binary Proxy Execution: Mshta", "Defense Evasion",
     "Using mshta.exe to execute malicious HTA or script content.",
     "Alert on mshta.exe executing remote URLs or inline script."),
    ("T1218.010", "System Binary Proxy Execution: Regsvr32", "Defense Evasion",
     "Using regsvr32.exe to execute remote scriptlets (Squiblydoo).",
     "Alert on regsvr32 /i:http with scrobj.dll."),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion",
     "Using rundll32.exe to proxy execution of malicious code.",
     "Alert on rundll32 invoking javascript: or unusual DLL exports (e.g. comsvcs MiniDump)."),
    ("T1490", "Inhibit System Recovery", "Impact",
     "Deleting backups and shadow copies to prevent recovery, typical before ransomware encryption.",
     "Alert on vssadmin delete shadows, wbadmin delete catalog, bcdedit recoveryenabled no."),
    ("T1560.001", "Archive Collected Data: Archive via Utility", "Collection",
     "Compressing (and often encrypting) collected data with utilities such as 7-Zip or RAR before exfiltration.",
     "Alert on password-protected archive creation, especially of sensitive directories."),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence",
     "Creating scheduled tasks to execute code persistently.",
     "Alert on schtasks /create that launches scripts or binaries from user-writable paths."),
    ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence",
     "Adding programs to Run keys or the Startup folder so they execute at logon.",
     "Alert on reg add to ...\\CurrentVersion\\Run by non-installer processes."),
    ("T1136.001", "Create Account: Local Account", "Persistence",
     "Creating local accounts to maintain access.",
     "Alert on net user /add and Windows event 4720 outside provisioning workflows."),
    ("T1005", "Data from Local System", "Collection",
     "Collecting data of interest from the local system before exfiltration.",
     "Alert on unusual volumes of access to sensitive files."),
    ("T1039", "Data from Network Shared Drive", "Collection",
     "Collecting data from network shares.",
     "Alert on unusual volumes of access to sensitive network share paths."),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
     "Exfiltrating data over a protocol other than the existing command-and-control channel.",
     "Alert on large outbound transfers to external destinations not normally contacted."),
    ("T1048.002", "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
     "Exfiltration",
     "Exfiltrating data over an encrypted protocol such as HTTPS/SFTP to an adversary-controlled server.",
     "Alert on large outbound HTTPS/SFTP transfers to uncategorized external destinations."),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
     "Exfiltration",
     "Exfiltrating data over an unencrypted protocol such as FTP or plain HTTP.",
     "Alert on large outbound FTP/HTTP transfers to external destinations."),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration",
     "Uploading data to cloud storage services (e.g. MEGA, Dropbox) to exfiltrate it.",
     "Alert on large uploads to cloud storage domains not sanctioned by the organization."),
]


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


TECHNIQUE_INDEX = {
    t[0]: {"id": t[0], "name": t[1], "tactic": t[2], "description": t[3], "detection_guidance": t[4],
           "url": technique_url(t[0])}
    for t in TECHNIQUES
}


def tactic_rank(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


def seed_mitre(db: Session) -> int:
    existing = {t.id for t in db.query(MITRETechnique.id).all()}
    added = 0
    for tid, info in TECHNIQUE_INDEX.items():
        if tid in existing:
            continue
        db.add(MITRETechnique(
            id=tid, name=info["name"], tactic=info["tactic"], description=info["description"],
            detection_guidance=info["detection_guidance"], url=info["url"],
        ))
        added += 1
    if added:
        db.flush()
    return added
