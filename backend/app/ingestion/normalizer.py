"""Normalize heterogeneous security telemetry into the SentinelX common event schema."""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

CANONICAL_FIELDS = (
    "event_id", "timestamp", "event_type", "user", "source_ip", "destination_ip", "host", "process",
    "command", "action", "status", "severity", "bytes", "resource", "source",
)

# Alias names are compared after lowercasing and stripping non-alphanumerics (dots kept for nested keys).
FIELD_ALIASES: dict[str, list[str]] = {
    "event_id": ["event_id", "eventid_uid", "uid", "record_id", "recordid", "event_uid", "log_id", "id", "event.id"],
    "timestamp": ["timestamp", "@timestamp", "time", "datetime", "date", "event_time", "eventtime", "ts",
                  "timecreated", "_time", "time_generated", "timegenerated", "created_at", "event.created"],
    "event_type": ["event_type", "eventtype", "type", "category", "event_category", "log_type", "event.category",
                   "event.type", "activity"],
    "user": ["user", "username", "user_name", "account", "account_name", "accountname", "targetusername",
             "user.name", "userprincipalname", "upn", "actor", "principal", "subject", "login", "uid_name",
             "subjectusername", "src_user", "user_id"],
    "source_ip": ["source_ip", "src_ip", "srcip", "src", "client_ip", "clientip", "sourceip", "source_address",
                  "src_addr", "ipaddress", "id.orig_h", "remote_ip", "remote_addr", "sourceipaddress",
                  "source.ip", "client.ip", "callerip", "ip"],
    "destination_ip": ["destination_ip", "dst_ip", "dstip", "dest_ip", "destip", "dst", "dest",
                       "destination_address", "dst_addr", "id.resp_h", "server_ip", "destinationip",
                       "destination.ip", "server.ip", "target_ip"],
    "host": ["host", "hostname", "host_name", "computer", "computername", "device", "device_name", "devicename",
             "endpoint", "machine", "workstation", "workstationname", "host.name", "agent.hostname", "system"],
    "process": ["process", "process_name", "processname", "image", "exe", "newprocessname", "program",
                "process.name", "process.executable", "app", "application"],
    "command": ["command", "command_line", "commandline", "cmd", "cmdline", "scriptblocktext",
                "process.command_line", "process_command_line", "query"],
    "action": ["action", "event_action", "operation", "event.action", "activity_name", "verb", "method"],
    "status": ["status", "outcome", "result", "event_outcome", "event.outcome", "auth_result", "disposition",
               "success"],
    "severity": ["severity", "level", "priority", "risk", "log_level", "event.severity", "severity_level"],
    "bytes": ["bytes", "bytes_out", "bytes_sent", "sent_bytes", "orig_bytes", "bytes_transferred", "size",
              "network.bytes", "source.bytes", "out_bytes", "sentbytes", "data_size", "transfer_bytes"],
    "resource": ["resource", "file", "file_path", "filepath", "filename", "path", "object", "objectname",
                 "object_name", "target", "url", "domain", "file.path", "url.full", "destination.domain",
                 "share", "sharename", "group", "group_name", "targetsid_group", "request"],
    "source": ["source", "log_source", "logsource", "provider", "product", "sourcetype", "source_type",
               "channel", "event.dataset", "event.module", "vendor"],
}

WINDOWS_EVENT_CODE_FIELDS = ["eventid", "event_code", "eventcode", "winlog.event_id", "winlog_event_id",
                             "windows_event_id", "event.code"]

WINDOWS_EVENT_CODES: dict[int, dict] = {
    4624: {"event_type": "authentication", "action": "login", "status": "success"},
    4625: {"event_type": "authentication", "action": "login", "status": "failure"},
    4634: {"event_type": "authentication", "action": "logout", "status": "success"},
    4647: {"event_type": "authentication", "action": "logout", "status": "success"},
    4648: {"event_type": "authentication", "action": "explicit_credential_login", "status": "success"},
    4672: {"event_type": "authentication", "action": "special_privileges_assigned", "status": "success",
           "privileged_logon": True},
    4740: {"event_type": "authentication", "action": "account_lockout", "status": "failure"},
    4688: {"event_type": "process", "action": "process_start"},
    4104: {"event_type": "process", "action": "script_block", "process": "powershell.exe"},
    4663: {"event_type": "file", "action": "file_access"},
    5145: {"event_type": "file", "action": "share_access"},
    5156: {"event_type": "network", "action": "connection"},
    4720: {"event_type": "privilege", "action": "account_created"},
    4728: {"event_type": "privilege", "action": "group_add"},
    4732: {"event_type": "privilege", "action": "group_add"},
    4756: {"event_type": "privilege", "action": "group_add"},
}

EVENT_TYPE_SYNONYMS = {
    "authentication": ["auth", "authentication", "login", "logon", "signin", "sign-in", "sign_in", "logoff",
                       "logout", "sso", "kerberos", "ntlm", "vpn", "session"],
    "process": ["process", "process_creation", "processcreate", "process_start", "execution", "exec", "proc",
                "powershell", "command", "script", "endpoint"],
    "file": ["file", "file_access", "fileaccess", "object_access", "file_read", "file_write", "fim", "share"],
    "network": ["network", "connection", "netflow", "conn", "traffic", "firewall", "flow", "proxy", "dns",
                "http", "web", "upload", "transfer"],
    "privilege": ["privilege", "privilege_change", "privilege_escalation", "group_change", "group_membership",
                  "account_change", "account_management", "iam", "role_change", "permission", "sudo"],
}
_TYPE_LOOKUP = {syn: canon for canon, syns in EVENT_TYPE_SYNONYMS.items() for syn in syns}

SUCCESS_WORDS = {"success", "succeeded", "successful", "ok", "allowed", "allow", "accept", "accepted",
                 "passed", "pass", "true", "1", "granted", "completed", "permit"}
FAILURE_WORDS = {"failure", "fail", "failed", "denied", "deny", "blocked", "block", "reject", "rejected",
                 "error", "invalid", "false", "0", "badpassword", "bad_password", "unauthorized", "locked"}

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_SYNONYMS = {
    "informational": "info", "information": "info", "info": "info", "debug": "info", "notice": "info",
    "low": "low", "warning": "low", "warn": "low", "medium": "medium", "moderate": "medium", "error": "medium",
    "high": "high", "severe": "high", "critical": "critical", "crit": "critical", "emergency": "critical",
    "alert": "high", "fatal": "critical",
}

INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10",
)]


def is_internal_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS)


def is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return not is_internal_ip(value)


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9@._]", "", name.strip().lower().replace("-", "_").replace(" ", "_"))


_ALIAS_INDEX: dict[str, str] = {}
for _canon, _aliases in FIELD_ALIASES.items():
    for _a in _aliases:
        _ALIAS_INDEX.setdefault(_key(_a), _canon)
_WIN_CODE_KEYS = {_key(k) for k in WINDOWS_EVENT_CODE_FIELDS}


def flatten(obj: dict, prefix: str = "", depth: int = 0, out: dict | None = None) -> dict:
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and depth < 3:
            flatten(v, key, depth + 1, out)
        else:
            out[key] = v
    return out


def build_field_mapping(columns: list[str]) -> dict[str, str]:
    """Map input column names to canonical fields. First alias match (by priority order) wins."""
    mapping: dict[str, str] = {}
    taken: set[str] = set()
    # Prioritise by the alias order so e.g. 'source_ip' beats a generic 'ip' column.
    keyed = {_key(c): c for c in columns}
    for canon, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            col = keyed.get(_key(alias))
            if col is not None and col not in mapping and canon not in taken:
                mapping[col] = canon
                taken.add(canon)
                break
    return mapping


def parse_timestamp(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value.strip())):
        num = float(value)
        if num > 1e11:  # milliseconds
            num /= 1000.0
        try:
            dt = datetime.fromtimestamp(num, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value).strip()
        dt = None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00") if text.endswith("Z") else text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
                        "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%d %b %Y %H:%M:%S",
                        "%b %d %Y %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    now = datetime.now(UTC).replace(tzinfo=None)
    if dt.year < 1990 or dt > now + timedelta(days=2):
        return None
    return dt


def clean_ip(value) -> tuple[str | None, str | None]:
    if value is None or str(value).strip() in ("", "-", "null", "None", "N/A"):
        return None, None
    text = str(value).strip().strip("[]")
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", text)
    if m:
        text = m.group(1)
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        return None, f"invalid IP address '{str(value)[:60]}'"


def parse_bytes(value) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().replace(",", "").upper()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB)?", text)
    if not m:
        return None
    mult = {None: 1, "B": 1, "KB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000, "TB": 1_000_000_000_000,
            "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3}[m.group(2)]
    return int(float(m.group(1)) * mult)


def normalize_status(value, action: str | None) -> str | None:
    if value is not None and value != "":
        v = str(value).strip().lower().replace(" ", "_")
        if v in SUCCESS_WORDS:
            return "success"
        if v in FAILURE_WORDS or any(w in v for w in ("fail", "denied", "invalid", "bad_pass")):
            return "failure"
        if "success" in v:
            return "success"
        return v[:32]
    if action:
        a = action.lower()
        if any(w in a for w in ("fail", "denied", "invalid", "reject")):
            return "failure"
        if "success" in a:
            return "success"
    return None


def normalize_severity(value) -> str:
    if value is None or value == "":
        return "info"
    if isinstance(value, (int, float)) or re.fullmatch(r"\d+(\.\d+)?", str(value).strip()):
        n = float(value)
        if n >= 9:
            return "critical"
        if n >= 7:
            return "high"
        if n >= 4:
            return "medium"
        if n >= 1:
            return "low"
        return "info"
    return SEVERITY_SYNONYMS.get(str(value).strip().lower(), "info")


def normalize_event_type(value, fields: dict) -> str:
    if value:
        v = str(value).strip().lower().replace(" ", "_")
        if v in _TYPE_LOOKUP:
            return _TYPE_LOOKUP[v]
        for syn, canon in _TYPE_LOOKUP.items():
            if len(syn) > 3 and syn in v:
                return canon
    action = (fields.get("action") or "").lower()
    if any(w in action for w in ("login", "logon", "auth", "sign")):
        return "authentication"
    if any(w in action for w in ("group", "privilege", "role", "sudo", "grant", "elevat")):
        return "privilege"
    if fields.get("command") or fields.get("process"):
        return "process"
    if fields.get("bytes") is not None and fields.get("destination_ip"):
        return "network"
    res = fields.get("resource") or ""
    if "\\" in res or "/" in res and "." in res.split("/")[-1]:
        return "file"
    return "other"


@dataclass
class NormalizedRow:
    fields: dict
    raw: dict
    fingerprint: str
    warnings: list[str] = field(default_factory=list)


class RowError(Exception):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


def normalize_record(record: dict, mapping: dict[str, str] | None = None) -> NormalizedRow:
    if not isinstance(record, dict):
        raise RowError("row is not an object")
    flat = flatten(record)
    if mapping is None:
        mapping = build_field_mapping(list(flat.keys()))
    values: dict = {}
    metadata: dict = {}
    warnings: list[str] = []
    win_code = None
    for col, val in flat.items():
        canon = mapping.get(col)
        if isinstance(val, str):
            val = val.strip()
            if val in ("", "-", "null", "NULL", "None", "N/A"):
                val = None
        if canon:
            values[canon] = val
        elif _key(col) in _WIN_CODE_KEYS and val is not None:
            try:
                win_code = int(str(val).strip())
            except ValueError:
                metadata[col] = val
        elif val is not None:
            metadata[col] = val

    ts = parse_timestamp(values.get("timestamp"))
    if values.get("timestamp") in (None, ""):
        raise RowError("missing required field 'timestamp'")
    if ts is None:
        raise RowError(f"unparseable or out-of-range timestamp '{str(values.get('timestamp'))[:40]}'")

    out: dict = {"timestamp": ts}
    for key in ("user", "host", "process", "command", "resource", "source"):
        v = values.get(key)
        out[key] = str(v)[: (4000 if key in ("command", "resource") else 255)] if v is not None else None
    if out["user"]:
        u = out["user"]
        if "\\" in u:  # DOMAIN\user -> user, keep domain in metadata
            domain, _, u = u.rpartition("\\")
            metadata.setdefault("domain", domain)
        out["user"] = u.lower()[:128]
    if out["host"]:
        out["host"] = out["host"].upper()[:128]

    for key in ("source_ip", "destination_ip"):
        ip, problem = clean_ip(values.get(key))
        out[key] = ip
        if problem:
            warnings.append(f"{key}: {problem} (field dropped)")
            metadata[f"{key}_original"] = str(values.get(key))[:100]

    b = parse_bytes(values.get("bytes"))
    if values.get("bytes") not in (None, "") and b is None:
        warnings.append(f"bytes: could not parse '{str(values.get('bytes'))[:30]}' (field dropped)")
    out["bytes"] = b

    action = values.get("action")
    out["action"] = str(action).strip().lower().replace(" ", "_")[:64] if action is not None else None

    if win_code is not None:
        metadata["windows_event_id"] = win_code
        info = WINDOWS_EVENT_CODES.get(win_code)
        if info:
            out["action"] = out["action"] or info.get("action")
            if info.get("process") and not out["process"]:
                out["process"] = info["process"]
            if info.get("privileged_logon"):
                metadata["privileged_logon"] = True

    out["status"] = normalize_status(values.get("status"), out["action"])
    if win_code in WINDOWS_EVENT_CODES and WINDOWS_EVENT_CODES[win_code].get("status") and out["status"] is None:
        out["status"] = WINDOWS_EVENT_CODES[win_code]["status"]
    out["severity"] = normalize_severity(values.get("severity"))

    if win_code in WINDOWS_EVENT_CODES and not values.get("event_type"):
        out["event_type"] = WINDOWS_EVENT_CODES[win_code]["event_type"]
    else:
        out["event_type"] = normalize_event_type(values.get("event_type"), out)
    if out["event_type"] == "other" and values.get("event_type"):
        metadata.setdefault("original_event_type", str(values.get("event_type"))[:64])

    if not any(out.get(k) for k in ("user", "host", "source_ip", "destination_ip", "process", "command",
                                    "resource", "action")):
        raise RowError("row has no identifiable security fields (user, host, IP, process, command, resource or action)")

    raw_json = canonical_json(record)
    supplied_id = values.get("event_id")
    if supplied_id not in (None, ""):
        out["event_uid"] = str(supplied_id)[:128]
        fingerprint = hashlib.sha256(("uid:" + out["event_uid"]).encode()).hexdigest()
    else:
        fingerprint = hashlib.sha256(raw_json.encode()).hexdigest()
        out["event_uid"] = "EVT-" + fingerprint[:12].upper()
    out["metadata"] = metadata
    return NormalizedRow(fields=out, raw=record, fingerprint=fingerprint, warnings=warnings)
