"""SentinelX detection rule implementations.

Every rule receives the workspace's normalized events (time-sorted), its parameters and a context,
and returns Candidates whose explanations are built from the actual matching evidence.
"""

import base64
import binascii
import re
from bisect import bisect_left
from collections import defaultdict
from datetime import timedelta

from app.detection.base import (
    Candidate,
    Ev,
    RuleContext,
    cluster_by_gap,
    densest_window,
    distinct,
    fmt_bytes,
    fmt_duration,
    fmt_ts,
    is_off_hours,
    join_limited,
    max_severity,
    most_common,
)
from app.detection.catalog import RULE_GUIDANCE
from app.ingestion.normalizer import is_external_ip, is_internal_ip


def _guidance(rule_key: str, **entities) -> tuple[list[str], list[str]]:
    g = RULE_GUIDANCE[rule_key]
    safe = defaultdict(lambda: "the entity", {k: (v or "the entity") for k, v in entities.items()})
    recs = [r.format_map(safe) for r in g["recommendations"]]
    return list(g["false_positives"]), recs


def _t(tid: str, reason: str, confidence: str = "high") -> dict:
    return {"id": tid, "reason": reason, "mapping_confidence": confidence}


def _is_login(e: Ev) -> bool:
    if e.type != "authentication":
        return False
    a = (e.action or "").lower()
    return not any(w in a for w in ("logout", "logoff", "special_priv", "lockout"))


# --------------------------------------------------------------------------------------------- SX-001
def brute_force(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = int(p.get("failure_threshold", 10))
    window = timedelta(minutes=float(p.get("window_minutes", 5)))
    spray_threshold = int(p.get("spray_account_threshold", 10))
    groups: dict[str, list[Ev]] = defaultdict(list)
    for e in events:
        if _is_login(e) and e.status == "failure":
            key = f"ip:{e.src}" if e.src else (f"user:{e.user}" if e.user else None)
            if key:
                groups[key].append(e)
    out = []
    for key, fails in groups.items():
        for burst in cluster_by_gap(fails, window):
            peak, w_start, w_end = densest_window(burst, window)
            if peak < threshold:
                continue
            users = distinct(e.user for e in burst)
            src = burst[0].src
            spray = len(users) >= spray_threshold
            span = burst[-1].ts - burst[0].ts
            external = is_external_ip(src)
            sev = "high" if (spray or external or peak >= 3 * threshold) else "medium"
            conf = round(min(0.95, 0.6 + 0.35 * min(1.0, peak / (3 * threshold))), 2)
            who = f"source IP {src}" if src else f"account {burst[0].user}"
            if spray:
                title = f"Password spraying: {len(users)} accounts targeted from {src or 'one source'}"
                target_txt = f"{len(users)} distinct accounts ({join_limited(users)})"
                mitre = [_t("T1110.003", f"{len(burst)} failures spread across {len(users)} accounts from one source "
                                         "is characteristic of password spraying.")]
            else:
                title = f"Brute force: {len(burst)} failed logins for {join_limited(users, 2)}" + (f" from {src}" if src else "")
                target_txt = f"user {join_limited(users)}"
                mitre = [_t("T1110.001", f"{len(burst)} failed password attempts against {join_limited(users, 3)} "
                                         f"within {fmt_duration(span)} indicates password guessing.")]
            explanation = (
                f"Triggered because {who} generated {len(burst)} failed authentication attempts against {target_txt} "
                f"within {fmt_duration(span)} ({fmt_ts(burst[0].ts)} to {fmt_ts(burst[-1].ts)}). "
                f"The densest {fmt_duration(window)} window contained {peak} failures; the rule threshold is "
                f"{threshold} failures in {fmt_duration(window)}."
                + (" The source address is external to the organization's private ranges." if external else "")
            )
            fps, recs = _guidance("SX-001", source_ip=src, user=users[0] if users else None)
            out.append(Candidate(
                rule_key="SX-001", dedupe_key=f"SX-001:{key}:{burst[0].ts.isoformat()}", title=title,
                description="Many failed authentication attempts in a short window.", severity=sev, confidence=conf,
                ts=burst[0].ts, last_seen=burst[-1].ts, events=burst, explanation=explanation, mitre=mitre,
                false_positives=fps, recommendations=recs, stage="Credential Access",
                user=users[0] if len(users) == 1 else None, host=most_common(e.host for e in burst), source_ip=src,
                evidence_summary={"failed_attempts": len(burst), "peak_in_window": peak, "accounts": users[:50],
                                  "account_count": len(users), "duration_seconds": int(span.total_seconds()),
                                  "window_start": w_start.isoformat(), "window_end": w_end.isoformat()},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-002
def success_after_failures(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = int(p.get("failure_threshold", 5))
    lookback = timedelta(minutes=float(p.get("lookback_minutes", 30)))
    fails_by_user: dict[str, list[Ev]] = defaultdict(list)
    successes = []
    for e in events:
        if not _is_login(e) or not e.user:
            continue
        if e.status == "failure":
            fails_by_user[e.user].append(e)
        elif e.status == "success":
            successes.append(e)
    out, used = [], set()
    for s in successes:
        fails = fails_by_user.get(s.user)
        if not fails:
            continue
        times = [f.ts for f in fails]
        lo = bisect_left(times, s.ts - lookback)
        hi = bisect_left(times, s.ts + timedelta(microseconds=1))
        window_fails = fails[lo:hi]
        if len(window_fails) < threshold:
            continue
        key = f"SX-002:{s.user}:{window_fails[0].ts.isoformat()}"
        if key in used:
            continue
        used.add(key)
        fail_ips = distinct(f.src for f in window_fails)
        same_source = s.src in fail_ips if s.src else False
        external = is_external_ip(s.src)
        sev = "critical" if (external and len(window_fails) >= 20) else "high"
        conf = 0.9 if same_source else 0.75
        gap = s.ts - window_fails[-1].ts
        explanation = (
            f"Triggered because user {s.user} logged in successfully"
            + (f" from {s.src}" if s.src else "") + (f" on {s.host}" if s.host else "")
            + f" at {fmt_ts(s.ts)} after {len(window_fails)} failed attempts in the preceding "
            f"{fmt_duration(s.ts - window_fails[0].ts)} (from {join_limited(fail_ips) or 'unknown sources'}). "
            f"The last failure occurred {fmt_duration(gap)} before the success. "
            + ("The successful login came from the same source as the failures, which strongly suggests the "
               "guessing attempt succeeded. " if same_source else
               "The success came from a different source than the failures; this may be the legitimate user, "
               "so confirm with them. ")
            + f"Rule threshold: {threshold} failures within {fmt_duration(lookback)} before a success."
        )
        fps, recs = _guidance("SX-002", user=s.user, source_ip=s.src)
        out.append(Candidate(
            rule_key="SX-002", dedupe_key=key, title=f"Successful login after {len(window_fails)} failures: {s.user}",
            description="Successful authentication following repeated failures.", severity=sev, confidence=conf,
            ts=window_fails[0].ts, last_seen=s.ts, events=window_fails + [s], explanation=explanation,
            mitre=[_t("T1110", f"{len(window_fails)} failed attempts preceded the success, consistent with brute force."),
                   _t("T1078", f"The attacker appears to have obtained working credentials for {s.user} and used "
                               "them to authenticate (valid account use).", "medium" if not same_source else "high")],
            false_positives=fps, recommendations=recs, stage="Initial Access", user=s.user, host=s.host,
            source_ip=s.src, evidence_summary={"failures": len(window_fails), "failure_sources": fail_ips,
                                               "success_event": s.uid, "same_source": same_source},
        ))
    return out


# --------------------------------------------------------------------------------------------- SX-003
def suspicious_privileged_login(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    patterns = [x.lower() for x in p.get("privileged_name_patterns", [])]
    explicit = {x.lower() for x in p.get("privileged_accounts", [])}
    min_hist = int(p.get("min_history_logins", 3))

    def privileged(user: str) -> str | None:
        if user in explicit:
            return "listed as a privileged account in rule configuration"
        if user in ctx.privileged_logon_users:
            return "received special privileges at logon (Windows event 4672)"
        for pat in patterns:
            if pat in user:
                return f"account name matches privileged pattern '{pat}'"
        return None

    history: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    groups: dict[tuple, dict] = {}
    for e in events:
        if not (_is_login(e) and e.status == "success" and e.user):
            continue
        why_priv = privileged(e.user)
        prior = history[e.user]
        if why_priv:
            reasons = []
            if is_off_hours(e.ts, ctx.business_hours):
                reasons.append(f"outside business hours ({e.ts:%H:%M} UTC; business hours "
                               f"{ctx.business_hours[0]:02d}:00-{ctx.business_hours[1]:02d}:00 UTC)")
            if is_external_ip(e.src):
                reasons.append(f"from external address {e.src}")
            total_prior = sum(prior.values())
            if e.src and total_prior >= min_hist and e.src not in prior:
                reasons.append(f"from {e.src}, a source never seen for this account in {total_prior} prior logins "
                               f"(previous sources: {join_limited(list(prior), 3)})")
            if reasons:
                gkey = (e.user, e.src, e.ts.strftime("%Y%m%d%H"))
                g = groups.setdefault(gkey, {"events": [], "reasons": reasons, "why": why_priv})
                g["events"].append(e)
        if e.src:
            prior[e.src] += 1
    out = []
    for (user, src, bucket), g in groups.items():
        evs = g["events"]
        reasons = g["reasons"]
        sev = "high" if len(reasons) >= 2 else "medium"
        conf = round(min(0.9, 0.5 + 0.15 * len(reasons)), 2)
        first = evs[0]
        explanation = (
            f"Triggered because privileged account {user} ({g['why']}) logged in successfully"
            + (f" on {first.host}" if first.host else "") + f" at {fmt_ts(first.ts)} "
            + "; ".join(reasons) + "."
            + (f" {len(evs)} logins matched in this hour." if len(evs) > 1 else "")
        )
        fps, recs = _guidance("SX-003", user=user)
        out.append(Candidate(
            rule_key="SX-003", dedupe_key=f"SX-003:{user}:{src}:{bucket}",
            title=f"Suspicious privileged login: {user}" + (f" from {src}" if src else ""),
            description="Privileged account login under unusual conditions.", severity=sev, confidence=conf,
            ts=first.ts, last_seen=evs[-1].ts, events=evs, explanation=explanation,
            mitre=[_t("T1078", "A privileged valid account was used under unusual conditions ("
                               + "; ".join(r.split(" (")[0] for r in reasons) + ").", "medium")],
            false_positives=fps, recommendations=recs, stage="Initial Access", user=user, host=first.host,
            source_ip=src, evidence_summary={"reasons": reasons, "privilege_basis": g["why"], "logins": len(evs)},
        ))
    return out


# --------------------------------------------------------------------------------------------- SX-004
_ESCALATION_CMDS = [
    (re.compile(r"net1?(?:\.exe)?\s+(?:localgroup|group)\s+\"?([\w\s-]+?)\"?\s+(\S+)\s+/add", re.I), "T1098.007"),
    (re.compile(r"add-(?:ad|localgroup)?groupmember\s+.*?-(?:identity|group)\s+\"?([\w\s-]+?)\"?\s+-members?\s+\"?(\S+?)\"?(?:\s|$)", re.I), "T1098.007"),
    (re.compile(r"usermod\s+-a?G\s+(\w+)\s+(\S+)", re.I), "T1098.007"),
    (re.compile(r"\bsudo\s+(?:su\b|-i\b|-s\b|bash\b|sh\b|/bin/(?:ba)?sh)", re.I), "T1548.003"),
]
_GROUP_ADD_ACTIONS = ("group_add", "add_member", "member_added", "add_to_group", "role_assign", "role_assigned",
                      "grant", "add_role", "group_membership_add", "elevate", "privilege_grant")


def privilege_escalation(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    groups_cfg = [g.lower() for g in p.get("privileged_groups", [])]

    def priv_group(name: str | None) -> bool:
        n = (name or "").lower().strip()
        return bool(n) and any(n == g or n.endswith("\\" + g) or g in n for g in groups_cfg)

    hits = []
    for e in events:
        action = (e.action or "").lower()
        target_group = e.meta.get("group") or e.meta.get("group_name") or e.resource
        target_user = e.meta.get("target_user") or e.meta.get("member") or e.meta.get("target_account")
        if e.type == "privilege" and any(a in action for a in _GROUP_ADD_ACTIONS) and priv_group(target_group):
            hits.append((e, "T1098.007", target_group, target_user or e.user))
            continue
        if e.type == "privilege" and ("sudo" in action or (e.process or "").lower() == "sudo") and \
                re.search(r"\b(su|bash|sh|-i|-s)\b", e.command or ""):
            hits.append((e, "T1548.003", "root", e.user))
            continue
        text = e.command or ""
        if not text:
            continue
        for rx, tid in _ESCALATION_CMDS:
            m = rx.search(text)
            if not m:
                continue
            if tid == "T1548.003":
                hits.append((e, tid, "root", e.user))
            elif priv_group(m.group(1)):
                hits.append((e, tid, m.group(1).strip(), m.group(2).strip('"') if m.lastindex and m.lastindex >= 2 else e.user))
            break
    grouped: dict[tuple, list] = defaultdict(list)
    for e, tid, grp, tgt in hits:
        grouped[(e.user, (grp or "").lower(), (tgt or "").lower(), e.ts.strftime("%Y%m%d%H"))].append((e, tid, grp, tgt))
    out = []
    for (actor, grp_l, tgt_l, bucket), items in grouped.items():
        evs = [i[0] for i in items]
        e0, tid, grp, tgt = items[0]
        domain_level = any(x in grp_l for x in ("domain admins", "enterprise admins", "schema admins"))
        self_add = bool(actor) and tgt_l == (actor or "").lower()
        sev = "critical" if domain_level else "high"
        conf = 0.9 if (self_add or domain_level) else 0.8
        if tid == "T1548.003":
            title = f"Privilege escalation: {actor or 'unknown user'} obtained a root shell via sudo" + (f" on {e0.host}" if e0.host else "")
            how = f"used sudo to spawn a root shell (command: '{(e0.command or '')[:120]}')"
            mitre = [_t("T1548.003", "sudo was used to obtain an interactive root shell.")]
        else:
            title = f"Privilege escalation: {tgt or actor} added to {grp}" + (f" on {e0.host}" if e0.host else "")
            how = (f"added {'itself' if self_add else (tgt or 'an account')} to the privileged group '{grp}'"
                   + (f" (command: '{(e0.command or '')[:120]}')" if e0.command else f" (action: {e0.action})"))
            mitre = [_t("T1098.007", f"Membership of '{grp}' grants elevated privileges; adding "
                                     f"{'the actor itself' if self_add else tgt} is account manipulation for privilege escalation.")]
        explanation = (
            f"Triggered because {actor or 'an unidentified actor'} {how} at {fmt_ts(e0.ts)}"
            + (f" on {e0.host}" if e0.host else "") + ". "
            + ("Self-assignment of privileges is rarely legitimate. " if self_add else "")
            + ("The group is a domain-wide administrative group. " if domain_level else "")
        ).strip()
        fps, recs = _guidance("SX-004", user=actor, host=e0.host)
        out.append(Candidate(
            rule_key="SX-004", dedupe_key=f"SX-004:{actor}:{grp_l}:{tgt_l}:{bucket}", title=title,
            description="Account added to a privileged group or elevated to root.", severity=sev, confidence=conf,
            ts=e0.ts, last_seen=evs[-1].ts, events=evs, explanation=explanation, mitre=mitre,
            false_positives=fps, recommendations=recs, stage="Privilege Escalation", user=actor, host=e0.host,
            source_ip=e0.src, evidence_summary={"group": grp, "target_account": tgt, "self_assignment": self_add},
        ))
    return out


# --------------------------------------------------------------------------------------------- SX-005
_PS_INDICATORS = [
    ("encoded command", re.compile(r"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I), 2.0, "T1027.010"),
    ("FromBase64String decoding", re.compile(r"frombase64string", re.I), 2.0, "T1027.010"),
    ("download cradle", re.compile(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|"
                                   r"start-bitstransfer|invoke-restmethod|\birm\s+http", re.I), 2.0, "T1105"),
    ("Invoke-Expression", re.compile(r"\biex\b|invoke-expression", re.I), 1.0, "T1059.001"),
    ("hidden window", re.compile(r"\s-w(?:indowstyle)?\s+h(?:idden)?\b", re.I), 1.0, "T1564.003"),
    ("no profile", re.compile(r"\s-nop(?:rofile)?\b", re.I), 0.5, None),
    ("execution policy bypass", re.compile(r"-(?:ex|ep|executionpolicy)\s+bypass", re.I), 1.0, None),
    ("non-interactive", re.compile(r"\s-noni(?:nteractive)?\b", re.I), 0.5, None),
    ("credential theft module", re.compile(r"invoke-mimikatz|sekurlsa|kerberos::|lsadump::", re.I), 4.0, "T1003.001"),
    ("AMSI bypass", re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I), 3.0, "T1562.001"),
]
_OFFICE_PARENTS = ("winword", "excel", "powerpnt", "outlook", "msaccess", "onenote")
_TECH_REASONS = {
    "T1027.010": "The command line is Base64-encoded/obfuscated, hiding its intent from casual inspection.",
    "T1105": "The command downloads content from a remote location (ingress tool transfer).",
    "T1564.003": "PowerShell was launched with a hidden window to conceal execution from the user.",
    "T1003.001": "The command references credential-theft modules that read LSASS memory.",
    "T1562.001": "The command contains an AMSI bypass, disabling PowerShell's malware scanning.",
}


def _decode_ps(cmd: str) -> str | None:
    m = re.search(r"\s-(?:e|ec|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", cmd, re.I)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
        text = raw.decode("utf-16-le", errors="strict")
        return text[:500]
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def suspicious_powershell(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = float(p.get("score_threshold", 2.5))
    gap = timedelta(minutes=float(p.get("cluster_minutes", 15)))
    matched: list[tuple[Ev, float, list, str | None]] = []
    for e in events:
        text = f"{e.process or ''} {e.command or ''}"
        if "powershell" not in text.lower() and "pwsh" not in text.lower():
            continue
        cmd = e.command or ""
        decoded = _decode_ps(cmd)
        scan = cmd + (" " + decoded if decoded else "")
        score, found = 0.0, []
        for name, rx, weight, tid in _PS_INDICATORS:
            if rx.search(scan):
                score += weight
                found.append((name, tid))
        parent = str(e.meta.get("parent_process") or e.meta.get("ParentImage") or "").lower()
        if any(o in parent for o in _OFFICE_PARENTS):
            score += 1.5
            found.append((f"spawned by Office application ({parent.split(chr(92))[-1]})", None))
        if score >= threshold:
            matched.append((e, score, found, decoded))
    by_key: dict[tuple, list] = defaultdict(list)
    for item in matched:
        by_key[(item[0].host, item[0].user)].append(item)
    out = []
    for (host, user), items in by_key.items():
        items.sort(key=lambda i: i[0].ts)
        clusters: list[list] = []
        for it in items:
            if clusters and it[0].ts - clusters[-1][-1][0].ts <= gap:
                clusters[-1].append(it)
            else:
                clusters.append([it])
        for cl in clusters:
            evs = [i[0] for i in cl]
            top = max(cl, key=lambda i: i[1])
            names = distinct(n for i in cl for n, _ in i[2])
            techs = distinct(t for i in cl for _, t in i[2] if t)
            crit = any(t in ("T1003.001", "T1562.001") for t in techs)
            sev = "critical" if crit else "high"
            conf = round(min(0.97, 0.55 + 0.08 * top[1]), 2)
            mitre = [_t("T1059.001", f"PowerShell was used to execute commands with suspicious characteristics ({join_limited(names, 4)}).")]
            mitre += [_t(t, _TECH_REASONS[t]) for t in techs if t in _TECH_REASONS]
            decoded = next((i[3] for i in cl if i[3]), None)
            explanation = (
                f"Triggered because {len(evs)} PowerShell execution(s)" + (f" by {user}" if user else "")
                + (f" on {host}" if host else "") + f" between {fmt_ts(evs[0].ts)} and {fmt_ts(evs[-1].ts)} "
                f"matched suspicious indicators: {', '.join(names)}. Highest indicator score {top[1]:.1f} "
                f"(threshold {threshold}). Example command: '{(top[0].command or '')[:200]}'."
                + (f" Decoded payload: '{decoded[:200]}'." if decoded else "")
            )
            fps, recs = _guidance("SX-005", host=host, user=user)
            out.append(Candidate(
                rule_key="SX-005", dedupe_key=f"SX-005:{host}:{user}:{evs[0].ts.isoformat()}",
                title=f"Suspicious PowerShell on {host or 'unknown host'}" + (f" ({user})" if user else ""),
                description="PowerShell with obfuscation, download or evasion characteristics.", severity=sev,
                confidence=conf, ts=evs[0].ts, last_seen=evs[-1].ts, events=evs, explanation=explanation,
                mitre=mitre, false_positives=fps, recommendations=recs, stage="Execution", user=user, host=host,
                source_ip=evs[0].src, destination_ip=None,
                evidence_summary={"indicators": names, "max_score": top[1], "decoded_command": decoded},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-006
_DISCOVERY = [
    ("whoami", re.compile(r"\bwhoami\b", re.I), "T1033"),
    ("net user", re.compile(r"\bnet1?(?:\.exe)?\s+user\b(?!.*\s/add)", re.I), "T1087"),
    ("net group", re.compile(r"\bnet1?(?:\.exe)?\s+group\b(?!.*\s/add)", re.I), "T1069.002"),
    ("net localgroup", re.compile(r"\bnet1?(?:\.exe)?\s+localgroup\b(?!.*\s/add)", re.I), "T1069.001"),
    ("nltest", re.compile(r"\bnltest\b", re.I), "T1018"),
    ("net view", re.compile(r"\bnet1?(?:\.exe)?\s+view\b", re.I), "T1018"),
    ("network configuration", re.compile(r"\bipconfig\b|\broute\s+print\b|\barp\s+-a\b|get-netipconfiguration", re.I), "T1016"),
    ("netstat", re.compile(r"\bnetstat\b|get-nettcpconnection", re.I), "T1049"),
    ("systeminfo", re.compile(r"\bsysteminfo\b|get-computerinfo", re.I), "T1082"),
    ("process listing", re.compile(r"\btasklist\b|\bget-process\b", re.I), "T1057"),
    ("AD enumeration", re.compile(r"get-aduser|get-adgroupmember|get-adcomputer|\bdsquery\b|\badfind\b", re.I), "T1087.002"),
    ("port scanner", re.compile(r"\bnmap\b|\bmasscan\b|test-netconnection\s+.*-port", re.I), "T1046"),
]


def internal_discovery(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = int(p.get("distinct_command_threshold", 3))
    window = timedelta(minutes=float(p.get("window_minutes", 15)))
    scan_threshold = int(p.get("scan_host_threshold", 25))
    scan_window = timedelta(minutes=float(p.get("scan_window_minutes", 5)))
    per_session: dict[tuple, list] = defaultdict(list)
    conns: dict[str, list[Ev]] = defaultdict(list)
    for e in events:
        if e.command:
            for label, rx, tid in _DISCOVERY:
                if rx.search(e.command):
                    tid_eff = "T1087.002" if (tid == "T1087" and "/domain" in e.command.lower()) else tid
                    per_session[(e.user, e.host)].append((e, label, tid_eff))
                    break
        if e.type == "network" and e.src and e.dst and is_internal_ip(e.dst):
            conns[e.src].append(e)
    out = []
    for (user, host), items in per_session.items():
        items.sort(key=lambda i: i[0].ts)
        clusters: list[list] = []
        for it in items:
            if clusters and it[0].ts - clusters[-1][-1][0].ts <= window:
                clusters[-1].append(it)
            else:
                clusters.append([it])
        for cl in clusters:
            labels = distinct(i[1] for i in cl)
            if len(labels) < threshold:
                continue
            evs = [i[0] for i in cl]
            techs = distinct(i[2] for i in cl)
            sev = "high" if len(labels) >= 6 or ("net group" in labels and "nltest" in labels) else "medium"
            conf = round(min(0.9, 0.5 + 0.07 * len(labels)), 2)
            mitre = []
            for t in techs:
                cmds = distinct(i[1] for i in cl if i[2] == t)
                mitre.append(_t(t, f"Observed discovery command(s): {', '.join(cmds)}."))
            explanation = (
                f"Triggered because {user or 'an unidentified user'}" + (f" on {host}" if host else "")
                + f" ran {len(labels)} distinct discovery commands ({', '.join(labels)}) within "
                f"{fmt_duration(evs[-1].ts - evs[0].ts)} ({fmt_ts(evs[0].ts)} to {fmt_ts(evs[-1].ts)}). "
                f"Individually these commands are common; the rule fires when at least {threshold} distinct "
                f"discovery commands occur within {fmt_duration(window)}."
            )
            fps, recs = _guidance("SX-006", user=user, host=host)
            out.append(Candidate(
                rule_key="SX-006", dedupe_key=f"SX-006:cmd:{user}:{host}:{evs[0].ts.isoformat()}",
                title=f"Internal discovery: {len(labels)} reconnaissance commands on {host or 'unknown host'}",
                description="Burst of reconnaissance commands.", severity=sev, confidence=conf, ts=evs[0].ts,
                last_seen=evs[-1].ts, events=evs, explanation=explanation, mitre=mitre, false_positives=fps,
                recommendations=recs, stage="Discovery", user=user, host=host, source_ip=evs[0].src,
                evidence_summary={"commands": labels, "command_count": len(evs)},
            ))
    for src, evs_all in conns.items():
        for cl in cluster_by_gap(evs_all, scan_window):
            dsts = distinct(e.dst for e in cl)
            if len(dsts) < scan_threshold:
                continue
            ports = distinct(str(e.meta.get("dest_port") or e.meta.get("destination_port") or "") for e in cl)
            host = most_common(e.host for e in cl)
            user = most_common(e.user for e in cl)
            explanation = (
                f"Triggered because {src}" + (f" ({host})" if host else "") + f" connected to {len(dsts)} distinct "
                f"internal hosts within {fmt_duration(cl[-1].ts - cl[0].ts)} ({fmt_ts(cl[0].ts)} to {fmt_ts(cl[-1].ts)})"
                + (f" on port(s) {join_limited([x for x in ports if x], 5)}" if any(ports) else "")
                + f". The scanning threshold is {scan_threshold} hosts within {fmt_duration(scan_window)}."
            )
            fps, recs = _guidance("SX-006", user=user, host=host)
            out.append(Candidate(
                rule_key="SX-006", dedupe_key=f"SX-006:scan:{src}:{cl[0].ts.isoformat()}",
                title=f"Internal network scan from {host or src}: {len(dsts)} hosts contacted",
                description="One host connecting to many internal systems.", severity="high", confidence=0.8,
                ts=cl[0].ts, last_seen=cl[-1].ts, events=cl, explanation=explanation,
                mitre=[_t("T1046", f"{len(dsts)} internal hosts were contacted in a short window, consistent with "
                                   "network service scanning.")],
                false_positives=fps, recommendations=recs, stage="Discovery", user=user, host=host, source_ip=src,
                evidence_summary={"distinct_destinations": len(dsts), "sample_destinations": dsts[:20],
                                  "ports": [x for x in ports if x][:10]},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-007
_PROC_PATTERNS = [
    ("Mimikatz credential dumping", re.compile(r"mimikatz|sekurlsa::|lsadump::|privilege::debug", re.I), "T1003.001", "critical"),
    ("LSASS memory dump", re.compile(r"procdump(?:64)?(?:\.exe)?\s+.*lsass|comsvcs(?:\.dll)?[, ]+#?\s*(?:24|minidump)|"
                                     r"rundll32.*comsvcs.*minidump", re.I), "T1003.001", "critical"),
    ("NTDS.dit extraction", re.compile(r"ntdsutil.*\bifm\b|ntdsutil.*create\s+full|copy\s+.*ntds\.dit|"
                                       r"vssadmin\s+create\s+shadow", re.I), "T1003.003", "critical"),
    ("Shadow copy / backup deletion", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+catalog|"
                                                 r"bcdedit.*recoveryenabled\s+no|wmic\s+shadowcopy\s+delete", re.I), "T1490", "critical"),
    ("PsExec remote execution", re.compile(r"\bpsexec(?:64)?(?:\.exe)?\b|psexesvc", re.I), "T1569.002", "high"),
    ("Certutil download", re.compile(r"certutil(?:\.exe)?\s+.*-urlcache", re.I), "T1105", "high"),
    ("Certutil decode", re.compile(r"certutil(?:\.exe)?\s+.*-decode", re.I), "T1140", "high"),
    ("Mshta script execution", re.compile(r"mshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)", re.I), "T1218.005", "high"),
    ("Regsvr32 scriptlet execution", re.compile(r"regsvr32(?:\.exe)?\s+.*/i:\s*https?:", re.I), "T1218.010", "high"),
    ("Rundll32 script execution", re.compile(r"rundll32(?:\.exe)?\s+.*javascript:", re.I), "T1218.011", "high"),
    ("WMI remote process creation", re.compile(r"wmic(?:\.exe)?\s+.*process\s+call\s+create", re.I), "T1047", "high"),
    ("Password-protected archive", re.compile(r"\b7z(?:a|\.exe)?\s+a\s+.*-p\S*|\brar(?:\.exe)?\s+a\s+.*-hp", re.I), "T1560.001", "medium"),
    ("Scheduled task creation", re.compile(r"schtasks(?:\.exe)?\s+/create\s+.*(?:powershell|cmd|\\appdata\\|\\temp\\|http)", re.I), "T1053.005", "medium"),
    ("Registry Run key persistence", re.compile(r"reg(?:\.exe)?\s+add\s+.*\\currentversion\\run", re.I), "T1547.001", "medium"),
    ("Local account creation", re.compile(r"\bnet1?(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add", re.I), "T1136.001", "high"),
]


def suspicious_process(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    gap = timedelta(minutes=float(p.get("cluster_minutes", 30)))
    hits: dict[str, list] = defaultdict(list)
    for e in events:
        text = f"{e.process or ''} {e.command or ''}"
        if not text.strip():
            continue
        for label, rx, tid, sev in _PROC_PATTERNS:
            if rx.search(text):
                hits[e.host or f"user:{e.user}"].append((e, label, tid, sev))
                break
    out = []
    for key, items in hits.items():
        items.sort(key=lambda i: i[0].ts)
        clusters: list[list] = []
        for it in items:
            if clusters and it[0].ts - clusters[-1][-1][0].ts <= gap:
                clusters[-1].append(it)
            else:
                clusters.append([it])
        for cl in clusters:
            evs = [i[0] for i in cl]
            labels = distinct(i[1] for i in cl)
            sev = max_severity(*(i[3] for i in cl))
            host = evs[0].host
            user = most_common(e.user for e in evs)
            mitre, seen = [], set()
            for e, label, tid, _ in cl:
                if tid not in seen:
                    seen.add(tid)
                    mitre.append(_t(tid, f"{label}: '{(e.command or e.process or '')[:120]}'."))
            stage = "Credential Access" if any(t.startswith("T1003") for t in seen) else "Execution"
            explanation = (
                f"Triggered because {len(evs)} process execution(s)" + (f" on {host}" if host else "")
                + (f" by {user}" if user else "") + f" between {fmt_ts(evs[0].ts)} and {fmt_ts(evs[-1].ts)} matched "
                f"known offensive tooling / abused-binary patterns: {', '.join(labels)}. "
                f"First command: '{(evs[0].command or evs[0].process or '')[:200]}'."
            )
            fps, recs = _guidance("SX-007", host=host, user=user)
            out.append(Candidate(
                rule_key="SX-007", dedupe_key=f"SX-007:{key}:{evs[0].ts.isoformat()}",
                title=f"Suspicious process execution on {host or 'unknown host'}: {join_limited(labels, 2)}",
                description="Known offensive tool or abused system binary executed.", severity=sev,
                confidence=0.9 if sev == "critical" else 0.8, ts=evs[0].ts, last_seen=evs[-1].ts, events=evs,
                explanation=explanation, mitre=mitre, false_positives=fps, recommendations=recs, stage=stage,
                user=user, host=host, source_ip=evs[0].src, evidence_summary={"patterns": labels},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-008
def sensitive_file_access(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = int(p.get("distinct_file_threshold", 5))
    window = timedelta(minutes=float(p.get("window_minutes", 30)))
    sens = [s.lower() for s in p.get("sensitive_patterns", [])]
    creds = [s.lower() for s in p.get("credential_patterns", [])]
    per_user: dict[str, list] = defaultdict(list)
    for e in events:
        if not e.resource:
            continue
        is_file = e.type == "file" or (e.action or "").startswith(("file", "read", "open", "copy", "share"))
        if not is_file:
            continue
        r = e.resource.lower()
        cred_hit = next((c for c in creds if c in r), None)
        sens_hit = next((s for s in sens if s in r), None)
        if cred_hit or sens_hit:
            per_user[e.user or f"host:{e.host}"].append((e, cred_hit, sens_hit))
    out = []
    for ukey, items in per_user.items():
        items.sort(key=lambda i: i[0].ts)
        clusters: list[list] = []
        for it in items:
            if clusters and it[0].ts - clusters[-1][-1][0].ts <= window:
                clusters[-1].append(it)
            else:
                clusters.append([it])
        for cl in clusters:
            evs = [i[0] for i in cl]
            files = distinct(e.resource for e in evs)
            cred_files = distinct(i[0].resource for i in cl if i[1])
            if len(files) < threshold and not cred_files:
                continue
            user = evs[0].user
            host = most_common(e.host for e in evs)
            off = [e for e in evs if is_off_hours(e.ts, ctx.business_hours)]
            share = any(f.startswith("\\\\") for f in files)
            sev = "high" if (cred_files or len(files) >= 3 * threshold or len(off) > len(evs) / 2) else "medium"
            conf = round(min(0.9, 0.55 + 0.03 * len(files) + (0.2 if cred_files else 0)), 2)
            mitre = []
            if len(files) - len(cred_files) >= 1:
                tid = "T1039" if share else "T1005"
                mitre.append(_t(tid, f"{len(files)} sensitive files were read from "
                                     f"{'network shares' if share else 'the local system'} in a short window, "
                                     "consistent with data collection.", "medium"))
            if any("ntds.dit" in f.lower() for f in cred_files):
                mitre.append(_t("T1003.003", "The Active Directory database (NTDS.dit) was accessed."))
            if any("ntds.dit" not in f.lower() for f in cred_files):
                mitre.append(_t("T1552.001", "Files that commonly store credentials were accessed: "
                                             + join_limited([f for f in cred_files if 'ntds.dit' not in f.lower()], 3) + "."))
            explanation = (
                f"Triggered because {user or 'an unidentified account'}" + (f" on {host}" if host else "")
                + f" accessed {len(files)} distinct sensitive file(s) within {fmt_duration(evs[-1].ts - evs[0].ts)} "
                f"({fmt_ts(evs[0].ts)} to {fmt_ts(evs[-1].ts)}), e.g. {join_limited(files, 3)}. "
                + (f"Credential stores were touched: {join_limited(cred_files, 3)}. " if cred_files else "")
                + (f"{len(off)} of the accesses happened outside business hours. " if off else "")
                + f"Threshold: {threshold} distinct sensitive files within {fmt_duration(window)}, or any credential store."
            )
            fps, recs = _guidance("SX-008", user=user)
            out.append(Candidate(
                rule_key="SX-008", dedupe_key=f"SX-008:{ukey}:{evs[0].ts.isoformat()}",
                title=f"Sensitive file access: {len(files)} files by {user or host or 'unknown'}",
                description="Unusual volume of sensitive file access.", severity=sev, confidence=conf,
                ts=evs[0].ts, last_seen=evs[-1].ts, events=evs, explanation=explanation, mitre=mitre,
                false_positives=fps, recommendations=recs, stage="Collection", user=user, host=host,
                source_ip=evs[0].src, evidence_summary={"files": files[:50], "file_count": len(files),
                                                        "credential_files": cred_files, "off_hours_accesses": len(off)},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-009
def data_exfiltration(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    threshold = int(p.get("bytes_threshold", 100_000_000))
    window = timedelta(minutes=float(p.get("window_minutes", 60)))
    clouds = [c.lower() for c in p.get("cloud_storage_domains", [])]
    sanctioned = {s.lower() for s in p.get("sanctioned_destinations", [])}
    groups: dict[tuple, list[Ev]] = defaultdict(list)
    for e in events:
        if not e.bytes or e.bytes <= 0:
            continue
        direction = str(e.meta.get("direction") or "").lower()
        if direction in ("inbound", "in", "download") or (e.action or "").lower() in ("download", "inbound"):
            continue
        domain = (e.resource or "").lower() if e.resource and not e.resource.startswith("\\") else ""
        dest = e.dst if e.dst else None
        external = is_external_ip(dest) or (not dest and bool(domain) and "." in domain and " " not in domain)
        if dest and is_internal_ip(dest):
            external = False
        if not external:
            continue
        dest_label = domain.split("/")[2] if domain.startswith("http") and domain.count("/") >= 2 else (domain or dest)
        if (dest_label or "").lower() in sanctioned or (dest or "") in sanctioned:
            continue
        groups[(e.user or f"host:{e.host}", dest_label or dest)].append(e)
    out = []
    for (actor, dest_label), evs_all in groups.items():
        for cl in cluster_by_gap(evs_all, window):
            total = sum(e.bytes or 0 for e in cl)
            if total < threshold:
                continue
            e0 = cl[0]
            dest_ip = most_common(e.dst for e in cl)
            proto = str(e0.meta.get("protocol") or e0.meta.get("app_protocol") or "").lower()
            port = str(e0.meta.get("dest_port") or e0.meta.get("destination_port") or "")
            label = (dest_label or "").lower()
            if any(c in label for c in clouds):
                mitre = [_t("T1567.002", f"Data was uploaded to the cloud storage service {dest_label}.")]
            elif proto in ("ftp", "http", "tftp") or port in ("21", "80", "69"):
                mitre = [_t("T1048.003", f"Large transfer over an unencrypted protocol ({proto or 'port ' + port}) "
                                         "to an external destination.", "medium")]
            elif proto in ("https", "tls", "sftp", "scp", "ssh") or port in ("443", "22", "8443"):
                mitre = [_t("T1048.002", f"Large transfer over an encrypted protocol ({proto or 'port ' + port}) to "
                                         "an external destination not identified as a C2 channel.", "medium")]
            else:
                mitre = [_t("T1048", "Large outbound transfer to an external destination; protocol unknown.", "low")]
            sev = "critical" if total >= 1_000_000_000 else "high"
            conf = round(min(0.9, 0.6 + 0.1 * (total / threshold) ** 0.5), 2)
            user = e0.user
            host = most_common(e.host for e in cl)
            explanation = (
                f"Triggered because {user or host or 'an unidentified source'} transferred {fmt_bytes(total)} "
                f"to external destination {dest_label}" + (f" ({dest_ip})" if dest_ip and dest_ip != dest_label else "")
                + f" in {len(cl)} transfer(s) between {fmt_ts(cl[0].ts)} and {fmt_ts(cl[-1].ts)}"
                + (f" over {proto or 'port ' + port}" if proto or port else "")
                + f". The rule threshold is {fmt_bytes(threshold)} to one external destination within {fmt_duration(window)}."
                + (" The transfer occurred outside business hours." if is_off_hours(e0.ts, ctx.business_hours) else "")
            )
            fps, recs = _guidance("SX-009", user=user, destination=dest_label)
            out.append(Candidate(
                rule_key="SX-009", dedupe_key=f"SX-009:{actor}:{dest_label}:{cl[0].ts.isoformat()}",
                title=f"Potential data exfiltration: {fmt_bytes(total)} to {dest_label}",
                description="Large outbound transfer to an external destination.", severity=sev, confidence=conf,
                ts=cl[0].ts, last_seen=cl[-1].ts, events=cl, explanation=explanation, mitre=mitre,
                false_positives=fps, recommendations=recs, stage="Exfiltration", user=user, host=host,
                source_ip=e0.src, destination_ip=dest_ip,
                evidence_summary={"total_bytes": total, "transfers": len(cl), "destination": dest_label,
                                  "protocol": proto, "port": port},
            ))
    return out


# --------------------------------------------------------------------------------------------- SX-010
def threat_intel_match(events: list[Ev], p: dict, ctx: RuleContext) -> list[Candidate]:
    min_conf = float(p.get("min_confidence", 0.5))
    by_type: dict[str, dict[str, dict]] = defaultdict(dict)
    for ind in ctx.indicators:
        if ind["confidence"] >= min_conf:
            by_type[ind["type"]][ind["value"].lower()] = ind
    if not by_type:
        return []
    hits: dict[tuple, list] = defaultdict(list)
    for e in events:
        candidates = []
        if e.src:
            candidates.append(("ip", e.src, "source IP"))
        if e.dst:
            candidates.append(("ip", e.dst, "destination IP"))
        if e.host:
            candidates.append(("hostname", e.host, "host"))
        if e.user:
            candidates.append(("username", e.user, "user"))
        if e.resource:
            res = e.resource.lower()
            dom = res.split("/")[2] if res.startswith("http") and res.count("/") >= 2 else res
            candidates.append(("domain", dom, "domain"))
        for hk in ("sha256", "hash", "md5", "sha1", "file_hash"):
            if e.meta.get(hk):
                candidates.append(("hash", str(e.meta[hk]), "file hash"))
        for itype, value, field_name in candidates:
            ind = by_type.get(itype, {}).get(str(value).lower())
            if ind:
                hits[(ind["value"], ind["type"], e.ts.strftime("%Y%m%d"))].append((e, ind, field_name))
    out = []
    for (value, itype, day), items in hits.items():
        evs = list({i[0].id: i[0] for i in items}.values())
        ind = items[0][1]
        fields = distinct(i[2] for i in items)
        e0 = evs[0]
        explanation = (
            f"Triggered because {len(evs)} event(s) on {e0.ts:%Y-%m-%d} referenced the {itype} indicator "
            f"'{value}' (matched in field(s): {', '.join(fields)}). Indicator source: {ind['source']}"
            + (" [SYNTHETIC DEMO INTELLIGENCE]" if ind.get("is_synthetic") else "")
            + f"; confidence {ind['confidence']:.2f}; severity {ind['severity']}. {ind.get('description') or ''}".rstrip()
        )
        fps, recs = _guidance("SX-010")
        out.append(Candidate(
            rule_key="SX-010", dedupe_key=f"SX-010:{itype}:{value}:{day}",
            title=f"Threat intelligence match: {itype} {value}", description="Known indicator observed in telemetry.",
            severity=ind["severity"] if ind["severity"] in ("low", "medium", "high", "critical") else "medium",
            confidence=round(float(ind["confidence"]), 2), ts=e0.ts, last_seen=evs[-1].ts, events=evs,
            explanation=explanation, mitre=[], false_positives=fps, recommendations=recs,
            stage="Threat Intelligence",
            user=e0.user if len({e.user for e in evs}) == 1 else None,
            host=e0.host if len({e.host for e in evs}) == 1 else None,
            source_ip=e0.src, destination_ip=e0.dst,
            evidence_summary={"indicator": value, "indicator_type": itype, "indicator_source": ind["source"],
                              "synthetic": bool(ind.get("is_synthetic")), "matched_fields": fields,
                              "mitre_note": "No ATT&CK technique is mapped: an indicator match alone does not "
                                            "establish which technique was used."},
        ))
    return out


RULE_IMPLEMENTATIONS = {
    "SX-001": brute_force,
    "SX-002": success_after_failures,
    "SX-003": suspicious_privileged_login,
    "SX-004": privilege_escalation,
    "SX-005": suspicious_powershell,
    "SX-006": internal_discovery,
    "SX-007": suspicious_process,
    "SX-008": sensitive_file_access,
    "SX-009": data_exfiltration,
    "SX-010": threat_intel_match,
}
