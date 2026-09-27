"""Deterministic LOCAL analysis used when no LLM is configured (or the live model is unavailable).

It never generates free-form language-model text. It classifies the question with keyword rules,
calls the same read-only tools the live model uses, and composes an answer strictly from their output.
"""

import re

from app.ai.toolbox import Toolbox
from app.detection.base import fmt_bytes

STAGE_PLAIN = {
    "Credential Access": "trying to obtain or guess passwords",
    "Initial Access": "getting into the environment with a working account",
    "Execution": "running commands or scripts on a machine",
    "Privilege Escalation": "gaining administrator-level rights",
    "Discovery": "looking around to learn about the network, users and groups",
    "Collection": "gathering files or data of interest",
    "Exfiltration": "sending data out of the organization",
    "Persistence": "making sure access survives reboots or password changes",
    "Threat Intelligence": "contact with an address or file already known to be malicious",
}
INTENTS = [
    ("ciso", r"\bciso\b|executive|board|management summary|non-technical|business impact"),
    ("technical_report", r"technical (incident )?report|incident report|full report|detailed report"),
    ("junior", r"junior|beginner|explain (it |this )?(simply|like)|new analyst|plain (english|language)"),
    ("compare", r"\bcompare\b|difference between|similar incidents"),
    ("explain_technique", r"\bT\d{4}(?:\.\d{3})?\b|what (does|is) (the )?(mitre )?technique"),
    ("explain_event", r"explain (this |the )?event|\bevent\b.*\b(?:[A-Z]{2,}[A-Z0-9]*-\d{4,}|EVT-[0-9A-F]{12})\b"),
    ("before", r"\bbefore\b|preceded|leading up to|prior to"),
    ("why_trigger", r"why did (this|the|it)?.*(trigger|fire|alert)|why.*(detection|rule|alert).*(trigger|fire)|trigger"),
    ("why_suspicious", r"why.*(suspicious|malicious|important|high risk|risk score|matter)|risk score"),
    ("false_positives", r"false positive|benign|legitimate explanation|could this be normal"),
    ("next_steps", r"next|what should i|recommend|investigate|contain|respond|remediat"),
    ("evidence", r"evidence|prove|support|show me the (logs|events)"),
    ("users", r"\busers?\b|accounts?\b.*(affected|involved)|who "),
    ("hosts", r"\bhosts?\b|machines?|endpoints?|servers?|devices?"),
    ("ips", r"\bips?\b|ip address|source address|addresses"),
    ("mitre", r"mitre|att&ck|attack technique|techniques|tactics"),
    ("related", r"related events|find related|other events|similar events|correlated events"),
    ("summary", r"what happened|summar|overview|explain (this|the) incident|tell me about|status"),
]
EVENT_REF = re.compile(r"\b(?:[A-Z]{2,}[A-Z0-9]*-(?:[A-Z0-9]+-)*\d{4,}|EVT-[0-9A-F]{12})\b")
INC_REF = re.compile(r"\bINC-\d{4,}\b", re.I)
TECH_REF = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def classify(question: str) -> str:
    q = question.lower()
    for name, rx in INTENTS:
        if re.search(rx, q if name not in ("explain_technique", "explain_event") else question, re.I):
            return name
    return "summary"


def _ans(summary="", evidence=None, inference=None, uncertainty=None, next_steps=None, techniques=None) -> dict:
    return {"summary": summary, "evidence": evidence or [], "inference": inference or [],
            "uncertainty": uncertainty or [], "next_steps": next_steps or [], "techniques": techniques or []}


def _det_evidence(dets: list[dict], limit_ids: int = 3) -> list[dict]:
    return [{"statement": f"[{d['rule_key']} · {d['severity'].upper()}] {d['title']}: {d['explanation']}",
             "event_ids": d["evidence_event_uids"][:limit_ids], "detection_ids": [d["id"]]} for d in dets]


def _techniques(ctx: dict) -> list[dict]:
    return [{"id": t["id"], "reason": f"{t['name']} ({t['tactic']}): {t['reason']}"} for t in ctx["techniques"]]


def _uncertainty(ctx: dict) -> list[str]:
    out = []
    low = [t for t in ctx["techniques"] if t.get("mapping_confidence") in ("low", "medium")]
    if low:
        out.append("Some technique mappings are only medium/low confidence: " +
                   ", ".join(f"{t['id']} ({t['mapping_confidence']})" for t in low) + ".")
    for d in ctx["detections"][:3]:
        if d["false_positives"]:
            out.append(f"{d['rule_key']} can be benign: {d['false_positives'][0]}")
    out.append("Analysis is limited to telemetry ingested into this workspace; activity in systems that do not send "
               "logs to SentinelX is not visible.")
    return out


def _next_steps(ctx: dict, n: int = 6) -> list[str]:
    steps = [c["item"] for c in ctx.get("checklist", []) if not c.get("done")]
    for d in ctx["detections"]:
        for r in d["recommendations"]:
            if r not in steps:
                steps.append(r)
    return steps[:n]


class LocalAnalyst:
    def __init__(self, toolbox: Toolbox):
        self.tb = toolbox

    def answer(self, question: str, incident_ref: str | None) -> tuple[dict, str]:
        intent = classify(question)
        incs = INC_REF.findall(question)
        if intent == "compare":
            return self.compare(incs, incident_ref), intent
        if intent == "explain_technique" and TECH_REF.search(question):
            return self.explain_technique(TECH_REF.search(question).group(0).upper(), incident_ref), intent
        ev = EVENT_REF.search(question)
        if ev and not INC_REF.fullmatch(ev.group(0)) and intent in ("explain_event", "evidence", "summary", "why_trigger"):
            return self.explain_event(ev.group(0)), "explain_event"
        ref = incs[0] if incs else incident_ref
        if ref is None:
            return self.general(question, intent), f"general:{intent}"
        ctx = self.tb.get_incident(ref)
        if "error" in ctx:
            return _ans(summary=ctx["error"]), intent
        fallback = {"explain_technique": self.mitre, "explain_event": self.evidence}
        handler = fallback.get(intent) or getattr(self, intent, self.summary)
        return handler(ctx, question), intent

    # ------------------------------------------------------------------ incident intents
    def summary(self, ctx: dict, question: str = "") -> dict:
        i = ctx["incident"]
        seq = " → ".join(i["stages"])
        return _ans(
            summary=f"{i['number']} — {i['title']}. {i['summary']} Status: {i['status']}; severity {i['severity'].upper()}; "
                    f"confidence {i['confidence']:.2f}.",
            evidence=_det_evidence(ctx["detections"]),
            inference=[f"The detections form the sequence {seq}, which is consistent with a single actor progressing "
                       f"through an attack rather than unrelated noise." if len(i["stages"]) > 1 else
                       "This incident consists of a single stage; it may be an isolated event or an early indicator.",
                       f"Correlation basis: {i['correlation_reason']}"],
            uncertainty=_uncertainty(ctx), next_steps=_next_steps(ctx), techniques=_techniques(ctx))

    def why_suspicious(self, ctx: dict, question: str = "") -> dict:
        i = ctx["incident"]
        contributing = [f for f in ctx["risk_factors"] if f["points"] > 0]
        return _ans(
            summary=f"{i['number']} has a SentinelX Risk Score of {i['risk_score']}/100 ({i['risk_band']}). The score is a "
                    "transparent additive heuristic, not a probability; the contributing factors are listed below.",
            evidence=[{"statement": f"{f['factor']}: +{f['points']} of {f['max']} — {f['detail']}", "event_ids": [],
                       "detection_ids": []} for f in contributing] + _det_evidence(ctx["detections"], 2),
            inference=["The activity is suspicious mainly because of: " + ", ".join(f["factor"].lower() for f in
                                                                                       sorted(contributing, key=lambda f: -f["points"])[:3]) + "."],
            uncertainty=_uncertainty(ctx), next_steps=_next_steps(ctx, 4), techniques=_techniques(ctx))

    def why_trigger(self, ctx: dict, question: str = "") -> dict:
        dets = ctx["detections"]
        m = re.search(r"SX-\d{3}", question, re.I)
        num = re.search(r"#(\d+)|detection (\d+)", question, re.I)
        if m:
            dets = [d for d in dets if d["rule_key"] == m.group(0).upper()] or dets
        elif num:
            did = int(num.group(1) or num.group(2))
            dets = [d for d in dets if d["id"] == did] or dets
        return _ans(
            summary=f"{len(dets)} detection rule(s) triggered. Each explanation below is generated from the matching events.",
            evidence=_det_evidence(dets, 5),
            inference=[f"{d['rule_key']} ({d['title']}) — confidence {d['confidence']:.2f}." for d in dets],
            uncertainty=[f"{d['rule_key']} possible benign causes: " + "; ".join(d["false_positives"][:2]) for d in dets[:4]],
            next_steps=_next_steps(ctx, 4),
            techniques=[{"id": m2["id"], "reason": m2["reason"]} for d in dets for m2 in d["mitre"]])

    def evidence(self, ctx: dict, question: str = "") -> dict:
        tl = self.tb.get_timeline(ctx["incident"]["number"], 40)
        ev = [{"statement": f"{e['timestamp']} {e['type']} {e.get('action') or ''} by {e.get('user') or '?'} on "
                            f"{e.get('host') or '?'}" + (f" from {e['source_ip']}" if e.get("source_ip") else "")
                            + (f": {e['command']}" if e.get("command") else f" → {e['resource']}" if e.get("resource") else "")
                            + (f" [{', '.join(e['detections'])}]" if e.get("detections") else ""),
               "event_ids": [e["event_uid"]], "detection_ids": []} for e in tl["events"]]
        return _ans(summary=f"{tl['total_evidence_events']} evidence events support {ctx['incident']['number']}; "
                            f"{tl['returned']} are listed chronologically below.",
                    evidence=ev, inference=["Each detection's evidence events are the exact rows that satisfied its rule."],
                    uncertainty=_uncertainty(ctx)[-1:], techniques=_techniques(ctx))

    def before(self, ctx: dict, question: str = "") -> dict:
        q = question.lower()
        stage_words = {"privilege": "Privilege Escalation", "exfil": "Exfiltration", "powershell": "Execution",
                       "discovery": "Discovery", "file": "Collection", "login": "Initial Access"}
        target_stage = next((v for k, v in stage_words.items() if k in q), "Privilege Escalation")
        target = next((d for d in ctx["detections"] if d["stage"] == target_stage), None)
        if target is None:
            return _ans(summary=f"No {target_stage} detection exists in {ctx['incident']['number']}, so there is no such "
                                "point in the timeline to look before.", uncertainty=_uncertainty(ctx))
        tl = self.tb.get_timeline(ctx["incident"]["number"])
        prior = [e for e in tl["events"] if e["timestamp"] < target["timestamp"]]
        prior_dets = [d for d in ctx["detections"] if d["timestamp"] < target["timestamp"]]
        ev = [{"statement": f"{e['timestamp']} {e['type']} {e.get('action') or ''}"
                            + (f": {e['command']}" if e.get("command") else "")
                            + (f" (from {e['source_ip']})" if e.get("source_ip") else ""),
               "event_ids": [e["event_uid"]], "detection_ids": []} for e in prior[-12:]]
        return _ans(
            summary=f"Before the {target_stage.lower()} at {target['timestamp']} ({target['title']}), SentinelX observed "
                    f"{len(prior_dets)} earlier detection(s): " + ("; ".join(f"{d['title']} at {d['timestamp']}" for d in prior_dets)
                                                                    or "none") + ".",
            evidence=_det_evidence(prior_dets, 2) + ev,
            inference=["The earlier stages show how the actor reached the point of " + STAGE_PLAIN.get(target_stage, target_stage) + "."],
            uncertainty=_uncertainty(ctx)[-1:], techniques=_techniques(ctx))

    def _entities(self, ctx: dict, key: str, label: str) -> dict:
        i = ctx["incident"]
        vals = i[key]
        ev = []
        for v in vals[:15]:
            dets = [d for d in ctx["detections"] if v in (d.get("user"), d.get("host"), d.get("source_ip"), d.get("destination_ip"))]
            ev.append({"statement": f"{v}: involved in {len(dets)} detection(s)" +
                                    (f" — {', '.join(d['rule_key'] for d in dets)}" if dets else " (seen in evidence events)"),
                       "event_ids": dets[0]["evidence_event_uids"][:2] if dets else [], "detection_ids": [d["id"] for d in dets]})
        return _ans(summary=f"{len(vals)} {label} involved in {i['number']}: {', '.join(vals[:15]) or 'none recorded'}.",
                    evidence=ev, uncertainty=_uncertainty(ctx)[-1:])

    def users(self, ctx, question=""):
        return self._entities(ctx, "users", "user account(s) are")

    def hosts(self, ctx, question=""):
        return self._entities(ctx, "hosts", "host(s) are")

    def ips(self, ctx, question=""):
        a = self._entities(ctx, "source_ips", "source IP(s) are")
        dst = ctx["incident"]["destination_ips"]
        if dst:
            a["summary"] += f" External destination IP(s): {', '.join(dst)}."
        return a

    def mitre(self, ctx, question=""):
        techs = ctx["techniques"]
        return _ans(summary=f"{len(techs)} MITRE ATT&CK technique(s) are mapped to {ctx['incident']['number']} from its "
                            "detections. Each mapping is justified by specific evidence:",
                    evidence=[{"statement": f"{t['id']} {t['name']} ({t['tactic']}, mapping confidence "
                                            f"{t['mapping_confidence']}): {t['reason']}", "event_ids": t["event_uids"][:3],
                               "detection_ids": []} for t in techs],
                    techniques=_techniques(ctx), uncertainty=_uncertainty(ctx)[:1])

    def next_steps(self, ctx, question=""):
        i = ctx["incident"]
        first = []
        if "Exfiltration" in i["stages"]:
            first.append(f"Block the exfiltration destination(s) {', '.join(i['destination_ips'][:3]) or ''} and preserve proxy/firewall logs.")
        if any(s in i["stages"] for s in ("Initial Access", "Credential Access")) and i["users"]:
            first.append(f"Disable or reset credentials for {', '.join(i['users'][:3])} and revoke active sessions.")
        if any(s in i["stages"] for s in ("Execution", "Privilege Escalation")) and i["hosts"]:
            first.append(f"Isolate {', '.join(i['hosts'][:3])} with EDR before collecting forensic artefacts.")
        steps = first + [s for s in _next_steps(ctx, 10) if s not in first]
        kb = self.tb.search_knowledge_base(" ".join(i["stages"]) + " playbook containment", 2)
        return _ans(summary=f"Recommended next steps for {i['number']} (status {i['status']}), ordered by urgency:",
                    next_steps=steps[:8],
                    evidence=[{"statement": f"Playbook guidance — {p['source']}: {p['text'][:300]}…", "event_ids": [],
                               "detection_ids": []} for p in kb["passages"]],
                    inference=["Containment comes first where data loss or credential compromise is ongoing."],
                    uncertainty=_uncertainty(ctx)[-1:])

    def false_positives(self, ctx, question=""):
        return _ans(summary="Possible benign explanations for each detection, and how to rule them out:",
                    evidence=[{"statement": f"{d['rule_key']} {d['title']}: " + " / ".join(d["false_positives"]),
                               "event_ids": d["evidence_event_uids"][:2], "detection_ids": [d["id"]]} for d in ctx["detections"]],
                    inference=["Multiple independent detections along one attack sequence make a purely benign explanation "
                               "less likely than any single detection would." if len(ctx["detections"]) > 2 else
                               "With few detections, a benign explanation is plausible and should be ruled out first."],
                    next_steps=["Confirm activity with the account owners and check change tickets before containment "
                                "actions that could disrupt the business."])

    def related(self, ctx, question=""):
        i = ctx["incident"]
        in_incident = self.tb.event_uids.copy()
        found = []
        for u in i["users"][:2]:
            found += self.tb.search_events(user=u, limit=25)["events"]
        for h in i["hosts"][:2]:
            found += self.tb.search_events(host=h, limit=25)["events"]
        outside = {e["event_uid"]: e for e in found if e["event_uid"] not in in_incident}
        ev = [{"statement": f"{e['timestamp']} {e['type']} {e.get('action') or ''} {e.get('user') or ''} on {e.get('host') or ''}"
                            + (f": {e['command']}" if e.get("command") else ""), "event_ids": [e["event_uid"]], "detection_ids": []}
              for e in sorted(outside.values(), key=lambda e: e["timestamp"], reverse=True)[:15]]
        return _ans(summary=f"{len(outside)} recent event(s) involve the same users/hosts but are not part of "
                            f"{i['number']}'s evidence (most recent first):", evidence=ev,
                    uncertainty=["These events share an entity with the incident; sharing an entity does not by itself make them malicious."])

    def ciso(self, ctx, question=""):
        i = ctx["incident"]
        exfil = sum(d["evidence_summary"].get("total_bytes", 0) for d in ctx["detections"] if d["rule_key"] == "SX-009")
        files = [f for d in ctx["detections"] if d["rule_key"] == "SX-008" for f in d["evidence_summary"].get("files", [])]
        impact = []
        if exfil:
            impact.append(f"approximately {fmt_bytes(exfil)} of data was transferred to external destination(s)")
        if files:
            impact.append(f"{len(files)} sensitive file(s) were accessed")
        if "Privilege Escalation" in i["stages"]:
            impact.append("the actor obtained elevated privileges")
        return _ans(
            summary=f"{i['number']} ({i['severity'].upper()}, SentinelX Risk {i['risk_score']}/100): {i['title']}. "
                    + (f"Business impact: {'; '.join(impact)}. " if impact else "No confirmed data loss at this time. ")
                    + f"Current status: {i['status']}. Affected: {len(i['users'])} account(s), {len(i['hosts'])} system(s).",
            evidence=[{"statement": f"{d['stage']}: {d['title']} ({d['timestamp'][:16].replace('T', ' ')} UTC)",
                       "event_ids": [], "detection_ids": [d["id"]]} for d in ctx["detections"]],
            inference=["Decisions required: approve containment (account suspension, host isolation, destination blocking) "
                       "and determine whether regulatory or customer notification assessment must begin." if impact else
                       "Decision required: approve containment actions proposed by the SOC."],
            uncertainty=["Scope is based on logs available to the SOC; forensic confirmation is pending."],
            next_steps=_next_steps(ctx, 4))

    def technical_report(self, ctx, question=""):
        base = self.summary(ctx)
        tl = self.tb.get_timeline(ctx["incident"]["number"], 60)
        base["evidence"] += [{"statement": f"{e['timestamp']} {e['type']}/{e.get('action') or ''} user={e.get('user')} "
                                           f"host={e.get('host')} src={e.get('source_ip')} dst={e.get('destination_ip')}"
                                           + (f" cmd={e['command']}" if e.get("command") else "")
                                           + (f" resource={e['resource']}" if e.get("resource") else ""),
                              "event_ids": [e["event_uid"]], "detection_ids": []} for e in tl["events"][:40]]
        base["summary"] = "Technical incident report. " + base["summary"]
        return base

    def junior(self, ctx, question=""):
        i = ctx["incident"]
        steps = [f"{n}. **{s}** — the attacker was {STAGE_PLAIN.get(s, 'doing something suspicious')}." for n, s in
                 enumerate(i["stages"], 1)]
        return _ans(
            summary=f"Think of {i['number']} as a story in {len(i['stages'])} chapters:\n\n" + "\n".join(steps),
            evidence=[{"statement": f"Chapter '{d['stage']}': the rule {d['rule_key']} noticed this because — {d['explanation']}",
                       "event_ids": d["evidence_event_uids"][:2], "detection_ids": [d["id"]]} for d in ctx["detections"]],
            inference=["SentinelX groups these detections because they share the same user, host or IP address within a "
                       "short time window — that is what 'correlation' means."],
            uncertainty=["Any single step can have an innocent explanation; the combination is what makes it concerning."],
            next_steps=["Read each detection's explanation and open its evidence events.",
                        "Ask a senior analyst before taking containment actions."] + _next_steps(ctx, 2),
            techniques=_techniques(ctx))

    # ------------------------------------------------------------------ other intents
    def explain_technique(self, tid: str, incident_ref: str | None) -> dict:
        info = self.tb.get_mitre(tid)
        if "error" in info:
            return _ans(summary=info["error"] + " SentinelX only describes techniques in its catalogue to avoid "
                                                "inventing definitions.")
        ev, inf = [], []
        if incident_ref:
            ctx = self.tb.get_incident(incident_ref)
            mapped = [t for t in ctx.get("techniques", []) if t["id"] == tid]
            if mapped:
                ev.append({"statement": f"In {ctx['incident']['number']}: {mapped[0]['reason']}",
                           "event_ids": mapped[0]["event_uids"][:3], "detection_ids": []})
            else:
                inf.append(f"{tid} is not mapped to the current incident.")
        return _ans(summary=f"{info['id']} — {info['name']} (tactic: {info['tactic']}). {info['description']}",
                    evidence=ev, inference=inf, next_steps=[f"Detection guidance: {info['detection_guidance']}",
                                                            f"Reference: {info['url']}"],
                    techniques=[{"id": tid, "reason": info["description"]}])

    def explain_event(self, uid: str) -> dict:
        e = self.tb.get_event(uid)
        if "error" in e:
            return _ans(summary=e["error"])
        fields = ", ".join(f"{k}={e[k]}" for k in ("type", "action", "status", "user", "host", "source_ip",
                                                   "destination_ip", "process", "resource", "bytes") if e.get(k) not in (None, ""))
        dets = e["detections"]
        return _ans(summary=f"Event {uid} at {e['timestamp']}: {fields}." + (f" Command: {e['command']}" if e.get("command") else ""),
                    evidence=[{"statement": f"Referenced by detection {d['rule_key']} — {d['title']}", "event_ids": [uid],
                               "detection_ids": [d["id"]]} for d in dets] or
                             [{"statement": "No detection references this event.", "event_ids": [uid], "detection_ids": []}],
                    inference=[f"Additional metadata fields: {', '.join(list(e['metadata'])[:12])}" if e.get("metadata") else
                               "No additional metadata."])

    def compare(self, refs: list[str], incident_ref: str | None) -> dict:
        refs = list(dict.fromkeys([r.upper() for r in refs] + ([incident_ref] if incident_ref else [])))
        if len(refs) < 2:
            lst = self.tb.list_incidents(limit=5)["incidents"]
            refs = [i["number"] for i in lst[:2]]
        ctxs = [self.tb.get_incident(r) for r in refs[:3]]
        ctxs = [c for c in ctxs if "error" not in c]
        if len(ctxs) < 2:
            return _ans(summary="At least two incidents are needed for a comparison.")
        sets = lambda k: [set(c["incident"][k]) for c in ctxs]  # noqa: E731
        tech_sets = [{t["id"] for t in c["techniques"]} for c in ctxs]
        shared = {k: sorted(set.intersection(*sets(k))) for k in ("users", "hosts", "source_ips")}
        shared_t = sorted(set.intersection(*tech_sets))
        return _ans(
            summary="Comparison of " + " vs ".join(c["incident"]["number"] for c in ctxs) + ".",
            evidence=[{"statement": f"{c['incident']['number']}: {c['incident']['title']} — risk {c['incident']['risk_score']}, "
                                    f"stages {' → '.join(c['incident']['stages'])}", "event_ids": [],
                       "detection_ids": [d["id"] for d in c["detections"]][:5]} for c in ctxs],
            inference=[f"Shared users: {', '.join(shared['users']) or 'none'}; shared hosts: {', '.join(shared['hosts']) or 'none'}; "
                       f"shared source IPs: {', '.join(shared['source_ips']) or 'none'}.",
                       f"Shared techniques: {', '.join(shared_t) or 'none'}."],
            uncertainty=["No shared entities suggests separate activity, but a common actor using different infrastructure "
                         "cannot be ruled out from telemetry alone."] if not any(shared.values()) else [],
            techniques=[{"id": t, "reason": "Present in all compared incidents."} for t in shared_t])

    def general(self, question: str, intent: str) -> dict:
        q = question.lower()
        if re.search(r"incident|what('s| is) (happening|going on)|open cases|status of", q):
            lst = self.tb.list_incidents(limit=10)["incidents"]
            return _ans(summary=f"{len(lst)} incident(s) in this workspace, highest risk first:",
                        evidence=[{"statement": f"{i['number']} [{i['severity'].upper()}, risk {i['risk_score']}, {i['status']}] "
                                                f"{i['title']}", "event_ids": [], "detection_ids": []} for i in lst],
                        next_steps=["Open an incident and ask 'What happened?' for an evidence-based summary."])
        kb = self.tb.search_knowledge_base(question, 3)
        passages = kb["passages"]
        if not passages:
            return _ans(summary="LOCAL analysis mode cannot compose free-form answers, and no relevant passage was found "
                                "in the knowledge base. Configure an LLM provider for general questions, or rephrase.",
                        uncertainty=["No knowledge-base passage matched this question."])
        return _ans(summary="LOCAL analysis mode (no language model configured). The most relevant knowledge-base passages "
                            "for your question are quoted below with their sources.",
                    evidence=[{"statement": f"From \"{p['source']}\" (relevance {p['score']:.2f}): {p['text']}",
                               "event_ids": [], "detection_ids": []} for p in passages],
                    uncertainty=["Passages are retrieved by lexical similarity; verify they answer your exact question."])
