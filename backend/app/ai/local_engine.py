"""Rule-based planner used when no language model is connected (or the model call failed).

It routes the question to the same SentinelX tools the language model uses and composes a cited
answer from their results. It never invents content: every statement comes from a tool result.
The agent labels these answers as rule-based analysis.
"""

import re

from app.ai import tools
from app.analysis.hunts import translate
from app.analysis.simulation import CONTROLS

CONTROL_WORDS = {"mfa": "mfa", "multi-factor": "mfa", "2fa": "mfa", "powershell": "powershell_constrained",
                 "credential guard": "credential_guard", "lsass": "credential_guard", "dlp": "dlp_egress",
                 "egress": "dlp_egress", "approval": "privileged_group_approval", "segmentation": "network_segmentation"}
SCENARIO_WORDS = {"brute": "credential_compromise", "credential": "credential_compromise", "spray": "password_spray",
                  "exfil": "insider_cloud_exfil", "insider": "insider_cloud_exfil", "scan": "internal_scan",
                  "dump": "admin_credential_dumping", "macro": "macro_powershell", "domain admin": "domain_admin_escalation"}


def _call(ctx: tools.ToolContext, tool_name: str, **args) -> dict:
    result, _ = tools.call(ctx, tool_name, args)
    ctx.state.setdefault("_results", []).append(result)
    return result


def _e(e: dict) -> str:
    what = e.get("command") or e.get("resource") or e.get("action") or ""
    who = " ".join(x for x in (f"[USER:{e['user']}]" if e.get("user") else "", f"on [HOST:{e['host']}]" if e.get("host") else "",
                               f"from [IP:{e['src']}]" if e.get("src") else "") if x)
    return f"`{e.get('time', '')[:19].replace('T', ' ')}` {e.get('type', '')} {e.get('status') or ''} {who} {what[:120]} [EVT:{e['event_uid']}]"


def _events_table(events: list[dict], limit: int = 12) -> str:
    return "\n".join(f"- {_e(e)}" for e in events[:limit])


def answer(ctx: tools.ToolContext, question: str, mode: str) -> str:
    q = question.lower()
    focus = ctx.state.get("focus", {})
    controls = sorted({v for k, v in CONTROL_WORDS.items() if k in q})

    if mode == "hunt" or re.match(r"^\s*(find|hunt|search for|look for|show me all)\b", q):
        return _hunt(ctx, question)
    if mode == "report" or re.search(r"\b(generate|create|write)\b.*\breport\b", q):
        rtype = "executive" if re.search(r"executive|ciso|non-technical", q) else "technical" if "technical" in q else "incident"
        if not focus.get("incident"):
            return "Which incident should the report cover? Mention its number (for example INC-0006)."
        r = _call(ctx, "generate_report", incident=focus["incident"], report_type=rtype)
        if "error" in r:
            return r["error"]
        return (f"Generated the {rtype} report **{r['title']}** from the incident's stored evidence "
                f"([INC:{focus['incident']}]). Open it from the report card below to print or export it.")
    if mode == "simulate" or re.search(r"\bwhat (happens|would happen|if)\b|\bsimulat", q):
        return _simulate(ctx, q, controls)
    if re.search(r"what (happened|changed)( in the environment)? today|what('s| is) new|changed (today|recently)", q):
        return _changes(ctx)
    if re.search(r"(most serious|biggest|top|highest[- ]risk|unresolved|still open|open) (incidents?|risks?)", q):
        return _open_incidents(ctx)
    if re.search(r"risk (increase|increased|rise|jump)|biggest risk increase", q):
        if focus.get("entity") and re.search(r"\bwhy\b", q):
            return _risk_history(ctx, focus["entity"])
        return _movers(ctx)
    if re.search(r"weak|poor coverage|detection gaps?|which (detection )?rules", q):
        return _rule_quality(ctx)
    if re.search(r"behaving strangely|unusual (user|behavior|behaviour)|strange|anomal|unexplained", q) and not focus.get("incident"):
        return _strange(ctx)
    if re.search(r"\bcompare\b", q):
        return _compare(ctx, question)
    if re.search(r"\bconnect|\bpath\b|\blinked\b|\brelated to\b", q):
        return _paths(ctx, question)
    if re.search(r"between (\d{1,2}):?(\d{2})? and (\d{1,2})", q):
        return _hunt(ctx, question)
    if focus.get("event") and re.search(r"\bbefore\b|\bafter\b|\bpreceded\b|\bnext\b|\bthen\b", q):
        return _around(ctx, focus["event"], q)
    if focus.get("detection") and re.search(r"\bwhy\b|fire|trigger|cause|explain|mean", q):
        return _detection(ctx, focus["detection"])
    if focus.get("event") and re.search(r"mean|explain|unusual|normal|what is this|what happened", q):
        return _explain_event(ctx, focus["event"])
    if focus.get("entity") and (re.search(r"summar|tell me|who is|normal|compromised|profile|done this before|behav|active", q)
                                or not focus.get("incident")):
        return _entity(ctx, focus["entity"], q)
    if focus.get("technique") and not focus.get("incident"):
        return _mitre(ctx, focus["technique"])
    if focus.get("incident"):
        return _incident(ctx, focus["incident"], q)
    return _overview(ctx, question)


# --------------------------------------------------------------------------------------------- handlers
def _hunt(ctx, question: str) -> str:
    t = translate(question)
    r = _call(ctx, "run_hunt", spec=t["spec"], name=question[:80], natural_language=question, translation="rule-based")
    if "error" in r:
        return r["error"]
    lines = "\n".join(f"- **{d['label']}:** {d['value']}" for d in r["description"])
    out = [f"Hunt [HUNT:{r['hunt']}] found **{r['total']}** matching event(s).", "", "**Generated search** "
           "(rule-based translation — edit it in the Hunt builder if it misses your intent):", lines]
    if r["events"]:
        out += ["", "**Matches (most relevant first)**", _events_table(r["events"])]
    if r["entities"]["users"] or r["entities"]["hosts"]:
        out += ["", "**Entities involved:** " + ", ".join([f"[USER:{u}]" for u in r["entities"]["users"][:6]] +
                                                          [f"[HOST:{h}]" for h in r["entities"]["hosts"][:6]])]
    if not r["total"]:
        out += ["", "The available telemetry contains no events matching this search. Widen the time range or remove "
                    "a behavior constraint."]
    return "\n".join(out)


def _simulate(ctx, q: str, controls: list[str]) -> str:
    focus = ctx.state.get("focus", {})
    if controls and focus.get("incident") and not any(w in q for w in SCENARIO_WORDS):
        r = _call(ctx, "defense_what_if", incident=focus["incident"], controls=controls)
        if "error" in r:
            return r["error"]
        rows = "\n".join(f"- **{s['status'].upper()}** — [DET:{s['detection_id']}] {s['title']} ({s['reason']})" for s in r["steps"])
        return (f"Modeled {', '.join(CONTROLS[c]['label'] for c in controls)} for [INC:{r['incident']}]. Estimated risk "
                f"{r['original_risk']} → **{r['residual_risk_estimate']}**.\n\n{rows}\n\n_{r['note']}_")
    scenario = next((v for k, v in SCENARIO_WORDS.items() if k in q), "credential_compromise")
    r = _call(ctx, "run_attack_simulation", scenario=scenario, controls=controls)
    if "error" in r:
        return r["error"]
    base = r["baseline"]
    out = [f"Simulated **{scenario.replace('_', ' ')}** in the sandbox (nothing was stored). Rules that fired: "
           + (", ".join(f"[RULE:{k}]" for k in base["rules_fired"]) or "none") + ".",
           f"Detected stages: {' → '.join(base['stages_detected']) or 'none'}; estimated risk {base['estimated_risk']}."]
    if r.get("with_controls"):
        out += ["", f"**With controls:** {r['summary']}"]
        out += [f"- Blocked: {b['detail'] or b['event_type']} ({CONTROLS[b['control']]['label']})" for b in r["blocked_steps"]]
    out += ["", f"_{r['label']}_"]
    return "\n".join(out)


def _changes(ctx) -> str:
    r = _call(ctx, "environment_changes", hours=24)
    if "note" in r and len(r) == 1:
        return r["note"]
    w = r["window"]
    out = [f"Changes in the last 24 hours of data ({w['start'][:16].replace('T', ' ')} → {w['end'][:16].replace('T', ' ')} UTC), "
           "compared with everything earlier:"]
    for key, label, tok in (("new_users", "First-seen users", "USER"), ("new_hosts", "First-seen hosts", "HOST"),
                            ("new_source_ips", "First-seen source IPs", "IP"), ("new_destinations", "First-seen destinations", "IP")):
        if r[key]:
            out.append(f"- **{label}:** " + ", ".join(f"[{tok}:{x}]" for x in r[key][:10]))
    if r["new_processes"]:
        out.append("- **First-seen processes:** " + ", ".join(f"`{p}`" for p in r["new_processes"][:10]))
    changed = [v for v in r["volume_by_event_type"] if v["change_pct"] is not None and abs(v["change_pct"]) >= 50]
    if changed:
        out.append("- **Volume changes:** " + "; ".join(f"{v['event_type']} {v['recent']} vs ~{v['expected_from_history']} "
                                                       f"expected ({v['change_pct']:+d}%)" for v in changed))
    if r["new_incidents"]:
        out.append("- **New incidents:** " + ", ".join(f"[INC:{i['number']}] {i['title']}" for i in r["new_incidents"]))
    if r["new_detections"]:
        out.append(f"- **New detections:** {len(r['new_detections'])}, e.g. " +
                   "; ".join(f"[DET:{d['id']}] {d['title']}" for d in r["new_detections"][:5]))
    if len(out) == 1:
        out.append("- No first-seen entities, volume changes or new detections in this window.")
    return "\n".join(out)


def _open_incidents(ctx) -> str:
    r = _call(ctx, "search_incidents", open_only=True, sort="risk", limit=10)
    if not r["incidents"]:
        return "There are no open incidents in this workspace."
    rows = "\n".join(f"| [INC:{i['number']}] | {i['severity']} | {i['risk']} | {i['status']} | {' → '.join(i['stages'][:4])} |"
                     for i in r["incidents"])
    return ("Open incidents ranked by SentinelX Risk Score (an additive score of severity, confidence, attack-chain "
            "breadth, privilege escalation, data transfer, techniques, entities, anomalies and threat intel):\n\n"
            "| Incident | Severity | Risk | Status | Stages |\n|---|---|---|---|---|\n" + rows)


def _movers(ctx) -> str:
    r = _call(ctx, "risk_movers", kind="user")
    if not r["movers"]:
        return "No entity's risk increased on the latest day of data compared with its earlier average."
    rows = "\n".join(f"- [USER:{m['entity']}] +{m['increase']} points ({m['latest_points']} on {m['latest_day']} vs "
                     f"{m['previous_daily_average']} average) — {', '.join(m['drivers'][:4])}" for m in r["movers"])
    return f"Biggest risk increases on the latest day of data:\n\n{rows}\n\n_{r['method']}_"


def _risk_history(ctx, entity: dict) -> str:
    r = _call(ctx, "get_risk_history", kind=entity["kind"], name=entity["name"])
    if "error" in r:
        return r["error"]
    days = [h for h in r["history"] if h["risk_points"]]
    tok = entity["kind"].upper()
    if not days:
        return f"[{tok}:{entity['name']}] has no detections or anomalies contributing risk."
    rows = "\n".join(f"- **{h['day']}**: {h['risk_points']} points — {', '.join(h['detections'])}"
                     + (f"; {h['anomalous_windows']} anomalous window(s)" if h["anomalous_windows"] else "") for h in days)
    return f"Risk for [{tok}:{entity['name']}] rose on these days, driven by:\n\n{rows}"


def _rule_quality(ctx) -> str:
    r = _call(ctx, "rule_quality")
    weak = [x for x in r["rules"] if x["weaknesses"]]
    if not weak:
        return "No weaknesses found: all rules pass regression and every evasion test."
    rows = "\n".join(f"- [RULE:{x['rule_key']}] {x['name']}: {'; '.join(x['weaknesses'])}" for x in weak)
    return ("Rules with measured weaknesses (from the regression suite on known scenarios and evasion tests that "
            f"replay realistic attack variations):\n\n{rows}\n\nA candidate rule can close a gap: describe the behavior "
            "and backtest it in the Detection Lab.")


def _strange(ctx) -> str:
    f = _call(ctx, "find_unexplained_behavior")["findings"]
    m = _call(ctx, "risk_movers", kind="user")["movers"]
    out = []
    anomalies = [x for x in f if x["type"] == "unexplained_anomaly"]
    if anomalies:
        out.append("**Anomalous behavior with no detection explaining it:**")
        out += [f"- [{x['entity_type'].upper()}:{x['entity']}] on {x['day']} (IF score {x['score']}): {x['detail']}" for x in anomalies[:8]]
    if m:
        out.append("\n**Largest risk increases:**")
        out += [f"- [USER:{x['entity']}] +{x['increase']} — {', '.join(x['drivers'][:3])}" for x in m[:5]]
    return "\n".join(out) or "No anomalous behavior or risk increases were found in the current data."


def _compare(ctx, question: str) -> str:
    incs = re.findall(r"INC-\d+", question.upper())
    focus = ctx.state.get("focus", {}).get("incident")
    if len(incs) < 2 and focus:
        incs = list(dict.fromkeys(([focus] if focus else []) + incs))
    if not incs:
        return "Mention the incidents to compare (for example INC-0006 and INC-0007)."
    r = _call(ctx, "find_similar_incidents", incident=incs[0])
    if "error" in r:
        return r["error"]
    rows = [s for s in r["similar"] if len(incs) < 2 or s["number"] in incs[1:]] or r["similar"][:3]
    out = [f"Attack DNA comparison for [INC:{incs[0]}] (signature `{r['dna_signature']}`):", "",
           "| Incident | Similarity | Techniques | Sequence | Rules | Entities | Traits | Shared techniques |",
           "|---|---|---|---|---|---|---|---|"]
    for s in rows:
        c = s["components"]
        out.append(f"| [INC:{s['number']}] | **{s['score']}** | {c['techniques']} | {c['sequence']} | {c['rules']} | "
                   f"{c['entities']} | {c['traits']} | {', '.join(s['shared_techniques']) or '—'} |")
    out += ["", f"Similarity is a weighted blend ({', '.join(f'{k} {v}' for k, v in r['weights'].items())})."]
    return "\n".join(out)


def _paths(ctx, question: str) -> str:
    from app.analysis.resolver import resolve_references

    refs = [r for r in resolve_references(ctx.db, ctx.ws, question) if r["type"] in ("USER", "HOST", "IP", "INC")]
    kinds = {"USER": "user", "HOST": "host", "IP": "ip", "INC": "incident"}
    if len(refs) < 2:
        return "Name two entities to connect (for example 't.nguyen' and 'NB-FS01')."
    a, b = refs[0], refs[1]
    r = _call(ctx, "find_attack_paths", source=f"{kinds[a['type']]}:{a['id']}", target=f"{kinds[b['type']]}:{b['id']}")
    if "error" in r:
        return r["error"]
    if not r["found"]:
        return f"No observed path connects [{a['type']}:{a['id']}] and [{b['type']}:{b['id']}] within 5 hops."
    return (f"Observed connections between [{a['type']}:{a['id']}] and [{b['type']}:{b['id']}]:\n\n"
            + "\n".join(f"{n}. {p}" for n, p in enumerate(r["paths"], 1)) + f"\n\n_{r['note']}_")


def _around(ctx, uid: str, q: str) -> str:
    r = _call(ctx, "events_around", event_id=uid, before_minutes=60, after_minutes=60)
    if "error" in r:
        return r["error"]
    want_after = "after" in q or "next" in q or "then" in q
    part = r["after"] if want_after else r["before"]
    label = "after" if want_after else "before"
    if not part:
        return f"No events involving the same user, host or IP occurred within 60 minutes {label} [EVT:{uid}]."
    evs = part if want_after else list(reversed(part))
    return f"Events {label} [EVT:{uid}] involving the same user, host or IP (within 60 minutes):\n\n{_events_table(evs, 15)}"


def _detection(ctx, did) -> str:
    r = _call(ctx, "get_detection", detection_id=int(str(did).upper().removeprefix("DET-")))
    if "error" in r:
        return r["error"]
    out = [f"**Why [DET:{r['id']}] fired ([RULE:{r['rule_key']}]):** {r['explanation']}"]
    if r.get("rule"):
        params = ", ".join(f"{k}={v}" for k, v in r["rule"]["parameters"].items() if not isinstance(v, (list, dict)))
        out.append(f"\n**Rule:** {r['rule']['name']} (v{r['rule']['version']}) — thresholds: {params or 'pattern-based'}")
    out.append("\n**Matched events:**\n" + _events_table(r["matched_events"], 10))
    if r["mitre"]:
        out.append("\n**ATT&CK:** " + "; ".join(f"[TECH:{m['id']}] {m['reason']}" for m in r["mitre"]))
    out.append("\n**Possible benign explanations:** " + " / ".join(r["false_positives"][:3]))
    return "\n".join(out)


def _explain_event(ctx, uid: str) -> str:
    e = _call(ctx, "get_event", event_id=uid)
    if "error" in e:
        return e["error"]
    out = [f"**[EVT:{uid}]** — {_e(e)}"]
    if e.get("user"):
        b = _call(ctx, "compare_to_baseline", kind="user", name=e["user"], at=e["time"])
        at = b.get("at") or {}
        if at.get("normally_active") is False:
            out.append(f"\n**Unusual timing:** [USER:{e['user']}] had {at['events_in_that_hour_on_other_days']} events in "
                       f"hour {at['hour_utc']:02d}:00 UTC across {at['other_days_observed']} other days; usual active hours: "
                       f"{', '.join(f'{h:02d}' for h in at['usual_active_hours_utc'])}.")
        elif at.get("normally_active"):
            out.append(f"\n**Timing is normal** for [USER:{e['user']}] (active at this hour on other days).")
        if e.get("src") and b["baseline"].get("source_ips") and e["src"] not in b["baseline"]["source_ips"][:10]:
            out.append(f"- Source [IP:{e['src']}] is not among the user's usual sources.")
    if e.get("detections"):
        out.append("\n**Referenced by detections:** " + ", ".join(f"[DET:{d['id']}] {d['title']}" for d in e["detections"]))
    else:
        out.append("\nNo detection references this event.")
    if e.get("incidents"):
        out.append("**Part of:** " + ", ".join(f"[INC:{i['number']}] ({i['role']})" for i in e["incidents"]))
    return "\n".join(out)


def _entity(ctx, entity: dict, q: str) -> str:
    r = _call(ctx, "get_entity", kind=entity["kind"], name=entity["name"])
    if "error" in r:
        return r["error"]
    tok = f"[{entity['kind'].upper()}:{entity['name']}]"
    b = r["baseline"]
    out = [f"**{tok}**" + (f" — SentinelX {entity['kind'].title()} Risk **{r['risk']['score']}/100** ({r['risk']['band']})"
                           if r.get("risk") else "")]
    if r.get("risk"):
        out.append("Risk factors: " + "; ".join(f"{f['factor']} +{f['points']} ({f['detail']})" for f in r["risk"]["factors"]))
    out.append(f"\n**Normal behavior:** {b['events']} events over {b['days_observed']} day(s); usually active "
               f"{', '.join(f'{h:02d}' for h in b['usual_active_hours_utc'] or [])} UTC; usual sources "
               f"{', '.join(f'[IP:{i}]' for i in (b['source_ips'] or [])[:4]) or '—'}.")
    if r["recent_detections"]:
        out.append("**Recent detections:** " + "; ".join(f"[DET:{d['id']}] {d['title']}" for d in r["recent_detections"][:6]))
    if r["incidents"]:
        out.append("**Incidents:** " + ", ".join(f"[INC:{i['number']}] ({i['status']})" for i in r["incidents"]))
    if entity["kind"] == "user" and re.search(r"normal|peer|compar|strange|unusual|compromised", q):
        p = _call(ctx, "peer_comparison", name=entity["name"])
        above = [c for c in p["comparison"] if c["above_all_peers"]]
        out.append(f"\n**Peer comparison** ({p['peer_basis']}): " + ("; ".join(
            f"{c['feature'].replace('_', ' ')} {c['value']} vs peer median {c['peer_median']}" for c in above)
            or "no feature exceeds every peer."))
    if "compromised" in q:
        out.append("\n**Assessment:** the evidence above shows what was observed; whether the account is compromised "
                   "depends on confirming the flagged activity with the account owner. Recommended next checks: review "
                   "the listed detections' evidence, the authentication sources, and activity after the first detection.")
    return "\n".join(out)


def _mitre(ctx, tid: str) -> str:
    r = _call(ctx, "search_mitre", query=tid)
    if not r.get("matches"):
        return r.get("note", "Technique not found.")
    m = r["matches"][0]
    out = [f"**[TECH:{m['id']}] {m['name']}** ({m['tactic']}): {m['description']}", f"\nDetection guidance: {m['detection_guidance']}"]
    if m["observed_in"]:
        out.append("\n**Observed in this workspace:**")
        out += [f"- [INC:{o['incident']}] — {o['reason']} " + " ".join(f"[EVT:{u}]" for u in o["evidence"][:3]) for o in m["observed_in"]]
    else:
        out.append("\nNot observed in this workspace.")
    return "\n".join(out)


_FULL_PARTS = (r"evidence|support", r"contradict|against", r"don'?t know|unknown|missing", r"next|should i")


def _incident(ctx, number: str, q: str) -> str:
    inc = _call(ctx, "get_incident", incident=number)
    if "error" in inc:
        return inc["error"]
    # "Investigate INC-…" or a multi-part question: narrative, evidence, contradictions, unknowns and next steps.
    if re.match(r"\s*investigate\b", q) or sum(bool(re.search(p, q)) for p in _FULL_PARTS) >= 2:
        return "\n\n".join(_incident_section(ctx, inc, part) for part in
                           ("", "what evidence supports it", "what contradicts it", "what don't we know",
                            "what should i investigate next"))
    return _incident_section(ctx, inc, q)


def _incident_section(ctx, inc: dict, q: str) -> str:
    number = inc["number"]
    tok = f"[INC:{inc['number']}]"
    dets = inc["detections"]
    if re.search(r"high risk|suspicious|why .*risk|why .*serious|matter", q):
        return (f"{tok} scores **{inc['risk_score']}/100 ({inc['risk_band']})** on the SentinelX Risk Score. Contributing factors:\n\n"
                + "\n".join(f"- **{f['factor']}** +{f['points']}/{f['max']}: {f['detail']}" for f in inc["risk_factors"])
                + f"\n\n**Why these detections were grouped:** {inc['correlation_reason']}")
    if re.search(r"which detections|what detections|alerts fired|rules fired|caused|trigger|fire", q):
        return f"Detections in {tok}:\n\n" + "\n".join(
            f"- [DET:{d['id']}] [RULE:{d['rule_key']}] {d['title']} ({d['severity']}, {d['time'][:19].replace('T', ' ')}): {d['explanation']}"
            for d in dets)
    if re.search(r"\bhosts?\b|machines|servers|endpoints", q):
        return f"Hosts involved in {tok}: " + ", ".join(f"[HOST:{h}]" for h in inc["hosts"]) + "."
    if re.search(r"accounts?|users?|who\b", q):
        return f"Accounts involved in {tok}: " + ", ".join(f"[USER:{u}]" for u in inc["users"]) + "."
    if re.search(r"\bips?\b|addresses", q):
        return (f"Source IPs in {tok}: " + (", ".join(f"[IP:{i}]" for i in inc["source_ips"]) or "none")
                + ". External destinations: " + (", ".join(f"[IP:{i}]" for i in inc["destination_ips"]) or "none") + ".")
    if re.search(r"mitre|techniques?|tactics?|att&ck", q):
        return f"ATT&CK techniques mapped to {tok} (each justified by evidence):\n\n" + "\n".join(
            f"- [TECH:{t['id']}] {t['name']} ({t['confidence']}): {t['reason']} " + " ".join(f"[EVT:{u}]" for u in t["evidence"][:2])
            for t in inc["techniques"])
    if re.search(r"similar|seen (this|it) before|before\?|same attack|family", q):
        return _compare(ctx, number)
    if re.search(r"contradict|against|disprove|benign|false positive", q):
        mem = _call(ctx, "get_investigation_memory", incident=number)["items"]
        contra = [m for m in mem if m["kind"] == "hypothesis" and m["contradicting"]]
        out = [f"**Evidence that could contradict {tok}:**"]
        out += [f"- Recorded hypothesis '{m['text']}' has contradicting evidence: {', '.join(m['contradicting'])} (historical record)" for m in contra]
        out += [f"- [DET:{d['id']}] could be benign if: {' / '.join(d['false_positives'])}" for d in dets[:6]]
        return "\n".join(out)
    if re.search(r"don'?t know|unknown|uncertain|missing|gaps?", q):
        f = _call(ctx, "find_unexplained_behavior")["findings"]
        missing = [x for x in f if x["type"] == "missing_telemetry" and x["entity"] in inc["hosts"]]
        mem = _call(ctx, "get_investigation_memory", incident=number)["items"]
        open_q = [m for m in mem if m["kind"] == "question" and m["status"] == "open"]
        out = [f"**What we don't know about {tok}:**"]
        out += [f"- Missing telemetry: {m['detail']} ([HOST:{m['entity']}])" for m in missing]
        out += [f"- Open question (recorded): {m['text']}" for m in open_q]
        low = [t for t in inc["techniques"] if t["confidence"] in ("low", "medium")]
        out += [f"- [TECH:{t['id']}] mapping is only {t['confidence']} confidence." for t in low]
        out.append("- Activity on systems that do not send telemetry to SentinelX is not visible.")
        return "\n".join(out)
    if re.search(r"investigate next|next steps?|what should i|recommend|do next", q):
        checks = [c["item"] for c in inc["checklist"] if not c["done"]]
        out = [f"**Recommended next checks for {tok}** (from its unresolved checklist items and detection guidance):"]
        out += [f"{n}. {c}" for n, c in enumerate(checks[:6], 1)]
        out.append("\nWhy: these items are not yet marked done, and each addresses a stage of the attack that the evidence "
                   "shows but has not been confirmed with the account owners or host forensics.")
        return "\n".join(out)
    if re.search(r"evidence|support|prove", q):
        return f"Evidence supporting {tok}:\n\n" + "\n".join(
            f"- [DET:{d['id']}] {d['title']}: {d['explanation']} " + " ".join(f"[EVT:{u}]" for u in d["evidence_event_uids"][:3])
            for d in dets)
    tl = _call(ctx, "get_incident_timeline", incident=number, limit=40)
    seq = " → ".join(inc["stages"])
    out = [f"{tok} **{inc['title']}** — {inc['severity']}, risk {inc['risk_score']}/100, status {inc['status']}.",
           f"\n**Sequence:** {seq} between {inc['first_seen'][:19].replace('T', ' ')} and {inc['last_seen'][:19].replace('T', ' ')} UTC, "
           f"involving " + ", ".join([f"[USER:{u}]" for u in inc["users"][:3]] + [f"[HOST:{h}]" for h in inc["hosts"][:3]]) + ".",
           "\n**What happened (detections in order):**"]
    out += [f"{n}. {d['time'][11:19]} [DET:{d['id']}] {d['title']} " + " ".join(f"[EVT:{u}]" for u in d["evidence_event_uids"][:2])
            for n, d in enumerate(dets, 1)]
    if tl.get("phases"):
        out.append(f"\nThe evidence timeline has {len(tl['phases'])} activity phase(s) separated by pauses of 15+ minutes.")
    out.append(f"\n**Why grouped:** {inc['correlation_reason']}")
    return "\n".join(out)


def _overview(ctx, question: str) -> str:
    o = _call(ctx, "get_environment_overview")
    kb = _call(ctx, "search_knowledge_base", query=question)
    out = [f"Workspace **{o['workspace']}**: {o['counts']['events']} events, {o['counts']['detections']} detections, "
           f"{o['counts']['open_incidents']} open incident(s)."]
    if o["open_incidents_by_risk"]:
        out.append("Highest-risk open incidents: " + ", ".join(f"[INC:{i['number']}] (risk {i['risk']})" for i in o["open_incidents_by_risk"][:4]) + ".")
    if kb.get("passages"):
        out.append("\n**From the knowledge base:**")
        out += [f"- *{p['document']}* — {p['section']}: {p['text'][:400]}…" for p in kb["passages"][:2]]
    out.append("\nAsk about an incident, event, user, host, IP, rule or technique by name or ID for a specific answer.")
    return "\n".join(out)
