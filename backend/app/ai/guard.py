"""Prompt-injection defenses and output grounding validation.

- Untrusted strings (telemetry, documents, notes) are escaped so they cannot close the XML-style
  delimiters that separate them from instructions.
- Injection-like phrases inside untrusted data are detected and surfaced as findings (they are data).
- Model output is validated against the references that were actually present in the context:
  unknown event IDs, detection IDs or ATT&CK techniques are removed and reported.
"""

import json
import re

INJECTION_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|messages)",
        r"disregard (all |any )?(the )?(previous|prior|above|system)",
        r"(reveal|print|show|output|leak) (me )?(your |the )?(system prompt|instructions|api[ _-]?keys?|secrets?|credentials)",
        r"you are now (a|an|in) ",
        r"new instructions?:",
        r"act as (an? )?(unrestricted|jailbroken|developer mode)",
        r"</?\s*(system|assistant|untrusted_data|instructions?)\s*>",
        r"do not (tell|inform) the (user|analyst)",
        r"\b(you must|assistant,|ai,|please) (now )?(delete|drop|disable|wipe|exfiltrate)\b",
    )
]
EVENT_ID_PATTERN = re.compile(r"\b(?:[A-Z]{2,}[A-Z0-9]*-(?:[A-Z0-9]+-)*\d{4,}|EVT-[0-9A-F]{12})\b")
TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def escape_untrusted(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sanitize(obj, max_str: int = 600):
    """Recursively escape and truncate strings inside untrusted structures."""
    if isinstance(obj, str):
        s = obj if len(obj) <= max_str else obj[:max_str] + "…[truncated]"
        return escape_untrusted(s)
    if isinstance(obj, dict):
        return {str(k)[:80]: sanitize(v, max_str) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v, max_str) for v in obj]
    return obj


def find_injections(obj, path: str = "", found: list | None = None, owner: str | None = None) -> list[dict]:
    """Return [{location, excerpt, event_uid}] for injection-like text inside untrusted data."""
    found = [] if found is None else found
    if isinstance(obj, dict):
        uid = obj.get("event_uid") or obj.get("uid") or owner
        for k, v in obj.items():
            find_injections(v, f"{path}.{k}" if path else str(k), found, uid)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            find_injections(v, f"{path}[{i}]", found, owner)
    elif isinstance(obj, str):
        for rx in INJECTION_PATTERNS:
            m = rx.search(obj)
            if m:
                start = max(0, m.start() - 40)
                found.append({"location": path, "event_uid": owner,
                              "excerpt": obj[start:m.end() + 40][:200]})
                break
    return found


def wrap_untrusted(label: str, payload) -> str:
    body = json.dumps(sanitize(payload), default=str, ensure_ascii=False)
    return f'<untrusted_data source="{label}">\n{body}\n</untrusted_data>'


def extract_json(text: str) -> dict | None:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        candidate = text[start:end + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def validate_answer(data: dict, allowed_events: set[str], allowed_detections: set[int],
                    allowed_techniques: set[str], allowed_incidents: set[str] | None = None) -> tuple[dict, dict]:
    """Normalize the structured answer and strip references that were not in the provided context."""
    removed_events, removed_dets, removed_techs, unverified_text = [], [], [], []
    evidence = []
    for item in _as_list(data.get("evidence")):
        if isinstance(item, str):
            item = {"statement": item}
        if not isinstance(item, dict):
            continue
        ev_ids = [str(e) for e in _as_list(item.get("event_ids"))]
        det_ids = []
        for d in _as_list(item.get("detection_ids")):
            try:
                det_ids.append(int(str(d).lstrip("#")))
            except ValueError:
                continue
        keep_ev = [e for e in ev_ids if e in allowed_events]
        removed_events += [e for e in ev_ids if e not in allowed_events]
        keep_det = [d for d in det_ids if d in allowed_detections]
        removed_dets += [d for d in det_ids if d not in allowed_detections]
        entry = {"statement": str(item.get("statement", ""))[:2000], "event_ids": keep_ev, "detection_ids": keep_det}
        if (ev_ids or det_ids) and not (keep_ev or keep_det):
            entry["unverified"] = True
        evidence.append(entry)
    techniques = []
    for t in _as_list(data.get("techniques")):
        tid = t.get("id") if isinstance(t, dict) else str(t)
        if not tid:
            continue
        tid = str(tid).strip().upper()
        if tid in allowed_techniques:
            techniques.append({"id": tid, "reason": str(t.get("reason", "")) if isinstance(t, dict) else ""})
        else:
            removed_techs.append(tid)
    text_fields = {"summary": str(data.get("summary", ""))[:6000],
                   "inference": [str(x)[:2000] for x in _as_list(data.get("inference"))],
                   "uncertainty": [str(x)[:2000] for x in _as_list(data.get("uncertainty"))],
                   "next_steps": [str(x)[:2000] for x in _as_list(data.get("next_steps"))]}
    blob = " ".join([text_fields["summary"], *text_fields["inference"], *text_fields["next_steps"],
                     *[e["statement"] for e in evidence]])
    blob = re.sub(r"https?://\S+", " ", blob)
    for ref in set(EVENT_ID_PATTERN.findall(blob)):
        if ref.startswith("INC-"):
            if ref not in (allowed_incidents or set()):
                unverified_text.append(ref)
        elif ref not in allowed_events:
            unverified_text.append(ref)
    for ref in set(TECHNIQUE_PATTERN.findall(blob)):
        if ref not in allowed_techniques:
            unverified_text.append(ref)
    clean = {**text_fields, "evidence": evidence, "techniques": techniques}
    validation = {"removed_event_ids": sorted(set(removed_events)), "removed_detection_ids": sorted(set(removed_dets)),
                  "removed_techniques": sorted(set(removed_techs)), "unverified_references_in_text": sorted(set(unverified_text)),
                  "passed": not (removed_events or removed_dets or removed_techs or unverified_text)}
    return clean, validation


def render_markdown(ans: dict) -> str:
    parts = []
    if ans.get("summary"):
        parts.append(f"**Summary**\n\n{ans['summary']}")
    if ans.get("evidence"):
        lines = []
        for e in ans["evidence"]:
            refs = ", ".join([f"`{x}`" for x in e.get("event_ids", [])] + [f"detection #{d}" for d in e.get("detection_ids", [])])
            flag = " _(reference could not be verified and was removed)_" if e.get("unverified") else ""
            lines.append(f"- {e['statement']}" + (f" — {refs}" if refs else "") + flag)
        parts.append("**Evidence**\n\n" + "\n".join(lines))
    for key, title in (("inference", "Inference"), ("uncertainty", "Uncertainty"), ("next_steps", "Recommended next steps")):
        if ans.get(key):
            parts.append(f"**{title}**\n\n" + "\n".join(f"- {x}" for x in ans[key]))
    if ans.get("techniques"):
        parts.append("**MITRE ATT&CK techniques**\n\n" + "\n".join(
            f"- {t['id']}" + (f" — {t['reason']}" if t.get("reason") else "") for t in ans["techniques"]))
    return "\n\n".join(parts)
