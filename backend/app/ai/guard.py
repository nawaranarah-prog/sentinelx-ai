"""Prompt-injection defenses for data that flows into the language model.

- Untrusted strings (telemetry, documents, notes) are escaped so they cannot close the XML-style
  delimiters that separate them from instructions.
- Injection-like phrases inside untrusted data are detected and surfaced as findings (they are data).
Citation grounding lives in app.analysis.resolver.verify_citations.
"""

import re

INJECTION_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|messages)",
        r"disregard (all |any )?(the )?(previous|prior|above|system)",
        r"(reveal|print|show|output|leak) (me )?(your |the )?(system prompt|instructions|api[ _-]?keys?|secrets?|credentials)",
        r"you are now (a|an|in) ",
        r"new instructions?:",
        r"act as (an? )?(unrestricted|jailbroken|developer mode)",
        r"</?\s*(system|assistant|untrusted_data|trusted_context|instructions?)\s*>",
        r"do not (tell|inform) the (user|analyst)",
        r"\b(you must|assistant,|ai,|please) (now )?(delete|drop|disable|wipe|exfiltrate)\b",
    )
]


def escape_untrusted(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sanitize(obj, max_str: int = 600):
    """Recursively escape and truncate strings inside untrusted structures."""
    if isinstance(obj, str):
        s = obj if len(obj) <= max_str else obj[:max_str] + "…[truncated]"
        return escape_untrusted(s)
    if isinstance(obj, dict):
        return {str(k)[:80]: sanitize(v, max_str) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
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
                found.append({"location": path, "event_uid": owner, "excerpt": obj[start:m.end() + 40][:200]})
                break
    return found
