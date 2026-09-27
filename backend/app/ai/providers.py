"""LLM provider abstraction.

LLM_PROVIDER=anthropic → official Anthropic Python SDK (Messages API with tool use).
LLM_PROVIDER=openai    → OpenAI-compatible Chat Completions endpoint (LLM_BASE_URL optional).
LLM_PROVIDER=none      → no live model; the assistant runs in LOCAL/DEMO analysis mode.
"""

import json
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import Settings, get_settings

log = logging.getLogger(__name__)
MAX_RESULT_CHARS = 24_000


class ProviderError(Exception):
    """Live AI failed; the caller falls back to local analysis and says so."""


class ProviderRefusal(ProviderError):
    pass


@dataclass
class ProviderResult:
    text: str
    model: str
    tool_rounds: int = 0
    usage: dict = field(default_factory=dict)


def _tool_result_text(result: dict) -> str:
    from app.ai.guard import wrap_untrusted

    text = wrap_untrusted("tool_result", result)
    return text if len(text) <= MAX_RESULT_CHARS else text[:MAX_RESULT_CHARS] + "\n…[tool result truncated]"


class AnthropicProvider:
    name = "anthropic"
    FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5-1")

    def __init__(self, settings: Settings):
        import anthropic

        self.anthropic = anthropic
        self.settings = settings
        self.model = settings.effective_llm_model
        self.client = anthropic.Anthropic(api_key=settings.llm_api_key, timeout=settings.llm_timeout_seconds,
                                          max_retries=1)

    def _create(self, **kwargs):
        if self.settings.llm_refusal_fallback and self.model in self.FALLBACK_MODELS:
            try:
                return self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"],
                                                        fallbacks="default", **kwargs)
            except self.anthropic.BadRequestError:
                log.warning("Server-side fallback not accepted; retrying without it")
        return self.client.messages.create(**kwargs)

    def run(self, system: str, messages: list[dict], toolbox, tool_specs: list[dict], max_rounds: int) -> ProviderResult:
        tools = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tool_specs]
        msgs = list(messages)
        deadline = time.monotonic() + self.settings.llm_timeout_seconds * 2
        rounds = 0
        try:
            while True:
                kwargs = dict(model=self.model, max_tokens=8000, system=system, messages=msgs)
                if rounds < max_rounds:
                    kwargs["tools"] = tools
                resp = self._create(**kwargs)
                if resp.stop_reason == "refusal":
                    raise ProviderRefusal("The model declined to answer this request.")
                tool_uses = [b for b in resp.content if getattr(b, "type", "") == "tool_use"]
                if resp.stop_reason == "tool_use" and tool_uses and rounds < max_rounds and time.monotonic() < deadline:
                    rounds += 1
                    msgs.append({"role": "assistant", "content": resp.content})
                    results = []
                    for tu in tool_uses:
                        out = toolbox.call(tu.name, dict(tu.input) if isinstance(tu.input, dict) else {})
                        results.append({"type": "tool_result", "tool_use_id": tu.id, "content": _tool_result_text(out),
                                        "is_error": "error" in out})
                    msgs.append({"role": "user", "content": results})
                    continue
                text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
                usage = {"input_tokens": getattr(resp.usage, "input_tokens", None),
                         "output_tokens": getattr(resp.usage, "output_tokens", None)}
                return ProviderResult(text=text, model=getattr(resp, "model", self.model), tool_rounds=rounds, usage=usage)
        except ProviderRefusal:
            raise
        except self.anthropic.APITimeoutError as exc:
            raise ProviderError("The AI provider timed out.") from exc
        except self.anthropic.AuthenticationError as exc:
            raise ProviderError("The AI provider rejected the configured API key.") from exc
        except self.anthropic.RateLimitError as exc:
            raise ProviderError("The AI provider rate limit was reached.") from exc
        except self.anthropic.APIStatusError as exc:
            raise ProviderError(f"The AI provider returned HTTP {exc.status_code}.") from exc
        except self.anthropic.APIConnectionError as exc:
            raise ProviderError("Could not connect to the AI provider.") from exc

    def probe(self) -> None:
        try:
            self.client.messages.create(model=self.model, max_tokens=64,
                                        messages=[{"role": "user", "content": "Reply with the single word OK."}])
        except self.anthropic.APIError as exc:
            raise ProviderError(f"Probe failed: {type(exc).__name__}") from exc


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = settings.effective_llm_model
        self.base = (settings.llm_base_url or "https://api.openai.com/v1").rstrip("/")
        self.headers = {"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"}

    def _post(self, payload: dict) -> dict:
        try:
            r = httpx.post(f"{self.base}/chat/completions", headers=self.headers, json=payload,
                           timeout=self.settings.llm_timeout_seconds)
        except httpx.TimeoutException as exc:
            raise ProviderError("The AI provider timed out.") from exc
        except httpx.HTTPError as exc:
            raise ProviderError("Could not connect to the AI provider.") from exc
        if r.status_code == 401:
            raise ProviderError("The AI provider rejected the configured API key.")
        if r.status_code >= 400:
            raise ProviderError(f"The AI provider returned HTTP {r.status_code}.")
        return r.json()

    def run(self, system: str, messages: list[dict], toolbox, tool_specs: list[dict], max_rounds: int) -> ProviderResult:
        tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                   "parameters": t["parameters"]}} for t in tool_specs]
        msgs = [{"role": "system", "content": system}] + [
            {"role": m["role"], "content": m["content"] if isinstance(m["content"], str) else json.dumps(m["content"])}
            for m in messages]
        rounds = 0
        while True:
            payload = {"model": self.model, "messages": msgs, "max_tokens": 4000}
            if rounds < max_rounds:
                payload["tools"] = tools
            data = self._post(payload)
            choice = data["choices"][0]
            msg = choice["message"]
            calls = msg.get("tool_calls") or []
            if calls and rounds < max_rounds:
                rounds += 1
                msgs.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
                for c in calls:
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    out = toolbox.call(c["function"]["name"], args if isinstance(args, dict) else {})
                    msgs.append({"role": "tool", "tool_call_id": c["id"], "content": _tool_result_text(out)})
                continue
            return ProviderResult(text=msg.get("content") or "", model=data.get("model", self.model),
                                  tool_rounds=rounds, usage=data.get("usage") or {})

    def probe(self) -> None:
        self._post({"model": self.model, "max_tokens": 5, "messages": [{"role": "user", "content": "Reply OK"}]})


_status = {"checked_at": None, "ok": None, "error": None}


def get_provider(settings: Settings | None = None):
    settings = settings or get_settings()
    if not settings.llm_configured:
        return None
    if settings.llm_provider == "anthropic":
        return AnthropicProvider(settings)
    if settings.llm_provider == "openai":
        return OpenAICompatibleProvider(settings)
    return None


def record_status(ok: bool, error: str | None = None) -> None:
    _status.update({"checked_at": time.time(), "ok": ok, "error": error})


def provider_status(probe: bool = False) -> dict:
    settings = get_settings()
    if not settings.llm_configured:
        return {"mode": "LOCAL", "label": "DEMO AI / LOCAL ANALYSIS", "status": "NOT CONFIGURED",
                "provider": settings.llm_provider if settings.llm_provider != "none" else None, "model": None,
                "detail": "No LLM_PROVIDER/LLM_API_KEY configured. Answers are produced by deterministic local "
                          "analysis of your data, not by a language model."}
    if probe or _status["checked_at"] is None or time.time() - _status["checked_at"] > 600:
        try:
            get_provider(settings).probe()
            record_status(True)
        except ProviderError as exc:
            record_status(False, str(exc))
    ok = _status["ok"]
    return {"mode": "LIVE" if ok else "LOCAL", "label": "LIVE AI" if ok else "LIVE AI UNAVAILABLE — LOCAL ANALYSIS",
            "status": "CONNECTED" if ok else "ERROR", "provider": settings.llm_provider,
            "model": settings.effective_llm_model, "detail": _status["error"] or "Last provider check succeeded.",
            "checked_at": _status["checked_at"]}
