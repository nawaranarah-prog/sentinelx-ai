"""LLM provider abstraction.

Providers speak a neutral message format so the agent loop is provider-agnostic:
  {"role": "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "args"}], "raw": <provider content>}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}

Resolution (LLM_PROVIDER=auto, the default):
  1. Vercel AI Gateway when AI_GATEWAY_API_KEY is set or a Vercel OIDC token is available (Vercel deployments).
  2. Anthropic when LLM_API_KEY is an Anthropic key; otherwise an OpenAI-compatible endpoint.
  3. No provider: the assistant says so and runs SentinelX's rule-based analysis instead.
"""

import contextvars
import json
import logging
import os
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import Settings, get_settings

log = logging.getLogger(__name__)
GATEWAY_BASE = "https://ai-gateway.vercel.sh"
DEFAULT_MODELS = {"gateway": "anthropic/claude-opus-5", "anthropic": "claude-opus-5", "openai": "gpt-4o-mini"}
request_oidc_token: contextvars.ContextVar[str | None] = contextvars.ContextVar("vercel_oidc_token", default=None)


class ProviderError(Exception):
    """A live model call failed. `category` is safe to show; `detail` is for administrators only."""

    def __init__(self, category: str, detail: str = ""):
        super().__init__(category)
        self.category = category
        self.detail = detail


@dataclass
class StepResult:
    text: str
    tool_calls: list[dict] = field(default_factory=list)
    raw: object = None
    stop_reason: str = ""
    model: str = ""
    usage: dict = field(default_factory=dict)


@dataclass
class ProviderConfig:
    name: str
    model: str
    api_key: str
    base_url: str | None
    use_bearer: bool = False


def resolve_config(settings: Settings | None = None) -> ProviderConfig | None:
    s = settings or get_settings()
    choice = s.llm_provider
    if choice == "none":
        return None
    gateway_token = os.environ.get("AI_GATEWAY_API_KEY") or os.environ.get("VERCEL_OIDC_TOKEN") or request_oidc_token.get()
    if choice == "gateway" or (choice == "auto" and not s.llm_api_key and gateway_token):
        if not gateway_token:
            return None
        return ProviderConfig("gateway", s.llm_model or DEFAULT_MODELS["gateway"], gateway_token,
                              s.llm_base_url or GATEWAY_BASE, use_bearer=True)
    if not s.llm_api_key:
        return None
    if choice == "anthropic" or (choice == "auto" and s.llm_api_key.startswith("sk-ant-")):
        return ProviderConfig("anthropic", s.llm_model or DEFAULT_MODELS["anthropic"], s.llm_api_key, s.llm_base_url or None)
    return ProviderConfig("openai", s.llm_model or DEFAULT_MODELS["openai"], s.llm_api_key,
                          (s.llm_base_url or "https://api.openai.com/v1").rstrip("/"))


class AnthropicProvider:
    """Official Anthropic SDK; also used for the Vercel AI Gateway (Anthropic-compatible endpoint)."""

    FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5-1")

    def __init__(self, cfg: ProviderConfig, timeout: float):
        import anthropic

        self.anthropic = anthropic
        self.cfg = cfg
        kwargs = {"timeout": timeout, "max_retries": 1}
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url
        if cfg.use_bearer:
            kwargs["auth_token"] = cfg.api_key
        else:
            kwargs["api_key"] = cfg.api_key
        self.client = anthropic.Anthropic(**kwargs)

    @staticmethod
    def _messages(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                if m.get("raw") is not None:
                    out.append({"role": "assistant", "content": m["raw"]})
                else:
                    blocks = [{"type": "text", "text": m["content"]}] if m.get("content") else []
                    blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]}
                               for c in m.get("tool_calls") or []]
                    out.append({"role": "assistant", "content": blocks or m.get("content", "")})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"],
                         "is_error": bool(m.get("is_error"))}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def step(self, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 8000) -> StepResult:
        a = self.anthropic
        kwargs = dict(model=self.cfg.model, max_tokens=max_tokens, system=system, messages=self._messages(messages))
        if tools:
            kwargs["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
                               for t in tools]
        try:
            resp = None
            if self.cfg.name == "anthropic" and get_settings().llm_refusal_fallback and self.cfg.model in self.FALLBACK_MODELS:
                try:
                    resp = self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default",
                                                            **kwargs)
                except a.BadRequestError:
                    resp = None
            if resp is None:
                resp = self.client.messages.create(**kwargs)
        except a.APITimeoutError as exc:
            raise ProviderError("timeout", str(exc)) from exc
        except a.AuthenticationError as exc:
            raise ProviderError("authentication", str(exc)) from exc
        except a.PermissionDeniedError as exc:
            raise ProviderError("permission_denied", str(exc)[:500]) from exc
        except a.RateLimitError as exc:
            raise ProviderError("rate_limited", str(exc)) from exc
        except a.APIStatusError as exc:
            raise ProviderError(f"http_{exc.status_code}", str(exc)[:500]) from exc
        except a.APIConnectionError as exc:
            raise ProviderError("connection", str(exc)) from exc
        if resp.stop_reason == "refusal":
            raise ProviderError("refusal", str(getattr(resp, "stop_details", "")))
        text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
        calls = [{"id": b.id, "name": b.name, "args": dict(b.input) if isinstance(b.input, dict) else {}}
                 for b in resp.content if getattr(b, "type", "") == "tool_use"]
        usage = {"input_tokens": getattr(resp.usage, "input_tokens", None),
                 "output_tokens": getattr(resp.usage, "output_tokens", None)}
        return StepResult(text=text, tool_calls=calls, raw=resp.content, stop_reason=resp.stop_reason or "",
                          model=getattr(resp, "model", self.cfg.model), usage=usage)

    def probe(self) -> None:
        self.step("Reply with the single word OK.", [{"role": "user", "content": "OK?"}], [], max_tokens=64)


class OpenAICompatibleProvider:
    def __init__(self, cfg: ProviderConfig, timeout: float):
        self.cfg = cfg
        self.timeout = timeout

    @staticmethod
    def _messages(system: str, messages: list[dict]) -> list[dict]:
        out = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant":
                entry = {"role": "assistant", "content": m.get("content") or ""}
                if m.get("tool_calls"):
                    entry["tool_calls"] = [{"id": c["id"], "type": "function",
                                            "function": {"name": c["name"], "arguments": json.dumps(c["args"])}}
                                           for c in m["tool_calls"]]
                out.append(entry)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                out.append({"role": "user", "content": m["content"]})
        return out

    def step(self, system: str, messages: list[dict], tools: list[dict], max_tokens: int = 4000) -> StepResult:
        payload = {"model": self.cfg.model, "messages": self._messages(system, messages), "max_tokens": max_tokens}
        if tools:
            payload["tools"] = [{"type": "function", "function": t} for t in tools]
        try:
            r = httpx.post(f"{self.cfg.base_url}/chat/completions", json=payload, timeout=self.timeout,
                           headers={"Authorization": f"Bearer {self.cfg.api_key}"})
        except httpx.TimeoutException as exc:
            raise ProviderError("timeout", str(exc)) from exc
        except httpx.HTTPError as exc:
            raise ProviderError("connection", str(exc)) from exc
        if r.status_code >= 400:
            cat = {401: "authentication", 403: "permission_denied", 429: "rate_limited"}.get(r.status_code, f"http_{r.status_code}")
            raise ProviderError(cat, r.text[:500])
        data = r.json()
        msg = data["choices"][0]["message"]
        calls = []
        for c in msg.get("tool_calls") or []:
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append({"id": c["id"], "name": c["function"]["name"], "args": args if isinstance(args, dict) else {}})
        return StepResult(text=msg.get("content") or "", tool_calls=calls, stop_reason=data["choices"][0].get("finish_reason", ""),
                          model=data.get("model", self.cfg.model), usage=data.get("usage") or {})

    def probe(self) -> None:
        self.step("Reply OK.", [{"role": "user", "content": "OK?"}], [], max_tokens=8)


def get_provider(settings: Settings | None = None):
    s = settings or get_settings()
    cfg = resolve_config(s)
    if cfg is None:
        return None
    if cfg.name in ("gateway", "anthropic"):
        return AnthropicProvider(cfg, s.llm_timeout_seconds)
    return OpenAICompatibleProvider(cfg, s.llm_timeout_seconds)


_status = {"checked_at": None, "ok": None, "category": None, "detail": None}

FRIENDLY = {
    "permission_denied": "The AI provider refused the request (for Vercel AI Gateway this usually means billing "
                         "has not been enabled for the team).",
    "authentication": "The AI provider rejected the configured credentials.",
    "rate_limited": "The AI provider rate limit was reached.",
    "timeout": "The AI provider did not respond in time.",
    "connection": "The AI provider could not be reached.",
    "refusal": "The model declined this request.",
}


def friendly(category: str | None) -> str:
    if not category:
        return ""
    return FRIENDLY.get(category, f"The AI provider returned an error ({category}).")


def record_status(ok: bool, category: str | None = None, detail: str | None = None) -> None:
    _status.update({"checked_at": time.time(), "ok": ok, "category": category, "detail": detail})


def provider_status(probe: bool = False) -> dict:
    s = get_settings()
    cfg = resolve_config(s)
    if cfg is None:
        return {"mode": "LOCAL", "status": "NOT CONFIGURED", "provider": None, "model": None,
                "label": "No language model connected",
                "detail": "Set LLM_PROVIDER/LLM_API_KEY, or enable Vercel AI Gateway for this project. Until then "
                          "the assistant runs SentinelX's rule-based analysis and labels its answers accordingly."}
    if probe or _status["checked_at"] is None or time.time() - _status["checked_at"] > 600:
        try:
            get_provider(s).probe()
            record_status(True)
        except ProviderError as exc:
            record_status(False, exc.category, exc.detail)
    ok = bool(_status["ok"])
    return {"mode": "LIVE" if ok else "LOCAL", "status": "CONNECTED" if ok else "ERROR", "provider": cfg.name,
            "model": cfg.model, "label": f"{cfg.model} via {cfg.name}" if ok else "Language model unavailable",
            "detail": "Last provider check succeeded." if ok else friendly(_status["category"]),
            "checked_at": _status["checked_at"]}
