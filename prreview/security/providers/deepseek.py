"""DeepSeek provider over the OpenAI-compatible endpoint, with tool calling.

Two behaviours drive the shape of this module:

* Thinking mode returns `reasoning_content` alongside the answer, and in a tool
  loop the assistant turns must be echoed back with that field intact or the API
  rejects the follow-up. So the reasoning text is carried in Response.opaque and
  replayed by the caller rather than dropped.
* A transient failure can arrive as prose inside a 200 OK. Anything that is not a
  well-formed choice is raised as ProviderError, because the caller must treat a
  failed call as a failed run, never as "the model found nothing".
"""
import json
import re
import time
import urllib.error
import urllib.request

from .base import ProviderError, Response, ToolCall, Usage

ALLOWED_BASE_URLS = ("https://api.deepseek.com",)
RETRY_STATUS = (408, 409, 429, 500, 502, 503, 504)
MAX_ATTEMPTS = 4


class DeepSeekProvider:
    def __init__(self, api_key, base_url="https://api.deepseek.com", timeout=300,
                 allow_custom_base_url=False, reasoning_effort=None):
        if not api_key:
            raise ProviderError("DeepSeek API key is empty")
        base = base_url.rstrip("/")
        if base not in ALLOWED_BASE_URLS and not allow_custom_base_url:
            raise ProviderError(
                "base URL %r is not allowlisted; a redirected endpoint would receive the "
                "API key and the source under review" % base)
        self.api_key = api_key
        self.base_url = base
        self.timeout = timeout
        self.reasoning_effort = reasoning_effort

    def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
        body = {"model": model, "messages": messages, "max_tokens": max_tokens,
                "temperature": 0.0, "stream": False}
        if tools:
            body["tools"] = tools
            # Parallel calls would interleave reads in the read log, which the
            # verifier's "did it actually re-read this line" check depends on.
            body["parallel_tool_calls"] = False
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        extra = dict(extra or {})
        body.update(reasoning_params(extra.pop("reasoning", None)))
        for key, value in extra.items():
            body[key] = value

        data = self._post("/chat/completions", body)
        return _to_response(data, model)

    def warm(self, role, model, messages, tools=None, extra=None):
        """Prefill one prompt so agents that share its prefix find the cache warm.

        DeepSeek caches a prompt only once a request for it has been processed, so agents
        launched together all miss it (M1 spike, second run: the first six verifiers 0%
        cached, the next four 98%). One request with max_tokens=1 fills the cache before
        the wave starts. Its answer is meaningless and ignored; only the usage matters.
        """
        body = {"model": model, "messages": messages, "max_tokens": 1,
                "temperature": 0.0, "stream": False}
        if tools:
            body["tools"] = tools
        # The same reasoning mode as the wave it warms, or the cached prefix may not match.
        body.update(reasoning_params((extra or {}).get("reasoning")))
        return _usage(self._post("/chat/completions", body))

    def _post(self, path, body):
        payload = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key,
                     "User-Agent": "ai-pr-review-security"})
        last = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", "replace")
                return _parse_json(raw)
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", "replace")[:400]
                last = ProviderError("HTTP %s from DeepSeek: %s" % (error.code, detail))
                if error.code not in RETRY_STATUS:
                    raise last
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last = ProviderError("network failure calling DeepSeek: %r" % (error,))
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(min(2 ** attempt, 8))
        raise last or ProviderError("DeepSeek call failed with no diagnostic")


def _parse_arguments(raw):
    """(arguments, error). strict=False admits a literal newline or tab inside a string,
    which models write in long free-text fields (M1 spike, third run); the value is the
    same string the escaped form would give. Only if that fails is a bare wildcard read
    as null -- never on arguments that parse as they are, where the same characters could
    sit inside a quoted string value."""
    try:
        arguments = json.loads(raw, strict=False)
    except ValueError as exc:
        first = exc
        try:
            arguments = json.loads(_bare_wildcards_as_null(raw), strict=False)
        except ValueError:
            return None, "arguments were not valid JSON (%s)" % first.msg
    if not isinstance(arguments, dict):
        return None, "arguments were not a JSON object"
    return arguments, ""


BARE_WILDCARD_RE = re.compile(r'(:\s*)\*{1,2}(\s*[,}])')


def _bare_wildcards_as_null(raw):
    """Read an unquoted `*` or `**` argument value as null.

    Models write "search every file" as a bare `"path_glob": *` or `**` -- three times
    across the M1 spike runs, each costing a feedback round. A bare wildcard is never
    valid JSON, and for an optional filter it can only mean "no filter", which is what
    null means, so the reading is lossless. Anything else malformed still fails.
    """
    return BARE_WILDCARD_RE.sub(r"\1null\2", raw)


def reasoning_params(level):
    """DeepSeek's request parameters for a provider-neutral reasoning level.

    `off` is `thinking: disabled`, which the general PR-Agent review in this repository
    already sends in production. The M1 spike's reasoning probe measured it at 0 reasoning
    tokens against 878 by default, with the answer still correct. The effort levels go out
    as `reasoning_effort`; the probe found them accepted but with no ordered effect (low 584,
    medium 541, high 490), so they are most likely ignored. None sends nothing at all.
    """
    if not level:
        return {}
    if level == "off":
        return {"thinking": {"type": "disabled"}}
    if level in ("low", "medium", "high"):
        return {"reasoning_effort": level}
    raise ProviderError("unknown reasoning level %r" % (level,))


def _usage(data):
    raw = (data or {}).get("usage") or {}
    details = raw.get("completion_tokens_details") or {}
    hit = raw.get("prompt_cache_hit_tokens", 0)
    miss = raw.get("prompt_cache_miss_tokens")
    if miss is None:
        miss = max(0, raw.get("prompt_tokens", 0) - hit)
    return Usage(cache_miss=miss, cache_hit=hit, output=raw.get("completion_tokens", 0),
                 reasoning=details.get("reasoning_tokens", 0))


def _parse_json(raw):
    try:
        return json.loads(raw)
    except ValueError:
        raise ProviderError("non-JSON body from DeepSeek: %s" % raw[:300])


def _to_response(data, model):
    if not isinstance(data, dict) or data.get("error"):
        raise ProviderError("error payload from DeepSeek: %s" % str(data)[:300])
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("no choices in DeepSeek response: %s" % str(data)[:300])
    message = choices[0].get("message") or {}
    finish = choices[0].get("finish_reason", "")

    tool_calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        name = function.get("name", "")
        raw_args = function.get("arguments") or "{}"
        arguments, error = _parse_arguments(raw_args)
        if error:
            # The API call itself succeeded; the model wrote a malformed call. That is the
            # tool surface's to answer, so the model can resend it.
            tool_calls.append(ToolCall(call.get("id") or "", name, None, error=error,
                                       raw=str(raw_args)))
            continue
        tool_calls.append(ToolCall(call.get("id") or "", name, arguments))

    usage = _usage(data)

    text = (message.get("content") or "").strip()
    reasoning = message.get("reasoning_content") or ""
    if not text and not tool_calls and finish != "tool_calls":
        # JSON mode is documented to occasionally return empty content; an empty
        # answer is a failed call, not an agent that had nothing to say.
        raise ProviderError("empty completion from DeepSeek (finish_reason=%s)" % finish)
    return Response(text=text, tool_calls=tool_calls, usage=usage, model=model,
                    finish_reason=finish,
                    opaque={"reasoning_content": reasoning} if reasoning else {})
