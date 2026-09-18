"""Record/replay provider: runs the whole pipeline in tests at zero API cost.

Every request is keyed by its fingerprint (model + messages + tools). In record
mode the wrapped provider answers and the exchange is written to a cassette; in
replay mode the cassette answers and any request that is not in it is an error
rather than a live call, so a test can never silently start spending money.

This exists from the first milestone rather than as a testing afterthought: the
prompts are large and are assembled from vendored skill text, and without replay
every refactor would cost real tokens to regression-test.
"""
import json
import os

from .base import ProviderError, Response, Usage, request_fingerprint


class ReplayProvider:
    """Answers from a cassette directory of <fingerprint>.json files."""

    def __init__(self, cassette_dir, inner=None, mode="replay"):
        if mode not in ("replay", "record", "auto"):
            raise ValueError("mode must be replay, record or auto")
        self.cassette_dir = cassette_dir
        self.inner = inner
        self.mode = mode
        self.hits = 0
        self.misses = 0
        os.makedirs(cassette_dir, exist_ok=True)

    def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
        key = request_fingerprint(model, messages, tools, extra)
        path = os.path.join(self.cassette_dir, key + ".json")
        if self.mode in ("replay", "auto") and os.path.exists(path):
            self.hits += 1
            return _load(path)
        self.misses += 1
        if self.mode == "replay":
            raise ProviderError(
                "no cassette for %s call to %s (key %s). The prompt changed: re-record "
                "with SA_CASSETTE_MODE=record, or fix the caller." % (role, model, key[:12]))
        if self.inner is None:
            raise ProviderError("record mode needs a live provider to wrap")
        response = self.inner.complete(role, model, messages, tools, max_tokens, extra)
        _save(path, response, role, model)
        return response


def _load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    usage = Usage(**data.get("usage", {}))
    calls = [_ToolCall(c["id"], c["name"], c["arguments"]) for c in data.get("tool_calls", [])]
    return Response(text=data.get("text", ""), tool_calls=calls, usage=usage,
                    model=data.get("model", ""), finish_reason=data.get("finish_reason", ""),
                    opaque=data.get("opaque") or {})


def _save(path, response, role, model):
    payload = {
        "role": role,
        "model": model or response.model,
        "text": response.text,
        "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments}
                       for c in response.tool_calls],
        "usage": response.usage.as_dict(),
        "finish_reason": response.finish_reason,
        "opaque": response.opaque,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


class _ToolCall:
    __slots__ = ("id", "name", "arguments")

    def __init__(self, id, name, arguments):
        self.id = id
        self.name = name
        self.arguments = arguments
