"""Provider-neutral conversation types, usage accounting and the spend meter.

A provider turns a list of messages plus a tool catalogue into one Response. The
orchestrator never sees provider wire formats, so a role can move between
DeepSeek and Claude by changing one model name.
"""
import hashlib
import json

from .. import config


class ProviderError(Exception):
    """A call failed in a way the caller must treat as a failure, never as 'no findings'."""


class BudgetExceeded(Exception):
    """The run's USD ceiling would be crossed by this call."""


class ToolCall:
    __slots__ = ("id", "name", "arguments", "error", "raw")

    def __init__(self, id, name, arguments, error="", raw=None):
        self.id = id
        self.name = name
        self.arguments = arguments      # already-parsed dict, or None when `error` is set
        # A call whose arguments did not parse is still a call: the model is told what
        # was wrong and resends it. Failing the conversation instead cost a verifier in
        # the M1 spike over one unquoted glob (`"path_glob": **`).
        self.error = error
        self.raw = raw                  # the exact argument text, echoed back in history

    def __repr__(self):
        return "ToolCall(%s, %s)" % (self.name, sorted(self.arguments))


class Usage:
    __slots__ = ("cache_miss", "cache_hit", "output", "reasoning")

    def __init__(self, cache_miss=0, cache_hit=0, output=0, reasoning=0):
        self.cache_miss = cache_miss
        self.cache_hit = cache_hit
        # DeepSeek bills reasoning tokens as output and requires them to be sent
        # back on every later turn of a tool loop, so they are counted, not ignored.
        self.output = output
        self.reasoning = reasoning

    def add(self, other):
        return Usage(self.cache_miss + other.cache_miss, self.cache_hit + other.cache_hit,
                     self.output + other.output, self.reasoning + other.reasoning)

    def as_dict(self):
        return {"cache_miss": self.cache_miss, "cache_hit": self.cache_hit,
                "output": self.output, "reasoning": self.reasoning}


class Response:
    __slots__ = ("text", "tool_calls", "usage", "model", "finish_reason", "opaque")

    def __init__(self, text="", tool_calls=(), usage=None, model="", finish_reason="",
                 opaque=None):
        self.text = text
        self.tool_calls = list(tool_calls)
        self.usage = usage or Usage()
        self.model = model
        self.finish_reason = finish_reason
        # Provider-specific fields that must be echoed back verbatim on the next
        # turn (DeepSeek's reasoning_content, Anthropic's thinking blocks).
        self.opaque = opaque or {}


class CostMeter:
    """Tracks spend and refuses the call that would cross the ceiling.

    Checked before each request using a projection from the assembled body, not
    only after a response, because one conversation can otherwise exceed the whole
    run's cap on its own.
    """

    def __init__(self, max_usd):
        self.max_usd = max_usd
        self.spent = 0.0
        self.by_role = {}

    def price(self, model):
        return config.PRICES.get(model)

    def charge(self, role, model, usage):
        price = self.price(model)
        if price is None:
            return 0.0
        cost = price.usd(usage.cache_miss, usage.cache_hit, usage.output + usage.reasoning)
        self.spent += cost
        self.by_role[role] = self.by_role.get(role, 0.0) + cost
        return cost

    def check(self, role, model, projected_input_tokens, max_output_tokens):
        """Raise before sending if the worst case for this call crosses the cap."""
        price = self.price(model)
        if price is None:
            return
        worst = price.usd(projected_input_tokens, 0, max_output_tokens)
        if self.spent + worst > self.max_usd:
            raise BudgetExceeded(
                "%s call would reach $%.2f of the $%.2f ceiling (spent $%.2f)"
                % (role, self.spent + worst, self.max_usd, self.spent))

    def remaining(self):
        return max(0.0, self.max_usd - self.spent)


def request_fingerprint(model, messages, tools, extra=None):
    """Stable hash of a request, used as the record/replay cache key.

    Includes everything that can change the response, so an edited prompt misses
    the cache instead of silently replaying a stale answer.
    """
    payload = {"model": model, "messages": messages, "tools": tools, "extra": extra or {}}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def estimate_tokens(messages, tools=None):
    """Cheap upper-ish estimate for pre-flight budgeting.

    Source and JSON tokenize denser than prose, so bytes/3.5 is used rather than
    the bytes/4 rule of thumb.
    """
    blob = json.dumps({"m": messages, "t": tools or []}, default=str)
    return int(len(blob) / 3.5)
