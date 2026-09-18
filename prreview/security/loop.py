"""The tool loop: one model conversation, driven to a validated result or a named failure.

One call to `run_conversation` is one skill agent. The loop owns the turn budget, the
wall clock, the context ceiling and the spend check; the tool session owns what the model
may read and whether a submitted record is acceptable. Nothing here inspects the content
of a record -- that belongs to tools.gate_record and the vendored validators.

Two rules shape the error handling:

* A failed call is a failed conversation, never an empty result. Cloudflare's harness
  notes that transient provider errors can arrive as prose inside a 200 OK, and a run
  that reads "no output" as "no findings" reports a clean bill it never earned.
* The parent never edits a record. When a submit fails validation the exact validator
  messages go back to the same conversation, at most MAX_FEEDBACK_ROUNDS times, and then
  the candidate is discarded for a fresh agent (VALIDATION-AND-REPORTING.md:89).
"""
import time

from . import tools as toolsmod
from .providers.base import BudgetExceeded, ProviderError, Usage, estimate_tokens

# Statuses a conversation can end with. Only "ok" carries a usable result.
OK = "ok"
NO_SUBMIT = "no_submit"
DISCARDED = "discarded"
BUDGET = "budget_exhausted"
DEADLINE = "deadline"
FAILED = "provider_failed"

FINALIZE_TURNS = 2          # turns reserved so an agent can still submit after a warning
CONTEXT_HEADROOM = 0.90     # of the model's per-conversation context cap


class ConversationResult:
    """What the orchestrator gets back from one agent."""

    __slots__ = ("role", "agent_id", "status", "reason", "result", "usage", "turns",
                 "seconds", "state", "messages")

    def __init__(self, role, agent_id, status, reason="", result=None, usage=None,
                 turns=0, seconds=0.0, state=None, messages=None):
        self.role = role
        self.agent_id = agent_id
        self.status = status
        self.reason = reason
        self.result = result
        self.usage = usage or Usage()
        self.turns = turns
        self.seconds = seconds
        self.state = state or {}
        self.messages = messages or []

    @property
    def ok(self):
        return self.status == OK

    def as_dict(self):
        return {"role": self.role, "agent_id": self.agent_id, "status": self.status,
                "reason": self.reason, "turns": self.turns,
                "seconds": round(self.seconds, 1), "usage": self.usage.as_dict(),
                "state": self.state}


def run_conversation(provider, role, model, system, user, session, meter=None, caps=None,
                     max_turns=None, clock=time.monotonic, strict_tools=True):
    """Drive one agent from its first message to a validated submit.

    `session` is a tools.ToolSession already bound to this agent's identity, read log and
    fingerprint allowlists. The loop never touches the repository itself.
    """
    caps = caps or session.caps
    max_turns = max_turns or caps.max_turns.get(role, 20)
    context_cap = int(caps.context_tokens(model) * CONTEXT_HEADROOM)
    catalogue = session.tools(strict=strict_tools)
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
    started = clock()
    deadline = started + caps.conversation_deadline_s
    total = Usage()
    turns = 0
    warned = False

    def done(status, reason=""):
        return ConversationResult(role, session.agent_id, status, reason,
                                  result=session.result, usage=total, turns=turns,
                                  seconds=clock() - started, state=session.state(),
                                  messages=messages)

    while True:
        if turns >= max_turns:
            return done(NO_SUBMIT, "reached the %d-turn limit without submitting" % max_turns)
        if clock() > deadline:
            return done(DEADLINE, "exceeded the %ds conversation deadline"
                        % caps.conversation_deadline_s)

        projected = estimate_tokens(messages, catalogue)
        if projected > context_cap and not warned:
            # Truncating history would drop the read evidence a verifier's citations are
            # checked against, so the agent is asked to finish with what it has instead.
            warned = True
            max_turns = min(max_turns, turns + FINALIZE_TURNS)
            messages.append({"role": "user", "content": toolsmod.FINALIZE_NOTICE})
            continue

        if meter is not None:
            try:
                meter.check(role, model, projected, _output_cap(caps, model))
            except BudgetExceeded as error:
                return done(BUDGET, str(error))

        try:
            response = provider.complete(role, model, messages, catalogue,
                                         max_tokens=_output_cap(caps, model))
        except ProviderError as error:
            return done(FAILED, str(error))
        turns += 1
        total = total.add(response.usage)
        if meter is not None:
            meter.charge(role, model, response.usage)
        messages.append(_assistant_message(response))

        if not response.tool_calls:
            # Prose instead of a tool call: say so once and let the turn budget end it.
            messages.append({"role": "user", "content": _no_tool_call_notice(session)})
            continue

        for call in response.tool_calls:
            outcome = session.dispatch(call)
            messages.append({"role": "tool", "tool_call_id": getattr(call, "id", "") or "",
                             "content": outcome.text})
            if outcome.terminal:
                # A discard also marks the session finished, so the action decides:
                # only "accept" leaves a result behind.
                action = getattr(outcome.outcome, "action", "accept")
                if action == "discard":
                    return done(DISCARDED, "submitted result failed validation %d times; "
                                           "a fresh agent must re-run this work"
                                % session.rounds)
                return done(OK)


def _assistant_message(response):
    """Rebuild the assistant turn the provider must see again next request.

    DeepSeek's thinking mode rejects a follow-up whose earlier assistant turns dropped
    their `reasoning_content`, so it is echoed back rather than discarded.
    """
    message = {"role": "assistant", "content": response.text or ""}
    reasoning = (response.opaque or {}).get("reasoning_content")
    if reasoning:
        message["reasoning_content"] = reasoning
    if response.tool_calls:
        message["tool_calls"] = [
            {"id": call.id, "type": "function",
             "function": {"name": call.name, "arguments": _json(call.arguments)}}
            for call in response.tool_calls]
    return message


def _no_tool_call_notice(session):
    return ("Answer only through tool calls. Use the read tools to gather evidence, then "
            "call %s exactly once with the complete result. Prose outside a tool call is "
            "not read by the parent." % session.submit_tool)


def _output_cap(caps, model):
    """Output ceiling per request.

    Generous because reasoning tokens are billed and counted here, and a truncated
    submit is a wasted conversation.
    """
    return min(16_000, max(4_000, caps.context_tokens(model) // 8))


def _json(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
