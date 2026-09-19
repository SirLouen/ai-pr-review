"""Tests for the conversation loop.

The loop is driven by a scripted provider, so every branch is exercised without a
network call. The tool session is a stand-in with the same surface the real one
presents to the loop: tools(), dispatch(), state(), finished, result, caps.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import loop
from prreview.security.config import Caps
from prreview.security.providers.base import (BudgetExceeded, CostMeter, ProviderError,
                                              Response, ToolCall, Usage)
from prreview.security.tools import SubmitOutcome, ToolResult


class FakeSession:
    """Minimal stand-in for tools.ToolSession."""

    def __init__(self, script=None, caps=None):
        self.caps = caps or Caps()
        self.agent_id = "h1"
        self.submit_tool = "submit_hunt"
        self.finished = False
        self.result = None
        self.rounds = 0
        self.dispatched = []
        self.script = script or {}

    def tools(self, strict=True):
        return [{"type": "function", "function": {"name": "read_file"}},
                {"type": "function", "function": {"name": "submit_hunt"}}]

    def dispatch(self, call):
        self.dispatched.append(call.name)
        if call.name != self.submit_tool:
            return ToolResult("<<<DATA>>>file<<<END>>>", tool=call.name)
        self.rounds += 1
        action = self.script.get("submit", "accept")
        if action == "feedback" and self.rounds <= 1:
            return ToolResult("fix it", ok=False,
                              outcome=SubmitOutcome("feedback", errors=["$[0]: bad"]),
                              tool=call.name)
        if action == "discard":
            self.finished = True
            return ToolResult("discarded", ok=False, terminal=True,
                              outcome=SubmitOutcome("discard", errors=["$[0]: bad"]),
                              tool=call.name)
        self.finished = True
        self.result = {"records": [], "units": []}
        return ToolResult("accepted", terminal=True,
                          outcome=SubmitOutcome("accept", payload=self.result),
                          tool=call.name)

    def state(self):
        return {"agent_id": self.agent_id, "tool_calls": len(self.dispatched)}


class ScriptedProvider:
    """Returns queued responses; records what it was sent."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
        self.requests.append({"messages": [dict(m) for m in messages], "tools": tools})
        if not self.responses:
            raise AssertionError("provider called more times than the script allows")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def call(name, **args):
    return ToolCall("id-" + name, name, args)


def usage():
    return Usage(cache_miss=100, cache_hit=10, output=50)


def run(provider, session, **kwargs):
    return loop.run_conversation(provider, "hunter", "deepseek-flash", "SYSTEM", "USER",
                                 session, **kwargs)


class Happy(unittest.TestCase):
    def test_reads_then_submits(self):
        provider = ScriptedProvider([
            Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                     finish_reason="tool_calls"),
            Response(tool_calls=[call("submit_hunt")], usage=usage(),
                     finish_reason="tool_calls"),
        ])
        session = FakeSession()
        result = run(provider, session)
        self.assertTrue(result.ok)
        self.assertEqual(result.turns, 2)
        self.assertEqual(session.dispatched, ["read_file", "submit_hunt"])
        self.assertEqual(result.result, {"records": [], "units": []})
        self.assertEqual(result.usage.output, 100)

    def test_tool_results_are_fed_back_as_tool_messages(self):
        provider = ScriptedProvider([
            Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                     finish_reason="tool_calls"),
            Response(tool_calls=[call("submit_hunt")], usage=usage(),
                     finish_reason="tool_calls"),
        ])
        run(provider, FakeSession())
        second = provider.requests[1]["messages"]
        self.assertEqual(second[-1]["role"], "tool")
        self.assertIn("<<<DATA>>>", second[-1]["content"])
        self.assertEqual(second[-2]["role"], "assistant")

    def test_reasoning_content_is_echoed_back(self):
        """DeepSeek rejects a follow-up whose assistant turns dropped their reasoning."""
        provider = ScriptedProvider([
            Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                     finish_reason="tool_calls", opaque={"reasoning_content": "thinking"}),
            Response(tool_calls=[call("submit_hunt")], usage=usage(),
                     finish_reason="tool_calls"),
        ])
        run(provider, FakeSession())
        assistant = [m for m in provider.requests[1]["messages"] if m["role"] == "assistant"]
        self.assertEqual(assistant[0]["reasoning_content"], "thinking")

    def test_validator_feedback_round_then_success(self):
        provider = ScriptedProvider([
            Response(tool_calls=[call("submit_hunt")], usage=usage(), finish_reason="tool_calls"),
            Response(tool_calls=[call("submit_hunt")], usage=usage(), finish_reason="tool_calls"),
        ])
        session = FakeSession({"submit": "feedback"})
        result = run(provider, session)
        self.assertTrue(result.ok)
        self.assertEqual(session.rounds, 2)


class MalformedCalls(unittest.TestCase):
    def test_the_models_exact_text_is_echoed_back_in_history(self):
        """Re-serialising a failed parse would show the model a `null` it never wrote."""
        bad = ToolCall("c1", "grep", None, error="bad json", raw='{"path_glob": **}')
        message = loop._assistant_message(Response(tool_calls=[bad], finish_reason="tool_calls"))
        self.assertEqual(message["tool_calls"][0]["function"]["arguments"], '{"path_glob": **}')

    def test_a_good_call_is_still_serialised_from_its_arguments(self):
        good = ToolCall("c1", "grep", {"pattern": "x"})
        message = loop._assistant_message(Response(tool_calls=[good], finish_reason="tool_calls"))
        self.assertEqual(message["tool_calls"][0]["function"]["arguments"], '{"pattern":"x"}')

    def test_strict_tool_schemas_are_not_sent_by_default(self):
        """DeepSeek's strict mode refuses these schemas; the flag must not be relied on."""
        seen = {}

        class Session(FakeSession):
            def tools(self, strict=True):
                seen["strict"] = strict
                return super().tools(strict)

        provider = ScriptedProvider([Response(tool_calls=[call("submit_hunt")], usage=usage(),
                                              finish_reason="tool_calls")])
        run(provider, Session())
        self.assertIs(seen["strict"], False)


class TurnBudget(unittest.TestCase):
    """First real pull request: two recon agents explored to turn 30 and were discarded."""

    def explorer(self, n, then_submit=False):
        replies = [Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                            finish_reason="tool_calls") for _ in range(n)]
        if then_submit:
            replies.append(Response(tool_calls=[call("submit_hunt")], usage=usage(),
                                    finish_reason="tool_calls"))
        return ScriptedProvider(replies)

    def test_the_agent_is_told_before_its_turns_run_out(self):
        provider = self.explorer(5, then_submit=True)
        result = run(provider, FakeSession(), max_turns=6)
        self.assertTrue(result.ok, "warned in time, the agent submits instead of being cut off")
        notices = [m["content"] for r in provider.requests for m in r["messages"]
                   if m["role"] == "user" and "turns left" in m["content"]]
        self.assertTrue(notices)
        self.assertIn("submit_hunt", notices[0])

    def test_the_notice_comes_once(self):
        provider = self.explorer(8)
        run(provider, FakeSession(), max_turns=8)
        last = provider.requests[-1]["messages"]
        self.assertEqual(sum(1 for m in last if m["role"] == "user"
                             and "turns left" in m["content"]), 1)

    def test_an_agent_that_still_does_not_submit_ends_as_before(self):
        result = run(self.explorer(10), FakeSession(), max_turns=6)
        self.assertEqual(result.status, loop.NO_SUBMIT)


class Failures(unittest.TestCase):
    def test_discard_is_not_reported_as_success(self):
        """A discarded submit finishes the session but leaves no result."""
        provider = ScriptedProvider([
            Response(tool_calls=[call("submit_hunt")], usage=usage(), finish_reason="tool_calls"),
        ])
        result = run(provider, FakeSession({"submit": "discard"}))
        self.assertEqual(result.status, loop.DISCARDED)
        self.assertFalse(result.ok)
        self.assertIsNone(result.result)

    def test_provider_error_is_a_failed_run_not_an_empty_one(self):
        provider = ScriptedProvider([ProviderError("502 from upstream")])
        result = run(provider, FakeSession())
        self.assertEqual(result.status, loop.FAILED)
        self.assertFalse(result.ok)
        self.assertIn("502", result.reason)

    def test_turn_limit_ends_without_a_result(self):
        provider = ScriptedProvider([
            Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                     finish_reason="tool_calls") for _ in range(5)])
        result = run(provider, FakeSession(), max_turns=3)
        self.assertEqual(result.status, loop.NO_SUBMIT)
        self.assertEqual(result.turns, 3)

    def test_prose_without_a_tool_call_is_corrected(self):
        provider = ScriptedProvider([
            Response(text="I think the code is fine.", usage=usage(), finish_reason="stop"),
            Response(tool_calls=[call("submit_hunt")], usage=usage(), finish_reason="tool_calls"),
        ])
        result = run(provider, FakeSession())
        self.assertTrue(result.ok)
        nudge = provider.requests[1]["messages"][-1]
        self.assertEqual(nudge["role"], "user")
        self.assertIn("submit_hunt", nudge["content"])

    def test_deadline_stops_the_conversation(self):
        ticks = iter([0, 0, 10_000, 10_001, 10_002])
        provider = ScriptedProvider([
            Response(tool_calls=[call("read_file", path="a.py")], usage=usage(),
                     finish_reason="tool_calls") for _ in range(3)])
        result = run(provider, FakeSession(), clock=lambda: next(ticks))
        self.assertEqual(result.status, loop.DEADLINE)

    def test_budget_stops_before_the_call_is_made(self):
        provider = ScriptedProvider([])          # any call would raise
        meter = CostMeter(max_usd=0.0001)
        result = run(provider, FakeSession(), meter=meter)
        self.assertEqual(result.status, loop.BUDGET)
        self.assertEqual(provider.requests, [])

    def test_spend_is_charged_to_the_meter(self):
        provider = ScriptedProvider([
            Response(tool_calls=[call("submit_hunt")], usage=Usage(cache_miss=1_000_000),
                     finish_reason="tool_calls"),
        ])
        meter = CostMeter(max_usd=5.0)
        run(provider, FakeSession(), meter=meter)
        self.assertGreater(meter.spent, 0.0)
        self.assertIn("hunter", meter.by_role)


class ContextCeiling(unittest.TestCase):
    def test_oversized_history_asks_the_agent_to_finalize(self):
        """History is never truncated: the cited-line evidence would go with it."""
        caps = Caps(context_fraction=0.000001)   # forces the ceiling immediately
        provider = ScriptedProvider([
            Response(tool_calls=[call("submit_hunt")], usage=usage(), finish_reason="tool_calls"),
        ])
        session = FakeSession(caps=caps)
        result = run(provider, session, caps=caps)
        self.assertTrue(result.ok)
        first = provider.requests[0]["messages"]
        self.assertIn("BUDGET_EXHAUSTED", first[-1]["content"])
        self.assertEqual(first[0]["content"], "SYSTEM", "history must not be dropped")


if __name__ == "__main__":
    unittest.main()


class ReasoningLevel(unittest.TestCase):
    class Recording(ScriptedProvider):
        def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
            self.extras = getattr(self, "extras", []) + [extra]
            return super().complete(role, model, messages, tools, max_tokens, extra)

    def submit(self):
        return self.Recording([Response(tool_calls=[call("submit_hunt")], usage=usage(),
                                         finish_reason="tool_calls")])

    def test_a_level_reaches_the_provider(self):
        provider = self.submit()
        run(provider, FakeSession(), reasoning="off")
        self.assertEqual(provider.extras, [{"reasoning": "off"}])

    def test_no_level_sends_no_extra_at_all(self):
        """A run with no level must send exactly what it always did."""
        provider = self.submit()
        run(provider, FakeSession())
        self.assertEqual(provider.extras, [None])
