"""Agents run concurrently. These tests prove the properties that makes risky.

Each one targets a way parallelism silently breaks a guarantee the sequential version
had for free: that work actually overlaps, that results keep a deterministic order, that
max-usd stays a hard ceiling, and that the shared validator bridge stays in sync.
"""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import orchestrator
from prreview.security import validate as validatemod
from prreview.security.config import Caps
from prreview.security.providers.base import (BudgetExceeded, CostMeter, Response,
                                              ToolCall, Usage)
from prreview.security.tools import SubmitOutcome, ToolResult

VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "vendor", "security-audit")


class Session:
    """Accepts the first submit. One per agent, as in production."""

    def __init__(self, agent_id, caps):
        self.agent_id = agent_id
        self.caps = caps
        self.submit_tool = "submit_hunt"
        self.finished = False
        self.result = None
        self.rounds = 0

    def tools(self, strict=True):
        return [{"type": "function", "function": {"name": "submit_hunt"}}]

    def dispatch(self, call):
        self.finished = True
        self.result = {"agent": self.agent_id, "records": [], "units": []}
        return ToolResult("ok", terminal=True,
                          outcome=SubmitOutcome("accept", payload=self.result),
                          tool=call.name)

    def state(self):
        return {"agent_id": self.agent_id}


class SlowProvider:
    """Answers after a delay chosen per agent, and records peak concurrency."""

    def __init__(self, delays):
        self.delays = delays
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()

    def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
        agent = messages[1]["content"]
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.delays.get(agent, 0.05))
        with self.lock:
            self.active -= 1
        return Response(tool_calls=[ToolCall("c", "submit_hunt", {})],
                        usage=Usage(cache_miss=10, output=5), finish_reason="tool_calls")


class Parent(orchestrator.Orchestrator):
    """The real run_agents, without a repository behind it."""

    def __init__(self, provider, caps):
        self.cfg = type("Cfg", (), {"caps": caps,
                                    "models": {"hunter": "deepseek-flash"}})()
        self.provider = provider
        self.meter = CostMeter(caps.max_usd)
        self.clock = time.monotonic
        self.conversations = []
        self.notes = []


def jobs(caps, n):
    return [orchestrator.Job("hunter", i, "SYSTEM", "agent-%d" % i,
                             Session("agent-%d" % i, caps)) for i in range(n)]


class RunsInParallel(unittest.TestCase):
    def test_agents_overlap_up_to_the_cap(self):
        caps = Caps(parallel_conversations=4)
        provider = SlowProvider({})
        started = time.monotonic()
        Parent(provider, caps).run_agents(jobs(caps, 8))
        elapsed = time.monotonic() - started
        self.assertEqual(provider.peak, 4, "concurrency must reach, and not exceed, the cap")
        # Eight 50ms agents four at a time is about two rounds, not eight.
        self.assertLess(elapsed, 8 * 0.05 * 0.75)

    def test_a_cap_of_one_is_sequential(self):
        caps = Caps(parallel_conversations=1)
        provider = SlowProvider({})
        Parent(provider, caps).run_agents(jobs(caps, 4))
        self.assertEqual(provider.peak, 1)

    def test_results_keep_job_order_whatever_finishes_first(self):
        """Metadata and the report must not depend on which request came back first."""
        caps = Caps(parallel_conversations=4)
        # The first job is the slowest, so completion order is reversed.
        provider = SlowProvider({"agent-0": 0.2, "agent-1": 0.1, "agent-2": 0.05})
        parent = Parent(provider, caps)
        results = parent.run_agents(jobs(caps, 3))
        self.assertEqual([r.agent_id for r in results], ["agent-0", "agent-1", "agent-2"])
        self.assertEqual([c.agent_id for c in parent.conversations],
                         ["agent-0", "agent-1", "agent-2"])


class CeilingHoldsUnderContention(unittest.TestCase):
    def test_concurrent_reservations_never_cross_the_ceiling(self):
        """Without reservations, every thread passes the same check and all overspend."""
        meter = CostMeter(max_usd=1.0)
        admitted = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()          # all sixteen ask at the same instant
            try:
                ticket = meter.reserve("hunter", "deepseek-flash", 0, 100_000)  # $0.12 worst
                admitted.append(ticket)
            except BudgetExceeded:
                pass

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(admitted), 8, "only floor($1.00 / $0.12) = 8 fit")
        self.assertLessEqual(meter.spent + meter.reserved, 1.0 + 1e-9)

    def test_a_check_without_reservations_would_have_overspent(self):
        """The control only matters if the naive version really fails."""
        meter = CostMeter(max_usd=1.0)
        passed = 0
        for _ in range(16):
            try:
                meter.check("hunter", "deepseek-flash", 0, 100_000)   # holds nothing
                passed += 1
            except BudgetExceeded:
                pass
        self.assertEqual(passed, 16, "check() alone admits all sixteen")

    def test_settling_frees_the_unused_part_of_a_reservation(self):
        meter = CostMeter(max_usd=1.0)
        ticket = meter.reserve("hunter", "deepseek-flash", 0, 100_000)
        meter.settle(ticket, Usage(output=1_000))
        self.assertAlmostEqual(meter.reserved, 0.0)
        self.assertAlmostEqual(meter.spent, 1_000 * 1.20 / 1_000_000)

    def test_a_failed_request_gives_its_reservation_back(self):
        meter = CostMeter(max_usd=1.0)
        meter.release(meter.reserve("hunter", "deepseek-flash", 0, 100_000))
        self.assertEqual((meter.spent, meter.reserved), (0.0, 0.0))


class BridgeStaysInSync(unittest.TestCase):
    def test_concurrent_callers_do_not_read_each_others_replies(self):
        """Unlocked, one thread reads another's reply and the bridge shuts itself down."""
        validator = validatemod.Validator(vendor_dir=VENDOR)
        errors = []

        def hammer(n):
            try:
                for i in range(20):
                    refs = {"surface": "path/%d/%d" % (n, i), "boundary": "b",
                            "subsystem": "c", "attack_class": "d"}
                    cid = validator.coverage_id(refs)
                    if "path%%2F%d%%2F%d" % (n, i) not in cid:
                        errors.append("thread %d got someone else's reply: %s" % (n, cid))
            except Exception as exc:   # a desync raises ValidationBridgeError here
                errors.append("%s: %s" % (type(exc).__name__, exc))

        threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            validator.close()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
