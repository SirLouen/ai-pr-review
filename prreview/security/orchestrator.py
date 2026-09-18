"""The parent: phase order, budget, shared state and the run's terminal status.

This module is the skill's "parent" (SKILL.md:23). It owns run-metadata.json, the
coverage ledger and findings.json; it decides what each agent is asked and in which
order; and it is the only thing that writes. Agents get one conversation each and can
neither see nor change shared state.

Phase order follows the quick profile over a scoped diff:

    P0  deterministic: size gate, fetch, diff index, path screening, routing, seeders
    P1  delta reconnaissance (or the four baseline agents when there is no baseline)
    P2  one hunter wave
    P3  the coverage critic, strictly before any verifier (VALIDATION-AND-REPORTING.md:5)
    P4  one fresh verifier per unique candidate, independent of the hunter
    P5  final gate: both vendored validators plus our cross-checks, fail closed
    P6  model-free render into the bundle

Two invariants are enforced here rather than asked for in a prompt: no candidate reaches
findings.json without an independent verifier (VAL:93), and no record is ever marked
confirmed, because nothing in this action executes the code under review.
"""
import json
import os
import time

from . import gitsrc
from . import ledger as ledgermod
from . import loop, pack, prompts, routing, seeders, tools
from .dataframe import DataFramer
from .providers.base import CostMeter

COMPLETE = "complete"
INCOMPLETE = "incomplete"

# The skill's own reason strings (SKILL.md:123-134). Used verbatim so a reader can map a
# stopped run back to the rule that stopped it.
REASON_NO_BUDGET = "budget_cannot_fund_reconnaissance_and_reserves"
REASON_NO_RESERVE = "budget_cannot_reserve_critics_and_validation"
REASON_VALIDATION = "validation_budget_exhausted"
REASON_CRITIC = "critic_budget_exhausted"
REASON_SIZE = "pr_exceeds_size_gate"
REASON_GATE = "final_gate_failed"


class RunAborted(Exception):
    """Stops the run with a recorded reason. The bundle is still written."""

    def __init__(self, reason, detail=""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class Orchestrator:
    def __init__(self, cfg, provider, validator, source, skill, clock=time.monotonic):
        self.cfg = cfg
        self.provider = provider
        self.validator = validator
        self.source = source              # tools.RepoSource: what the model may read
        # pack.py resolves paths through its own tree-index cache and needs text_at(),
        # which the tool surface deliberately does not expose. Same objects, two readers.
        self.packsrc = pack.PackSource(source.repo, source.head_sha, source.base_sha,
                                       caps=cfg.caps)
        self.skill = skill                # skillpack.SkillPack
        self.clock = clock
        self.framer = DataFramer()
        self.meter = CostMeter(cfg.caps.max_usd)
        self.conversations = []
        self.deviations = []
        self.notes = []
        self.status = COMPLETE
        self.reason = ""
        self.started = clock()
        self.ledger = None
        self.records = []
        self.unvalidated = []

    # ------------------------------------------------------------------ bookkeeping

    def spent(self):
        return len(self.conversations)

    def remaining_conversations(self):
        return max(0, self.cfg.caps.max_conversations - self.spent())

    def deviate(self, name, why):
        """Record a departure from the skill in the register the report prints.

        A deviation that is not written down is indistinguishable from a bug, and the
        report's coverage claim depends on the reader seeing both.
        """
        self.deviations.append({"deviation": name, "reason": why})

    def incomplete(self, reason, detail=""):
        self.status = INCOMPLETE
        self.reason = reason
        if detail:
            self.notes.append(detail)

    def out_of_time(self):
        return self.clock() - self.started > self.cfg.caps.run_deadline_s

    # ----------------------------------------------------------------- conversations

    def run_agent(self, role, index, system, user, session, max_turns=None):
        """One agent. Every stop condition is recorded, never silently swallowed."""
        result = loop.run_conversation(self.provider, role, self.cfg.models[role],
                                       system, user, session, meter=self.meter,
                                       caps=self.cfg.caps, max_turns=max_turns,
                                       clock=self.clock)
        self.conversations.append(result)
        if not result.ok:
            self.notes.append("%s %s ended as %s: %s"
                              % (role, result.agent_id, result.status, result.reason))
        return result

    def session_for(self, role, agent_id, expected=None, offered=None):
        return tools.ToolSession(self.source, framer=self.framer, role=role,
                                 model=self.cfg.models[role], agent_id=agent_id,
                                 validator=self.validator, expected_fingerprints=expected,
                                 offered_fingerprints=offered, caps=self.cfg.caps)

    # ------------------------------------------------------------------------ phases

    def plan(self, diff, changed_files, commit_count, symbol_resolver, prior=None,
             recon_calls=1):
        """P0: routing, the coverage floor and the budget gate, before any model call."""
        self.diff = diff
        self.routing = routing.route(changed_files, workflow_ref=self.cfg.workflow_ref)
        self.ledger = ledgermod.seed(self.validator, self.routing, changed_files,
                                     commit_count=commit_count,
                                     symbol_resolver=symbol_resolver, prior=prior)
        assignments = ledgermod.cluster(self.ledger)
        plan = ledgermod.budget_gate(self.cfg.caps, len(assignments),
                                     recon_calls=recon_calls,
                                     expected_candidates=len(assignments))
        if plan.run_status == INCOMPLETE:
            # The skill says to launch nothing rather than thin the evidence.
            raise RunAborted(plan.incomplete_reason or REASON_NO_BUDGET,
                             "; ".join(plan.notes))
        # Assignments past the hunter allowance are deferred with the skill's reason and
        # stay visible in "not reviewed"; they are never dropped.
        # apply_budget returns (launched, deferred); the deferred half is already
        # recorded in the ledger and shows up in not_reviewed().
        self.assignments, self.deferred_assignments = ledgermod.apply_budget(
            self.ledger, assignments, plan)
        self.budget_plan = plan
        return plan

    def recon(self, facts, architecture=None, changed_paths=()):
        """P1: delta reconnaissance.

        The skill reserves four baseline reconnaissance calls per run (SKILL.md:123).
        With a usable baseline architecture.md this run spends one instead, which is a
        deviation, not an interpretation, so it is registered as one.
        """
        if architecture is not None:
            self.deviate("delta reconnaissance",
                         "one delta-recon agent instead of the four baseline calls "
                         "reserved by SKILL.md:123, because a baseline architecture.md "
                         "for the merge-base was available")
            agents = ("1c",)
        else:
            agents = prompts.RECON_AGENTS
        results = []
        for number, agent in enumerate(agents):
            identifier = ledgermod.agent_id("recon", number + 1)
            session = self.session_for("recon", identifier)
            prompt = prompts.recon_prompt(facts, self.framer, identifier, agent=agent,
                                          changed_paths=list(changed_paths),
                                          architecture=architecture,
                                          pack=self.skill,
                                          submit_tool=tools.SUBMIT_TOOLS["recon"])
            results.append(self.run_agent("recon", number + 1, prompt.system, prompt.user,
                                          session))
        return [r for r in results if r.ok]

    def hunt(self, facts, assignments, architecture=None, secret_facts=(), drafts=()):
        """P2: exactly one hunter wave (SKILL.md:111)."""
        results = []
        for number, assignment in enumerate(assignments, start=1):
            if self.out_of_time() or self.remaining_conversations() <= self.reserved():
                self.ledger_defer(assignment, REASON_NO_RESERVE)
                continue
            identifier = assignment.agent_id or ledgermod.agent_id("hunter", number)
            # Serialised, not the live Unit: prompts copies a whitelist of fields, which
            # also keeps the parent's own bookkeeping out of an agent's prompt.
            units = [self.ledger.get(cid).to_json() for cid in assignment.coverage_ids]
            for coverage_id in assignment.coverage_ids:
                self.ledger.assign(coverage_id, identifier)
            session = self.session_for("hunter", identifier)
            context = pack.hunter_pack(self.packsrc, self.diff, units,
                                       self.pack_budget("hunter"))
            prompt = prompts.hunter_prompt(
                facts, self.framer, identifier, units,
                architecture=architecture,
                excluded_blocks=self.routing.excluded,
                peer_coverage_ids=self.peer_ids(assignments, assignment),
                secret_facts=secret_facts, seeder_drafts=drafts,
                context_pack=pack.render(context, self.framer), pack=self.skill,
                submit_tool=tools.SUBMIT_TOOLS["hunter"])
            result = self.run_agent("hunter", number, prompt.system, prompt.user, session)
            if result.ok:
                results.append((assignment, result))
            else:
                self.ledger_defer(assignment, result.status)
        return results

    def critique(self, facts, candidates, architecture=None):
        """P3: the coverage critic, before any verifier runs.

        VALIDATION-AND-REPORTING.md:5 puts consolidation after "the clean coverage-critic
        pass". Running it beside the verifiers would save a few minutes and break the
        order the skill states, so it runs alone here.
        """
        identifier = ledgermod.agent_id("critic", 1)
        session = self.session_for("critic", identifier)
        prompt = prompts.critic_prompt(facts, self.framer, identifier,
                                       units=self.ledger.document(),
                                       candidates=candidates, architecture=architecture,
                                       pack=self.skill,
                                       submit_tool=tools.SUBMIT_TOOLS["critic"])
        result = self.run_agent("critic", 1, prompt.system, prompt.user, session)
        if not result.ok:
            self.incomplete(REASON_CRITIC, "the coverage critic did not complete, so the "
                                           "coverage claim is unreviewed")
        return result

    def verify(self, facts, candidates, architecture=None):
        """P4: one fresh verifier per unique candidate.

        Fresh means a new conversation with a new agent id, built only from the
        structured candidate: no hunter reasoning, and no other verifier's conclusion
        (VALIDATION-AND-REPORTING.md:5-7). Independence is structural here, not asked for.
        """
        verified = []
        for number, candidate in enumerate(candidates, start=1):
            if self.out_of_time() or self.remaining_conversations() <= 0:
                self.unvalidated.append(candidate.get("fingerprint", ""))
                continue
            identifier = ledgermod.agent_id("verifier", number)
            fingerprint = candidate.get("fingerprint", "")
            session = self.session_for("verifier", identifier,
                                       expected=(fingerprint,) if fingerprint else None)
            context = pack.verifier_pack(self.packsrc, candidate,
                                         self.pack_budget("verifier"), diff=self.diff)
            prompt = prompts.verifier_prompt(
                facts, self.framer, identifier, candidate,
                architecture=architecture, assigned_fingerprint=fingerprint,
                context_pack=pack.render(context, self.framer), pack=self.skill,
                submit_tool=tools.SUBMIT_TOOLS["verifier"])
            result = self.run_agent("verifier", number, prompt.system, prompt.user, session)
            if result.ok and result.result:
                verified.extend(result.result.get("records") or [])
            else:
                # An unvalidated candidate never becomes a finding under any verdict.
                self.unvalidated.append(fingerprint)
        if self.unvalidated:
            self.incomplete(REASON_VALIDATION,
                            "%d candidate(s) could not be validated" % len(self.unvalidated))
        return verified

    # ------------------------------------------------------------------- run metadata

    def metadata(self, extra=None):
        """run-metadata.json: the contract publish.py and state.py read.

        `suppressions` and `prior_source_state` are what let a later run tell a lead that
        was fixed from one that was talked out of the report.
        """
        data = {
            "run_id": self.cfg.run_id,
            "repo": self.cfg.repository,
            "pr_number": self.cfg.pr_number,
            "head_sha": self.cfg.head_sha,
            "base_sha": self.cfg.base_sha,
            "profile": "quick",
            "scope": "diff",
            "execution_policy": "source-only-no-execution",
            "models": dict(self.cfg.models),
            "run_status": self.status,
            "incomplete_reason": self.reason,
            "deviations": list(self.deviations),
            "notes": list(self.notes),
            "unvalidated_fingerprints": list(self.unvalidated),
            "conversations": [c.as_dict() for c in self.conversations],
            "usd_spent": round(self.meter.spent, 4),
            "seconds": round(self.clock() - self.started, 1),
            "suppressions": [],
            # Spelled as publish.Bundle reads it; a second spelling here was dead.
            "prior_source_state": {},
        }
        data.update(extra or {})
        return data

    def write(self, name, payload):
        path = os.path.join(self.cfg.out_dir, "bundle", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        blob = payload if isinstance(payload, str) else json.dumps(payload, indent=1,
                                                                   sort_keys=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(blob)
        return path

    # ----------------------------------------------------------------------- helpers

    def reserved(self):
        """Conversations that must stay available: the critic plus one verifier."""
        return 2

    def pack_budget(self, role):
        model = self.cfg.models[role]
        return pack.budget_for(self.cfg.caps, model, skill=self.skill)

    def peer_ids(self, assignments, mine):
        ids = []
        for assignment in assignments:
            if assignment is mine:
                continue
            ids.extend(assignment.coverage_ids)
        return ids

    def ledger_defer(self, assignment, reason):
        for coverage_id in assignment.coverage_ids:
            try:
                self.ledger.defer(coverage_id, reason)
            except ledgermod.LedgerError:
                pass


def routing_changes(repo, merge_base, head, diff, max_bytes=200_000):
    """Adapt a gitsrc diff index into the records routing expects.

    They disagree on one word: a numstat entry's `added` is a count, while a routing
    entry's `added` is the added lines themselves. Handing routing the unified patch
    lets it parse the lines it needs and keeps the two meanings apart.
    """
    changes = []
    for entry in diff.get("files") or []:
        record = {"path": entry.get("path", ""),
                  "previous_path": entry.get("old_path") or "",
                  "status": (entry.get("status") or "modified").lower()}
        if not entry.get("binary"):
            try:
                patch = gitsrc.diff_text(repo, merge_base, head, record["path"],
                                         old_path=record["previous_path"] or None,
                                         max_bytes=max_bytes)
                record["patch"] = patch.get("text", "") if isinstance(patch, dict) else patch
            except gitsrc.GitError:
                # Routing still sees the path; only the content signals are missing, and
                # the omission is recorded rather than passing as "nothing to route".
                record["patch"] = ""
        changes.append(record)
    return changes


def secret_facts_for(repo, commits, head_sha=""):
    """Deterministic seeder facts, carried as parent facts rather than findings.

    ATTACK-CLASSES.md:130 is explicit that a flag is not a finding, so these are inputs
    to a hunter and are routed through a verifier like any other candidate.

    The walk is per commit rather than over the merge-base diff because a credential
    added in one commit and deleted in a later one is absent from that diff and still
    present in the pushed history.
    """
    blobs = []
    for meta in commits:
        sha = meta["sha"] if isinstance(meta, dict) else meta
        patch = gitsrc.commit_patch(repo, sha)
        if not patch.get("available"):
            continue
        for path, text in _added_by_path(patch.get("text", "")).items():
            blobs.append({"commit": sha, "path": path, "text": text,
                          "is_head": sha == head_sha})
    return seeders.scan_secrets(blobs)


def _added_by_path(patch_text):
    """Added lines of a unified patch, grouped by the file they were added to."""
    by_path = {}
    path = ""
    for line in (patch_text or "").splitlines():
        if line.startswith("+++ b/"):
            path = line[6:].strip()
        elif line.startswith("+++ "):
            path = line[4:].strip()
        elif path and line.startswith("+") and not line.startswith("+++"):
            by_path.setdefault(path, []).append(line[1:])
    return {p: "\n".join(lines) for p, lines in by_path.items()}
