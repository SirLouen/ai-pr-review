"""The coverage ledger -- which IS this run's coverage claim (RECONNAISSANCE.md:154).

Nothing else in the bundle claims coverage. An architecture summary, an agent count or a
"we reviewed auth" sentence is not evidence; only a unit with an owner, owned paths and
owned checks is. So every rule the skill states about units is enforced here, in code,
before the vendored validator ever sees the document -- and then the vendored validator
is run anyway, because it is the authority.

Three things in this module are deliberately immune to model output:

1. The coverage floor (design 4.5 step 3). Every changed non-doc file gets a unit, the
   diff and the PR's own commit history get one each, and every changed CI file gets one
   per routed CI class. A successful prompt injection can talk a hunter out of reporting;
   it cannot talk `seed()` out of seeding. Honest naming, though: on a PR whose floor
   exceeds what the hunter budget can reach, this is a SEEDING-AND-DISCLOSURE guarantee,
   not a review guarantee. The tail becomes `deferred` with a reason and is listed by
   `not_reviewed()`; it is never silently dropped.
2. `coverage_id`, which only ever comes from the vendored `canonicalCoverageId` through
   `validate.Validator`. There is no Python percent-encoder here on purpose.
3. The state table (RECONNAISSANCE.md:141-152). Owner, evidence and fingerprint rules are
   checked on every transition, and `reviewed_paths` is computed as the union of the
   checks' owned paths rather than accepted from a result.

Because this run executes nothing, every check is `method: "source"` with `artifact:
null`. That is legal ledger evidence, and it is what makes a no-execution run
representable at all.

Boundary references are source-derived. A fixed literal in the boundary dimension would
collapse the coverage claim into one row per file, so a changed file's boundary is the
symbol enclosing its change. Only the two genuinely diff-wide mandatory units use
synthetic `repo#...` references, and they say so in their own labels.
"""
import json
import math
import os
import unicodedata
from dataclasses import dataclass, replace

from . import routing as rt

QUICK_SUBSYSTEM_REF = "profile/quick/all-in-scope-subsystems"
QUICK_SUBSYSTEM_LABEL = "All in-scope subsystems (quick)"

# Reason strings the skill defines verbatim. Paraphrasing one would make a machine-read
# report lie about which rule stopped the run, so they are constants, never literals.
REASON_NO_RECON = "budget_cannot_fund_reconnaissance_and_reserves"   # SKILL.md:123
REASON_RESERVES = "budget_cannot_reserve_critics_and_validation"     # SKILL.md:130
REASON_VALIDATION = "validation_budget_exhausted"                    # SKILL.md:134
REASON_CRITIC = "critic_budget_exhausted"                            # SKILL.md:132
REASON_QUICK_CRITIC = "quick_profile_final_critic"                   # HUNTING.md:249
REASON_MALFORMED = "hunter_result_malformed"                         # HUNTING.md:217

STATUSES = ("planned", "not_applicable", "out_of_scope", "in_progress",
            "covered", "candidate", "blocked", "deferred")

# RECONNAISSANCE.md:139 -- only evidence-bearing states may be archived into `attempts`.
ARCHIVABLE = ("covered", "candidate", "blocked")

TRANSITIONS = {
    "planned": ("in_progress", "deferred", "out_of_scope", "not_applicable"),
    "in_progress": ("covered", "candidate", "blocked", "planned", "deferred"),
    "covered": ("in_progress", "deferred"),
    "candidate": ("in_progress", "deferred"),
    "blocked": ("in_progress", "deferred"),
    "deferred": ("planned", "in_progress"),
    "out_of_scope": ("planned",),
    "not_applicable": ("planned",),
}

PRIOR_STATUSES = ("new", "prior_confirmed_same_source", "prior_confirmed_changed_source",
                  "prior_needs_validation", "prior_deferred", "prior_blocked",
                  "prior_out_of_scope", "prior_covered_same_source",
                  "prior_covered_changed_source", "prior_rejected_claim_changed", "none")

# Floor origins. `mandatory` here means "the parent seeded it, no model chose it".
ORIGIN_DIFF = "floor-diff"            # design 4.5 step 3(a)
ORIGIN_COMMITS = "floor-commits"      # design 4.5 step 3(b)
ORIGIN_CI = "floor-ci"                # design 4.5 step 3(c)
ORIGIN_PATH = "floor-path"            # design 4.5 step 3(d)
ORIGIN_RECON = "recon"
ORIGIN_CRITIC = "critic"
FLOOR_ORIGINS = (ORIGIN_DIFF, ORIGIN_COMMITS, ORIGIN_CI, ORIGIN_PATH)

DEFAULT_UNITS_PER_HUNTER = 4          # design 4.5 step 5
DEFAULT_COMPANIONS_PER_HUNTER = 3

MAX_REF_CHARS = 1024                  # isCanonicalRef
MAX_TEXT_CHARS = 4096                 # isVisibleText
MAX_LIST_ITEMS = 1000                 # LIMITS.collectionItems
MAX_EXCLUDED_BLOCKS = 200

SYNTHETIC_NOTE = "synthetic diff-wide reference"

# HUNTING.md:7 rank 1: surfaces an unauthenticated principal reaches. A pull request's
# own content is the least trusted input this reviewer ever sees.
UNTRUSTED_TAGS = frozenset(("privileged-trigger", "head-checkout", "ci", "ai-in-ci",
                            "webhook", "agent-config", "review-gate"))
REACHABLE_TAGS = frozenset(("route", "http", "rpc", "socket", "messaging", "frontend",
                            "template", "llm", "edge", "auth"))
# HUNTING.md:7 rank 2: credentials, code execution, release authority first, then
# cross-tenant data.
CROWN_TAGS = frozenset(("secret", "crypto", "release", "automation-identity",
                        "cloud-identity", "privileged-trigger", "head-checkout", "ci"))
TENANT_TAGS = frozenset(("tenant", "data"))
CROWN_CLASSES = frozenset((
    "Cryptography and secrets", "Untrusted code in a privileged workflow",
    "Workflow command and expression confusion", "Automation identity overreach",
    "Cache, artifact, and workspace trust mixing", "Release and artifact integrity",
    "Injection", "Obvious things"))
TENANT_CLASSES = frozenset(("Access control", "Feature abuse and data leakage",
                            "Cross-tenant isolation"))
# HUNTING.md:7 rank 4: classes that historically close with a real finding on this
# target type (a PR diff) rather than a speculative one.
HIGH_YIELD_CLASSES = frozenset((
    "Obvious things", "Injection", "Access control", "Cryptography and secrets",
    "Untrusted code in a privileged workflow", "Workflow command and expression confusion",
    "Automation identity overreach"))

# A prior gap is current work (HUNTING.md:7 rank 3); a same-source re-pass is not.
PRIOR_RANK = {
    "prior_needs_validation": 0, "prior_blocked": 0, "prior_deferred": 0,
    "prior_out_of_scope": 0, "prior_confirmed_changed_source": 0,
    "prior_covered_changed_source": 0, "prior_rejected_claim_changed": 0,
    "new": 1, "none": 1,
    "prior_confirmed_same_source": 2, "prior_covered_same_source": 2,
}


class LedgerError(Exception):
    pass


# --------------------------------------------------------------------- text helpers

def visible_text(value, limit=MAX_TEXT_CHARS):
    """Mirror of the validator's isVisibleText, for failing early with our own message."""
    if not isinstance(value, str) or not value or len(value) > limit:
        return False
    if value.strip() != value:
        return False
    for ch in value:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
            return False
    return any(not ch.isspace() for ch in value)


def canonical_ref(value):
    """Mirror of isCanonicalRef. NFC is checked because a path can arrive decomposed."""
    return (visible_text(value, MAX_REF_CHARS)
            and unicodedata.normalize("NFC", value) == value)


def safe_agent_id(value):
    if not isinstance(value, str) or not (1 <= len(value) <= 64):
        return False
    if value[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
        return False
    for ch in value[1:]:
        if ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-":
            return False
    base = value.split(".", 1)[0]
    return base not in ("con", "prn", "aux", "nul") and not (
        base[:3] in ("com", "lpt") and len(base) == 4 and base[3] in "123456789")


def agent_id(role, index):
    """A canonical lowercase owner id. Owners are parent-assigned, never model-chosen."""
    value = "%s-%d" % (role, index)
    if not safe_agent_id(value):
        raise LedgerError("generated agent id is not canonical: %r" % value)
    return value


def _dedupe(values):
    out, seen = [], set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return tuple(out)


# --------------------------------------------------------------------------- checks

@dataclass(frozen=True)
class Check:
    """One owned check. `method` is 'source' for every check this run can produce."""
    agent_id: str
    reviewed_paths: tuple
    invariant: str
    result: str
    method: str = "source"
    artifact: object = None

    def to_json(self):
        return {"agent_id": self.agent_id,
                "reviewed_paths": list(self.reviewed_paths),
                "invariant": self.invariant,
                "method": self.method,
                "result": self.result,
                "artifact": self.artifact}


def source_check(owner, reviewed_paths, invariant, result):
    """A source-only check: the only evidence shape a no-execution run can produce."""
    paths = _dedupe(reviewed_paths)
    if not paths:
        raise LedgerError("a check must name at least one reviewed path")
    if not safe_agent_id(owner):
        raise LedgerError("check owner %r is not a canonical agent id" % (owner,))
    for text, name in ((invariant, "invariant"), (result, "result")):
        if not visible_text(text):
            raise LedgerError("check %s is not visible text" % name)
    return Check(agent_id=owner, reviewed_paths=paths, invariant=invariant,
                 result=result, method="source", artifact=None)


# ---------------------------------------------------------------------------- units

@dataclass
class Unit:
    coverage_id: str
    canonical_refs: dict
    surface: str
    boundary: str
    subsystem: str
    attack_class: str
    starting_paths: tuple
    ordinary_attack_class_block: object
    selected_companion_blocks: tuple = ()
    excluded_blocks: tuple = ()
    prior_status: str = "none"
    attempts: tuple = ()
    wave: int = 1
    status: str = "planned"
    agent_id: object = None
    reviewed_paths: tuple = ()
    local_checks: tuple = ()
    result_fingerprints: tuple = ()
    unresolved: tuple = ()
    # Parent bookkeeping (RECONNAISSANCE.md:137 allows it beside the semantic fields).
    origin: str = ORIGIN_RECON
    mandatory: bool = False
    boundary_kind: str = "symbol"      # symbol | module-scope | config-key | diff-wide
    companions: tuple = ()
    tags: tuple = ()
    priority: tuple = ()
    rationale: str = ""
    hardening: tuple = ()
    owners_seen: tuple = ()

    @property
    def floor(self):
        return self.origin in FLOOR_ORIGINS

    @property
    def synthetic(self):
        return self.boundary_kind == "diff-wide"

    def to_json(self):
        """The validator-shaped unit. Bookkeeping lives under one namespaced key."""
        return {
            "coverage_id": self.coverage_id,
            "canonical_refs": dict(self.canonical_refs),
            "surface": self.surface,
            "boundary": self.boundary,
            "subsystem": self.subsystem,
            "attack_class": self.attack_class,
            "starting_paths": list(self.starting_paths),
            "ordinary_attack_class_block": self.ordinary_attack_class_block,
            "selected_companion_blocks": list(self.selected_companion_blocks),
            "excluded_blocks": [dict(entry) for entry in self.excluded_blocks],
            "prior_status": self.prior_status,
            "attempts": [dict(attempt) for attempt in self.attempts],
            "wave": self.wave,
            "status": self.status,
            "agent_id": self.agent_id,
            "reviewed_paths": list(self.reviewed_paths),
            "local_checks": [check.to_json() for check in self.local_checks],
            "result_fingerprints": list(self.result_fingerprints),
            "unresolved": list(self.unresolved),
            "parent": {
                "origin": self.origin,
                "mandatory": self.mandatory,
                "boundary_kind": self.boundary_kind,
                "companions": list(self.companions),
                "tags": list(self.tags),
                "priority": list(self.priority),
                "ordering_rationale": self.rationale,
                "hardening": list(self.hardening),
            },
        }


def _check_state(unit, status, owner, checks, fingerprints, unresolved):
    """RECONNAISSANCE.md:141-152, enforced before the vendored validator runs."""
    paths = tuple(sorted({p for check in checks for p in check.reviewed_paths}))
    if status != "candidate" and fingerprints:
        raise LedgerError("%s unit cannot carry result_fingerprints" % status)
    if status in ("planned", "not_applicable", "out_of_scope", "deferred", "in_progress"):
        if status != "in_progress" and owner is not None:
            raise LedgerError("%s unit must be unassigned" % status)
        if status == "in_progress" and not safe_agent_id(owner or ""):
            raise LedgerError("in_progress unit needs a canonical owner")
        if checks or paths:
            raise LedgerError("%s unit must carry no evidence" % status)
    else:
        if not safe_agent_id(owner or ""):
            raise LedgerError("%s unit needs a canonical owner" % status)
        if not checks or not paths:
            raise LedgerError("%s unit needs nonempty reviewed_paths and local_checks"
                              % status)
    if status in ("not_applicable", "out_of_scope", "deferred", "blocked"):
        if not unresolved:
            raise LedgerError("%s unit needs a nonempty unresolved reason" % status)
    if status in ("planned", "in_progress", "covered") and unresolved:
        raise LedgerError("%s unit must keep unresolved empty" % status)
    if status == "candidate" and not fingerprints:
        raise LedgerError("candidate unit requires result_fingerprints")
    return paths


def _apply(unit, status, owner=None, checks=(), fingerprints=(), unresolved=()):
    if status not in STATUSES:
        raise LedgerError("unknown status %r" % (status,))
    allowed = TRANSITIONS.get(unit.status, ())
    if status != unit.status and status not in allowed:
        raise LedgerError("illegal transition %s -> %s for %s"
                          % (unit.status, status, unit.coverage_id))
    checks = tuple(checks)
    fingerprints = _dedupe(fingerprints)
    unresolved = _dedupe(unresolved)
    for text in unresolved:
        if not visible_text(text):
            raise LedgerError("unresolved entry is not visible text")
    paths = _check_state(unit, status, owner, checks, fingerprints, unresolved)
    unit.status = status
    unit.agent_id = owner
    unit.local_checks = checks
    unit.reviewed_paths = paths
    unit.result_fingerprints = fingerprints
    unit.unresolved = unresolved
    if owner:
        unit.owners_seen = _dedupe(unit.owners_seen + (owner,))
    return unit


# ------------------------------------------------------------------- unit factories

def _class_name(block):
    return block.split("#", 1)[1] if "#" in block else block


def make_unit(validator, surface_ref, boundary_ref, attack_ref, surface, boundary,
              attack_class, starting_paths, ordinary_block=None, companion_blocks=(),
              excluded=(), subsystem_ref=QUICK_SUBSYSTEM_REF,
              subsystem=QUICK_SUBSYSTEM_LABEL, **bookkeeping):
    """Build one unit. `coverage_id` comes from the vendored canonicalCoverageId only."""
    refs = {"surface": surface_ref, "boundary": boundary_ref,
            "subsystem": subsystem_ref, "attack_class": attack_ref}
    for name, value in refs.items():
        if not canonical_ref(value):
            raise LedgerError("canonical ref %s is not usable: %r" % (name, value))
    paths = _dedupe(starting_paths)[:MAX_LIST_ITEMS]
    if not paths:
        raise LedgerError("a unit needs at least one starting path (%s)" % surface_ref)
    excluded = tuple({e["block"]: dict(e) for e in excluded}.values())[:MAX_EXCLUDED_BLOCKS]
    selected = _dedupe(companion_blocks)
    excluded = tuple(e for e in excluded if e["block"] not in set(selected))
    return Unit(coverage_id=validator.coverage_id(refs),
                canonical_refs=refs,
                surface=surface, boundary=boundary, subsystem=subsystem,
                attack_class=attack_class,
                starting_paths=paths,
                ordinary_attack_class_block=ordinary_block,
                selected_companion_blocks=selected,
                excluded_blocks=excluded,
                **bookkeeping)


# --------------------------------------------------------------------------- ledger

@dataclass
class Assignment:
    """One hunter's cluster. `rank` is its position in the priority queue.

    `deferred_companions` are companion files a single over-broad unit brought in above
    the per-hunter cap. They cannot be split across hunters, so they are dropped from
    the prompt in HUNTING.md:7 domain order and named here for `excluded_blocks`.
    """
    agent_id: str
    coverage_ids: tuple
    companions: tuple
    starting_paths: tuple
    rank: int
    rationale: str
    deferred_companions: tuple = ()


@dataclass(frozen=True)
class BudgetPlan:
    budget: int
    recon_calls: int
    critic_reserve: int
    verifier_reserve: int
    hunters: int
    run_status: str
    incomplete_reason: str
    notes: tuple = ()

    @property
    def launches(self):
        return self.run_status != "incomplete" and self.hunters > 0


class Ledger:
    """Every unit in the run, plus the paths the skill's own validator cannot represent.

    The ledger owns the state machine so that no caller can move a unit without the
    owner/evidence rules being checked, and it owns the `Validator` so that a coverage
    id is never assembled anywhere else.
    """

    def __init__(self, validator, routing=None, changed_paths=(), floor_required=(),
                 unreportable=()):
        self.validator = validator
        self.routing = routing
        self.changed_paths = frozenset(changed_paths)
        # The floor obligation covers changed NON-DOC files; a changed README is in
        # scope for a proposal but does not by itself demand a seeded unit.
        self.floor_required = frozenset(floor_required)
        self.unreportable = tuple(unreportable)
        self._units = {}

    # -- membership

    def add(self, unit):
        existing = self._units.get(unit.coverage_id)
        if existing is not None:
            if existing.canonical_refs != unit.canonical_refs:
                raise LedgerError("canonical identity collision on %s" % unit.coverage_id)
            return existing
        for other in self._units.values():
            if self._semantic(other) == self._semantic(unit):
                raise LedgerError(
                    "semantic tuple of %s already uses coverage id %s"
                    % (unit.coverage_id, other.coverage_id))
        self._units[unit.coverage_id] = unit
        return unit

    @staticmethod
    def _semantic(unit):
        return (unit.surface, unit.boundary, unit.subsystem, unit.attack_class)

    def get(self, coverage_id):
        try:
            return self._units[coverage_id]
        except KeyError:
            raise LedgerError("no such coverage unit: %r" % (coverage_id,))

    def __len__(self):
        return len(self._units)

    def __contains__(self, coverage_id):
        return coverage_id in self._units

    @property
    def units(self):
        """Sorted lexicographically by coverage_id -- the validator requires that order."""
        return tuple(self._units[key] for key in sorted(self._units))

    def by_status(self, *statuses):
        wanted = set(statuses)
        return tuple(u for u in self.units if u.status in wanted)

    # -- state machine

    def assign(self, coverage_id, owner):
        return _apply(self.get(coverage_id), "in_progress", owner=owner)

    def close_covered(self, coverage_id, owner, checks):
        checks = self._screen_checks(owner, checks)
        return _apply(self.get(coverage_id), "covered", owner=owner, checks=checks)

    def close_candidate(self, coverage_id, owner, checks, fingerprints, unresolved=()):
        checks = self._screen_checks(owner, checks)
        return _apply(self.get(coverage_id), "candidate", owner=owner, checks=checks,
                      fingerprints=fingerprints, unresolved=unresolved)

    def close_blocked(self, coverage_id, owner, checks, unresolved):
        checks = self._screen_checks(owner, checks)
        return _apply(self.get(coverage_id), "blocked", owner=owner, checks=checks,
                      unresolved=unresolved)

    def defer(self, coverage_id, reason):
        return _apply(self.get(coverage_id), "deferred", unresolved=(reason,))

    def mark_out_of_scope(self, coverage_id, reason):
        return _apply(self.get(coverage_id), "out_of_scope", unresolved=(reason,))

    def mark_not_applicable(self, coverage_id, reason):
        return _apply(self.get(coverage_id), "not_applicable", unresolved=(reason,))

    def replan(self, coverage_id):
        """A malformed hunter result leaves its unit `planned` (HUNTING.md:217)."""
        return _apply(self.get(coverage_id), "planned")

    def reopen(self, coverage_id, reason, owner=None):
        """Archive the live terminal state into `attempts` and take the unit forward.

        RECONNAISSANCE.md:139: the archive keeps its own owner and evidence, the live
        state starts empty, the wave increments, and the next owner must be fresh.
        """
        unit = self.get(coverage_id)
        if unit.status not in ARCHIVABLE:
            raise LedgerError("only %s units can be archived, not %s"
                              % ("/".join(ARCHIVABLE), unit.status))
        if not visible_text(reason):
            raise LedgerError("reassignment_reason is not visible text")
        if owner is not None and owner in unit.owners_seen:
            raise LedgerError("assignment owner must be fresh for each attempt")
        archive = {"wave": unit.wave,
                   "status": unit.status,
                   "agent_id": unit.agent_id,
                   "reviewed_paths": list(unit.reviewed_paths),
                   "local_checks": [c.to_json() for c in unit.local_checks],
                   "result_fingerprints": list(unit.result_fingerprints),
                   "unresolved": list(unit.unresolved),
                   "reassignment_reason": reason}
        unit.attempts = unit.attempts + (archive,)
        unit.status = "planned"          # neutral hop; the real state is set below
        unit.agent_id = None
        unit.local_checks = ()
        unit.reviewed_paths = ()
        unit.result_fingerprints = ()
        unit.unresolved = ()
        unit.wave += 1
        if owner is None:
            return _apply(unit, "deferred", unresolved=(reason,))
        return _apply(unit, "in_progress", owner=owner)

    def _screen_checks(self, owner, checks):
        """Reject evidence that cites a path the skill's own validator cannot express."""
        checks = tuple(checks)
        for check in checks:
            if check.agent_id != owner and not safe_agent_id(check.agent_id):
                raise LedgerError("check owner %r is not canonical" % (check.agent_id,))
        paths = sorted({p for check in checks for p in check.reviewed_paths})
        for bad in self.validator.screen_paths(paths):
            raise LedgerError("check cites an unrepresentable path %s: %s"
                              % (bad.path, bad.reason))
        return checks

    # -- serialisation

    def document(self):
        return [unit.to_json() for unit in self.units]

    def dumps(self):
        return json.dumps(self.document(), indent=2, ensure_ascii=False) + "\n"

    def write(self, out_dir, name="coverage-ledger.json"):
        target = os.path.join(out_dir, name)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(self.dumps())
        return target

    def validate(self):
        """The vendored validator's exact messages. Empty means the document is valid."""
        return self.validator.validate_ledger(self.document())

    # -- disclosure

    def not_reviewed(self):
        """Everything this run did not review, in one list. Nothing is dropped silently.

        The coverage floor is a seeding guarantee, not a review guarantee: on a PR whose
        floor exceeds the hunter budget the tail lands here as `deferred` with a reason.
        Paths the skill's validator cannot represent at all land here too -- otherwise a
        PR author could suppress a lead by naming a file `src/aux/handler.ts`.
        """
        out = []
        for unit in self.units:
            if unit.status in ("planned", "deferred", "out_of_scope", "not_applicable",
                               "in_progress", "blocked"):
                out.append({"kind": "unit",
                            "coverage_id": unit.coverage_id,
                            "status": unit.status,
                            "surface": unit.surface,
                            "boundary": unit.boundary,
                            "attack_class": unit.attack_class,
                            "starting_paths": list(unit.starting_paths),
                            "floor": unit.floor,
                            "mandatory": unit.mandatory,
                            "reason": unit.unresolved[0] if unit.unresolved else
                                      "assigned but never closed"})
        for entry in self.unreportable:
            out.append({"kind": "path", "path": entry["path"], "status": "unrepresentable",
                        "reason": entry["reason"], "floor": True, "mandatory": True})
        return tuple(out)

    def coverage_summary(self):
        counts = {}
        for unit in self.units:
            counts[unit.status] = counts.get(unit.status, 0) + 1
        return {"units": len(self._units), "by_status": counts,
                "floor_units": sum(1 for u in self.units if u.floor),
                "unrepresentable_paths": len(self.unreportable)}


# ----------------------------------------------------------------------- floor seed

def _excluded_for(routing, unit_companions):
    """Per-unit `excluded_blocks` at group-heading granularity (RECONNAISSANCE.md:135).

    Group granularity keeps the list at a few dozen entries instead of ~160, and a
    heading is a legal block reference. Blocks routed for this run but carried by a peer
    unit are excluded here with that fact as the reason, which is what stops a hunter
    treating another unit's scope as its own (HUNTING.md:25).
    """
    if routing is None:
        return ()
    out = [dict(entry) for entry in routing.excluded]
    carried = set(unit_companions)
    seen = set()
    for selection in routing.selections:
        group = selection.get("group")
        if group is None or group in seen or selection["companion"] in carried:
            continue
        seen.add(group)
        out.append({"block": rt.group_block(group),
                    "companion": selection["companion"],
                    "group": group,
                    "reason": "routed for this run from another changed path; this "
                              "boundary is owned by a peer coverage unit"})
    return tuple(out)


def _screen(validator, paths):
    """Split paths into (usable, unreportable). NFC is our own extra gate."""
    usable, bad = [], []
    rejected = {entry.path: entry.reason for entry in validator.screen_paths(paths)}
    for path in paths:
        reason = rejected.get(path)
        if reason is None and not canonical_ref(path):
            reason = ("path is not a usable canonical reference (non-NFC, over %d "
                      "characters, or carrying an invisible code point)" % MAX_REF_CHARS)
        if reason is None:
            usable.append(path)
        else:
            bad.append({"path": path, "reason": reason})
    return usable, bad


def _boundary_for(path, symbol):
    """A changed file's boundary is the control its change sits inside.

    A fixed literal here would give every file the same boundary label and collapse the
    coverage claim, so the symbol enclosing the change is resolved from source. When no
    symbol resolves the boundary is the module's own top-level scope, which is still a
    real source object, and the unit records which of the two it got.
    """
    symbol = (symbol or "").strip()
    if symbol and symbol != "_top" and canonical_ref("%s#%s" % (path, symbol)):
        return "%s#%s" % (path, symbol), "%s in %s" % (symbol, path), "symbol"
    return ("%s#module scope" % path, "Module scope of %s" % path, "module-scope")


def seed(validator, routing, changed_files, commit_count=1, symbol_resolver=None,
         prior=None, subsystem_ref=QUICK_SUBSYSTEM_REF):
    """The code-enforced coverage floor: design 4.5 step 3 (a) (b) (c) (d).

    `symbol_resolver(path)` returns the symbol enclosing that file's change, normally
    `fingerprint.enclosing_symbol` over the first hunk. It is a callable rather than
    baked in so this module never touches git.

    Returns a `Ledger` whose every unit is `planned`. Nothing a model later says can
    remove one of these units; the worst a budget can do is defer it with a reason.
    """
    changes = [rt.normalize_change(entry) for entry in changed_files]
    all_paths = _dedupe(c["path"] for c in changes)
    usable, unreportable = _screen(validator, list(all_paths))
    usable_set = set(usable)
    non_doc = _dedupe(c["path"] for c in changes
                      if c["path"] in usable_set and not rt.is_doc(c["path"]))
    ledger = Ledger(validator, routing=routing, changed_paths=usable,
                    floor_required=non_doc, unreportable=unreportable)
    prior_of = (lambda cid: (prior or {}).get(cid, "new")) if prior is not None \
        else (lambda cid: "none")

    diff_paths = list(non_doc) or list(usable)
    if not diff_paths:
        raise LedgerError("no changed path can be represented in a coverage ledger; "
                          "%d path(s) were rejected by the skill's own validator"
                          % len(unreportable))

    def tags_for(paths):
        out = set()
        for path in paths:
            out.update(routing.path_tags.get(path, ()) if routing else ())
        return tuple(sorted(out))

    # (a) The diff itself. Synthetic refs, and the labels say so.
    ledger.add(make_unit(
        validator,
        "repo#pull-request-diff", "repo#committed-content",
        rt.block_id(rt.ATTACK, "Obvious things"),
        "Pull request diff (mandatory diff-wide unit)",
        "Committed repository content (%s)" % SYNTHETIC_NOTE,
        "Obvious things", diff_paths,
        ordinary_block=rt.block_id(rt.ATTACK, "Obvious things"),
        excluded=_excluded_for(routing, ()),
        subsystem_ref=subsystem_ref,
        origin=ORIGIN_DIFF, mandatory=True, boundary_kind="diff-wide",
        tags=tags_for(diff_paths)))

    # (b) The PR's own commits. A secret added in commit 1 and removed in commit 3 is
    # invisible in base...head and still in the pushed history (ATTACK-CLASSES.md:103).
    if commit_count > 1:
        ledger.add(make_unit(
            validator,
            "repo#pull-request-commits", "repo#history",
            rt.block_id(rt.ATTACK, "Wildcard"),
            "Pull request commit history (mandatory diff-wide unit)",
            "Pushed git history (%s)" % SYNTHETIC_NOTE,
            "Wildcard", diff_paths,
            ordinary_block=rt.block_id(rt.ATTACK, "Wildcard"),
            excluded=_excluded_for(routing, ()),
            subsystem_ref=subsystem_ref,
            origin=ORIGIN_COMMITS, mandatory=True, boundary_kind="diff-wide",
            tags=tags_for(diff_paths)))

    # (c) Every changed CI file, once per routed CI class. `on` and `permissions` are
    # real keys in that file, so these boundaries are source-derived even though the
    # parent -- not a model -- chose them.
    ci_classes = rt.routed_ci_classes(routing) if routing else ()
    ci_paths = [p for p in usable if rt.matches_any(p, rt.CI_GLOBS)]
    for path in ci_paths:
        for block in ci_classes:
            ledger.add(make_unit(
                validator,
                "%s#on" % path, "%s#permissions" % path, block,
                "Workflow trigger of %s" % path,
                "Permission grant in %s" % path,
                _class_name(block), [path],
                ordinary_block=None,
                companion_blocks=[rt.block_id(rt.SUPPLY, name)
                                  for name in rt.FIXED_BLOCKS] + [block],
                excluded=_excluded_for(routing, (rt.SUPPLY,)),
                subsystem_ref=subsystem_ref,
                origin=ORIGIN_CI, mandatory=True, boundary_kind="config-key",
                companions=(rt.SUPPLY,),
                tags=tags_for([path])))

    # (d) Every changed non-doc file, with a source-derived boundary.
    for entry in (rt.floor_paths(routing, changed_files) if routing else ()):
        path = entry["path"]
        if path not in usable_set:
            continue
        symbol = symbol_resolver(path) if symbol_resolver else ""
        boundary_ref, boundary_label, kind = _boundary_for(path, symbol)
        for block in entry["attack_classes"]:
            ledger.add(make_unit(
                validator,
                path, boundary_ref, block,
                "Changed source file %s" % path, boundary_label,
                _class_name(block), [path],
                ordinary_block=block,
                excluded=_excluded_for(routing, ()),
                subsystem_ref=subsystem_ref,
                origin=ORIGIN_PATH, mandatory=True, boundary_kind=kind,
                tags=entry["tags"]))

    for unit in ledger.units:
        unit.prior_status = prior_of(unit.coverage_id)
        unit.priority, unit.rationale = rank(unit)
    return ledger


def floor_gap(ledger):
    """Changed non-doc paths that no in-scope unit names. Must always be empty."""
    covered = set()
    for unit in ledger.units:
        if unit.status == "out_of_scope":
            continue
        covered.update(unit.starting_paths)
    return tuple(sorted(ledger.floor_required - covered))


def assert_floor(ledger):
    gap = floor_gap(ledger)
    if gap:
        raise LedgerError("coverage floor violated; no unit names %s" % ", ".join(gap))
    return True


def add_proposed(ledger, proposal):
    """Accept one model-proposed unit, or reject it with a reason (HUNTING.md:247).

    A proposal outside the changed set is recorded `out_of_scope` rather than assigned
    (design 4.5 step 3(e), SKILL.md:115); it is never silently discarded, because a
    scoped run still has to disclose what it saw and did not review.
    """
    surface_ref = (proposal.get("surface_ref") or proposal.get("surface") or "").strip()
    boundary_ref = (proposal.get("boundary_ref") or proposal.get("boundary") or "").strip()
    attack_ref = (proposal.get("attack_class_ref")
                  or proposal.get("attack_class") or "").strip()
    paths = _dedupe(proposal.get("starting_paths") or ())
    reason = (proposal.get("reason") or "").strip()
    if not (canonical_ref(surface_ref) and canonical_ref(boundary_ref)
            and canonical_ref(attack_ref)):
        return None, "proposal carries a reference the skill's ID rules reject"
    usable, bad = _screen(ledger.validator, list(paths))
    if not usable:
        return None, "proposal names no representable repository-relative path"
    if bad:
        ledger.unreportable = ledger.unreportable + tuple(bad)
    in_scope = (set(usable) & ledger.changed_paths) or (
        {p for p in (surface_ref.rsplit("#", 1)[0], boundary_ref.rsplit("#", 1)[0])
         if p in ledger.changed_paths})
    companions = _dedupe(proposal.get("selected_companion_blocks") or ())
    companion_files = _dedupe(b.split("#", 1)[0] for b in companions)
    unit = make_unit(
        ledger.validator, surface_ref, boundary_ref, attack_ref,
        proposal.get("surface_label") or "Surface %s" % surface_ref,
        proposal.get("boundary_label") or "Boundary %s" % boundary_ref,
        _class_name(attack_ref), usable,
        ordinary_block=attack_ref if attack_ref.startswith(rt.ATTACK) else None,
        companion_blocks=companions,
        excluded=_excluded_for(ledger.routing, companion_files),
        origin=proposal.get("origin") or ORIGIN_RECON,
        mandatory=False,
        boundary_kind="symbol" if "#" in boundary_ref else "module-scope",
        companions=companion_files,
        tags=tuple(sorted({t for p in usable
                           for t in (ledger.routing.path_tags.get(p, ())
                                     if ledger.routing else ())})))
    if unit.coverage_id in ledger:
        return ledger.get(unit.coverage_id), "already seeded by the coverage floor"
    unit.priority, unit.rationale = rank(unit)
    ledger.add(unit)
    if not in_scope:
        ledger.mark_out_of_scope(
            unit.coverage_id,
            reason or "outside the merge-base...head scope of this run; recorded so a "
                      "later full run can turn it into current work")
    return unit, ""


# ------------------------------------------------------------------ priority + queue

def rank(unit):
    """HUNTING.md:7, as a sort key plus the rationale the ledger has to record."""
    tags = set(unit.tags)
    if tags & UNTRUSTED_TAGS or unit.origin in (ORIGIN_DIFF, ORIGIN_COMMITS, ORIGIN_CI):
        trust, trust_why = 0, "unauthenticated or lowest-trust entry surface"
    elif tags & REACHABLE_TAGS:
        trust, trust_why = 1, "authenticated or already-inside entry surface"
    else:
        trust, trust_why = 2, "no entry-surface signal on this path"
    if tags & CROWN_TAGS or unit.attack_class in CROWN_CLASSES:
        value, value_why = 0, "boundary protects credentials, code execution or release authority"
    elif tags & TENANT_TAGS or unit.attack_class in TENANT_CLASSES:
        value, value_why = 1, "boundary protects cross-tenant or user data"
    else:
        value, value_why = 2, "no high-value resource identified behind this boundary"
    prior = PRIOR_RANK.get(unit.prior_status, 1)
    prior_why = {0: "prior-run gap or changed source", 1: "first seen in this run",
                 2: "prior same-source pass exists"}[prior]
    yield_rank = 0 if unit.attack_class in HIGH_YIELD_CLASSES else 1
    yield_why = ("class historically closes with a real finding on a pull-request diff"
                 if yield_rank == 0 else "speculative class for this target type")
    rationale = "; ".join((trust_why, value_why, prior_why, yield_why))
    return (trust, value, prior, yield_rank, unit.coverage_id), rationale


def _cluster_key(unit):
    """Units group by boundary, then companion set (design 4.5 step 5).

    Same-companion floor units under one top-level directory are treated as one
    subsystem: HUNTING.md:5 forbids combining UNRELATED boundaries, and two changed
    files in the same package under the same routed classes are not unrelated.
    """
    if unit.boundary_kind == "diff-wide":
        return ("diff-wide", unit.canonical_refs["attack_class"], "")
    # rsplit, not split: a repository path may itself contain "#", and only the last
    # fragment is the control name this module appended.
    path = unit.canonical_refs["boundary"].rsplit("#", 1)[0]
    head = path.split("/", 1)[0] if "/" in path else ""
    return ("source", "|".join(sorted(unit.companions)), head)


def cluster(ledger, units_per_hunter=DEFAULT_UNITS_PER_HUNTER,
            companions_per_hunter=DEFAULT_COMPANIONS_PER_HUNTER, role="hunter"):
    """Group `planned` units into a stable, priority-ordered hunter queue."""
    if units_per_hunter < 1 or companions_per_hunter < 1:
        raise LedgerError("cluster caps must be positive")
    pending = sorted(ledger.by_status("planned"), key=lambda u: u.priority)
    buckets = []
    index = {}
    for unit in pending:
        key = _cluster_key(unit)
        bucket = index.get(key)
        if bucket is not None:
            merged = set(bucket["companions"]) | set(unit.companions)
            if (len(bucket["units"]) >= units_per_hunter
                    or len(merged) > companions_per_hunter):
                bucket = None
        if bucket is None:
            bucket = {"key": key, "units": [], "companions": set(),
                      "priority": unit.priority}
            buckets.append(bucket)
            index[key] = bucket
        bucket["units"].append(unit)
        bucket["companions"].update(unit.companions)
    buckets.sort(key=lambda b: b["priority"])
    out = []
    for position, bucket in enumerate(buckets):
        units = sorted(bucket["units"], key=lambda u: u.priority)
        ordered = sorted(bucket["companions"], key=_companion_rank)
        out.append(Assignment(
            agent_id=agent_id(role, position + 1),
            coverage_ids=tuple(u.coverage_id for u in units),
            companions=tuple(ordered[:companions_per_hunter]),
            starting_paths=_dedupe(p for u in units for p in u.starting_paths),
            rank=position,
            rationale=units[0].rationale,
            deferred_companions=tuple(ordered[companions_per_hunter:])))
    return tuple(out)


def _companion_rank(companion):
    """HUNTING.md:7 domain order: SUPPLY > WEB > AI > DATA > CLOUD > ... > RESOURCE."""
    order = rt.DOMAIN_PRIORITY
    return (order.index(companion) if companion in order else len(order), companion)


# ----------------------------------------------------------------------- budget gate

def budget_gate(caps, cluster_count, recon_calls=1, expected_candidates=0, spent=0,
                profile="quick"):
    """SKILL.md:121-134 as code. Reserves come first; hunters get what is left.

    The gate runs BEFORE any agent is launched. If the budget cannot fund reconnaissance
    plus the mandatory reserves, nothing launches at all -- that is the skill's rule, and
    a run that quietly thins its evidence instead would be lying about its coverage.
    """
    budget = int(caps.max_conversations)
    critic_reserve = 1 if profile == "quick" else 2
    notes = []
    floor = recon_calls + critic_reserve + 1 + 1        # + 1 verifier + 1 hunter
    if budget < floor:
        return BudgetPlan(budget=budget, recon_calls=recon_calls,
                          critic_reserve=critic_reserve, verifier_reserve=0, hunters=0,
                          run_status="incomplete", incomplete_reason=REASON_NO_RECON,
                          notes=("budget %d cannot fund %d reconnaissance call(s), %d "
                                 "critic reserve, one verifier and one hunter (needs %d)"
                                 % (budget, recon_calls, critic_reserve, floor),))
    available = budget - max(spent, recon_calls) - critic_reserve
    verifier_reserve = max(1, int(expected_candidates),
                           int(math.ceil(0.30 * available)))
    verifier_reserve = min(verifier_reserve, max(1, available - 1),
                           int(caps.max_verifiers))
    hunters = min(int(caps.max_hunters), int(cluster_count), available - verifier_reserve)
    if hunters < 1:
        hunters = 0
        notes.append("no hunter fits beside the critic and validation reserves; every "
                     "planned unit is deferred with reason %s" % REASON_RESERVES)
    elif cluster_count > hunters:
        notes.append("%d cluster(s) ranked below the hunting allowance of %d are "
                     "deferred with reason %s" % (cluster_count - hunters, hunters,
                                                  REASON_RESERVES))
    return BudgetPlan(budget=budget, recon_calls=recon_calls,
                      critic_reserve=critic_reserve, verifier_reserve=verifier_reserve,
                      hunters=hunters, run_status="running", incomplete_reason="",
                      notes=tuple(notes))


def critic_reserve_lost(plan):
    """SKILL.md:132: later facts ate the required final-critic reserve."""
    return replace(plan, hunters=0, run_status="incomplete",
                   incomplete_reason=REASON_CRITIC,
                   notes=plan.notes + ("the reserved final critic call was consumed; no "
                                       "hunter launches and no coverage claim is made",))


def apply_budget(ledger, assignments, plan):
    """Launch the first `plan.hunters` assignments; defer the rest, with the reason.

    This is the honest half of the coverage floor. On a medium PR the floor exceeds what
    the hunter budget can reach, so the overflow becomes `deferred` with the skill's
    exact reason and is listed by `not_reviewed()`. It is never dropped.
    """
    launched = tuple(assignments[:max(0, plan.hunters)]) if plan.launches else ()
    deferred = []
    for assignment in assignments[len(launched):]:
        for coverage_id in assignment.coverage_ids:
            unit = ledger.get(coverage_id)
            if unit.status != "planned":
                continue
            reason = REASON_RESERVES
            if plan.incomplete_reason:
                reason = plan.incomplete_reason
            ledger.defer(coverage_id, reason)
            deferred.append(coverage_id)
    for assignment in launched:
        for coverage_id in assignment.coverage_ids:
            ledger.assign(coverage_id, assignment.agent_id)
    return launched, tuple(deferred)


def defer_untouched(ledger, reason=REASON_RESERVES):
    """After the wave, a unit nobody closed is deferred, never left mid-flight."""
    out = []
    for unit in ledger.by_status("planned", "in_progress"):
        if unit.status == "in_progress":
            _apply(unit, "planned")
        ledger.defer(unit.coverage_id, reason)
        out.append(unit.coverage_id)
    return tuple(out)


def validation_plan(fingerprints, remaining):
    """SKILL.md:134: validate in fingerprint order while the budget permits.

    Returns (to_verify, unverified). The caller records `validation_budget_exhausted` on
    the units still holding an unverified fingerprint and never reports the run complete.
    """
    ordered = tuple(sorted(_dedupe(fingerprints)))
    limit = max(0, int(remaining))
    return ordered[:limit], ordered[limit:]


def mark_unvalidated(ledger, fingerprints, reason=REASON_VALIDATION):
    """Keep every unvalidated fingerprint attached to its `candidate` unit."""
    wanted = set(fingerprints)
    touched = []
    for unit in ledger.by_status("candidate"):
        if not wanted & set(unit.result_fingerprints):
            continue
        unit.unresolved = _dedupe(unit.unresolved + (reason,))
        touched.append(unit.coverage_id)
    return tuple(touched)
