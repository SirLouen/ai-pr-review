"""Command line: analyze | publish | baseline | selftest | replay.

`analyze` is the only subcommand that talks to a model. It drives the phases in the order
the skill fixes -- P0 deterministic, P1 reconnaissance, P2 one hunter wave, P3 the
coverage critic, P4 independent verifiers, P5 the fail-closed gate, P6 a model-free
render -- and its one hard promise is that it always leaves a bundle behind. The publish
job never sees this process, only the bundle, so a run that crashed and a run that found
nothing have to be distinguishable there.

Exit status carries the same contract: 0 means the phases completed, 1 means a bundle was
written carrying `run_status: incomplete` and the exact reason, 2 means the inputs were
rejected before a run existed. Only the last case leaves no bundle, and the publish job's
own missing-bundle path is what reports it.
"""
import argparse
import hashlib
import json
import os
import sys

from . import config
from . import fingerprint as fp
from . import github as githubmod
from . import gitsrc
from . import ledger as ledgermod
from . import orchestrator
from . import prompts
from . import publish as publishmod
from . import render
from . import routing
from . import seeders
from . import skillpack
from . import state
from . import tools
from . import validate as validatemod
from .providers.deepseek import DeepSeekProvider
from .providers.replay import ReplayProvider

EXIT_OK = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2

REASON_CRASHED = "analyze_crashed_before_the_report"
REASON_SEEDING = "no_changed_path_can_be_represented"
REASON_NO_HUNT = "hunter_wave_produced_no_result"

# A cassette answers every request, so replay needs no credential. config.load() fails
# closed without one, and this literal is what satisfies it; it is never sent anywhere.
REPLAY_PLACEHOLDER = "replay-cassette-no-credential"

BUNDLE = "bundle"


def default_vendor_dir():
    """config owns where the vendored skill lives; publish and selftest need it too."""
    return config._default_vendor_dir()


# --------------------------------------------------------------------- argument types

def _pr_number(raw):
    if not raw.isdigit() or not 0 < int(raw) < 10 ** 9:
        raise argparse.ArgumentTypeError("pull request number must be 1..999999999, got %r"
                                         % raw[:40])
    return raw


def _sha(raw):
    if not config.SHA_RE.match(raw):
        raise argparse.ArgumentTypeError("expected a full 40-character lowercase sha, got %r"
                                         % raw[:60])
    return raw


def _repository(raw):
    if not config.REPO_RE.match(raw):
        raise argparse.ArgumentTypeError("expected owner/name, got %r" % raw[:80])
    return raw


def _models(raw):
    """Same shape config.load() parses, rejected here so nothing malformed reaches env."""
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        role, sep, model = part.partition("=")
        if not sep or role.strip() not in config.ROLES:
            raise argparse.ArgumentTypeError(
                "expected role=model with role in %s, got %r"
                % (", ".join(config.ROLES), part[:60]))
        if not config.MODEL_RE.match(model.strip()):
            raise argparse.ArgumentTypeError("malformed model name %r" % model.strip()[:60])
    return raw


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m prreview.security",
        description="Skill-based security reviewer for pull requests.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("analyze", "baseline", "replay"):
        child = sub.add_parser(name)
        child.add_argument("--repository", type=_repository)
        child.add_argument("--pr-number", type=_pr_number)
        child.add_argument("--head-sha", type=_sha)
        child.add_argument("--base-sha", type=_sha)
        child.add_argument("--models", type=_models)
        child.add_argument("--out-dir")
        child.add_argument("--vendor-dir")
        if name == "replay":
            child.add_argument("--cassette", required=True)

    pub = sub.add_parser("publish")
    pub.add_argument("--repository", type=_repository)
    pub.add_argument("--pr-number", type=_pr_number)
    pub.add_argument("--head-sha", type=_sha)
    pub.add_argument("--bundle")
    pub.add_argument("--vendor-dir")
    pub.add_argument("--fail-on", choices=("never", "any-lead"))

    check = sub.add_parser("selftest")
    check.add_argument("--vendor-dir")
    return parser


_ENV_FOR = {"repository": "SA_REPOSITORY", "pr_number": "SA_PR_NUMBER",
            "head_sha": "SA_HEAD_SHA", "base_sha": "SA_BASE_SHA", "models": "SA_MODELS",
            "out_dir": "SA_OUT_DIR", "vendor_dir": "SA_VENDOR_DIR"}


def apply_overrides(args, env):
    """A flag wins over the environment. Validation already happened in the parser."""
    for attribute, name in _ENV_FOR.items():
        value = getattr(args, attribute, None)
        if value:
            env[name] = value


# ------------------------------------------------------------------- outside the process

class Services:
    """Everything outside this process, in one object a test can replace wholesale.

    The GitHub client, the model provider and the git remote are the three things a test
    cannot exercise for real, and threading them separately through the driver is how one
    of them quietly stays live.
    """

    def __init__(self, token="", gh=None, provider=None, remote_url=None,
                 protocols=("https",), node="node"):
        self.token = token
        self._gh = gh
        self._provider = provider
        self.remote_url = remote_url
        self.protocols = tuple(protocols)
        self.node = node

    def has_github(self):
        return self._gh is not None or bool(self.token)

    def github(self, api=githubmod.API):
        if self._gh is not None:
            return self._gh
        if not self.token:
            return None
        return githubmod.GitHub(self.token, api=api)

    def provider(self, cfg, creds):
        if self._provider is not None:
            return self._provider
        if not creds.deepseek_key:
            raise config.ConfigError("no DeepSeek credential; the Claude adapter is not "
                                     "wired up yet, so DEEPSEEK_API_KEY is required")
        return DeepSeekProvider(creds.deepseek_key, timeout=cfg.caps.request_timeout_s,
                                allow_custom_base_url=cfg.allow_custom_base_url)

    def remote(self, cfg):
        return self.remote_url or "https://github.com/%s.git" % cfg.repository

    def pr_facts(self, cfg, notes):
        """Compare-API numbers for the size gate, read BEFORE anything is fetched.

        Without a token there are no numbers, so the gate cannot run here at all; that is
        recorded and the same gate runs again over the real diff once it is fetched.
        """
        gh = self.github(cfg.github_api)
        facts = {"changed_files": 0, "additions": 0, "deletions": 0, "commits": 1,
                 "private": False, "merge_base": cfg.base_sha, "gated": False}
        if gh is None:
            notes.append("no GitHub token: the pre-fetch PR size gate did not run")
            return facts
        try:
            pull = gh.pull_request(cfg.repository, cfg.pr_number)
        except githubmod.GitHubError as exc:
            notes.append("pre-fetch size gate skipped: %s" % exc)
            return facts
        facts.update(changed_files=int(pull.get("changed_files") or 0),
                     additions=int(pull.get("additions") or 0),
                     deletions=int(pull.get("deletions") or 0),
                     commits=max(1, int(pull.get("commits") or 1)),
                     private=bool(((pull.get("base") or {}).get("repo") or {}).get("private")),
                     gated=True)
        try:
            compare = gh.get("/repos/%s/compare/%s...%s"
                             % (cfg.repository, cfg.base_sha, cfg.head_sha))
            merge_base = (compare.get("merge_base_commit") or {}).get("sha")
        except githubmod.GitHubError as exc:
            notes.append("merge base falls back to the event's base sha: %s" % exc)
            merge_base = None
        if isinstance(merge_base, str) and config.SHA_RE.match(merge_base):
            facts["merge_base"] = merge_base
        return facts


# -------------------------------------------------------------------------- the bundle

class BundleWriter:
    """Collects the bundle and writes it once, whatever happened to the run.

    run-metadata.json is written last and carries a sha256 of every other file, because
    publish.verify_integrity refuses a bundle whose files it cannot account for.
    """

    def __init__(self, cfg, profile="quick", scope="diff"):
        self.cfg = cfg
        self.directory = os.path.join(cfg.out_dir, BUNDLE)
        self.profile = profile
        self.scope = scope
        self.parent = None
        self.validator = None
        self.status = orchestrator.COMPLETE
        self.reason = ""
        self.notes = []
        self.extra = {}
        self.files = {}

    def note(self, text):
        self.notes.append(text)

    def abort(self, reason, detail=""):
        self.status = orchestrator.INCOMPLETE
        self.reason = reason
        if detail:
            self.notes.append(detail)

    def add(self, name, payload):
        blob = payload if isinstance(payload, str) else json.dumps(payload, indent=1,
                                                                  sort_keys=True)
        self.files[name] = blob.encode("utf-8")

    def outcome(self):
        """The run's status, whether this writer or the orchestrator recorded it."""
        if self.status == orchestrator.INCOMPLETE or self.parent is None:
            return self.status, self.reason
        return self.parent.status, self.parent.reason

    def metadata(self):
        extra = dict(self.extra)
        extra.update({"profile": self.profile, "scope": self.scope,
                      "digests": {name: hashlib.sha256(blob).hexdigest()
                                  for name, blob in sorted(self.files.items())}})
        if self.parent is not None:
            if self.status == orchestrator.INCOMPLETE:
                self.parent.incomplete(self.reason, "")
            self.parent.notes.extend(self.notes)
            self.notes = []
            return self.parent.metadata(extra)
        data = {
            "run_id": self.cfg.run_id, "repo": self.cfg.repository,
            "pr_number": self.cfg.pr_number, "head_sha": self.cfg.head_sha,
            "base_sha": self.cfg.base_sha, "models": dict(self.cfg.models),
            "execution_policy": "source-only-no-execution",
            "run_status": self.status, "incomplete_reason": self.reason,
            "deviations": [], "notes": list(self.notes), "conversations": [],
            "unvalidated_fingerprints": [], "usd_spent": 0.0, "seconds": 0.0,
            "suppressions": [],
        }
        data.update(extra)
        return data

    def fallback(self):
        """What a run that never reached P6 still owes its reader.

        A bundle with no summary reads, on the pull request, as a run that found nothing.
        These files say what actually happened instead.
        """
        status, reason = self.outcome()
        self.files.setdefault("findings.json", b"[]\n")
        self.files.setdefault("coverage-ledger.json", b"[]\n")
        self.files.setdefault("inline.json", b"[]\n")
        if "summary.md" not in self.files:
            self.add("summary.md", render.framed_summary(
                "", run_id=self.cfg.run_id, head_sha=self.cfg.head_sha,
                run_status=status, incomplete_reason=reason))
        if "pr-annotations.json" not in self.files:
            self.add("pr-annotations.json",
                     {"version": 1, "run_id": self.cfg.run_id,
                      "head_sha": self.cfg.head_sha, "merge_base_sha": self.cfg.base_sha,
                      "execution_policy": "source-only-no-execution", "severity": None,
                      "run_status": status, "leads": []})

    def write(self):
        """Emit the bundle, run-metadata.json last so it can digest the rest."""
        self.fallback()
        os.makedirs(self.directory, exist_ok=True)
        payload = json.dumps(self.metadata(), indent=1, sort_keys=True).encode("utf-8")
        self.files["run-metadata.json"] = payload
        for name, blob in sorted(self.files.items()):
            with open(os.path.join(self.directory, name), "wb") as handle:
                handle.write(blob)
        return self.directory


# ------------------------------------------------------------------------ P0 helpers

def head_text(source, path):
    """File text at head, or "" for anything that is not readable text."""
    try:
        entry = gitsrc.read_path(source.repo, source.index_for("head"), path,
                                 caps=source.caps)
    except (gitsrc.GitError, gitsrc.PathError):
        return ""
    return entry.get("text", "") if entry.get("kind") == "text" else ""


def symbol_resolver(source, diff):
    """`fingerprint.enclosing_symbol` over each path's first changed line."""
    first = {}
    for entry in diff.get("files") or ():
        hunks = entry.get("hunks") or []
        first[entry.get("path", "")] = hunks[0].get("new_start", 1) if hunks else 1

    def resolve(path):
        return fp.enclosing_symbol(head_text(source, path), first.get(path, 1) or 1, path)
    return resolve


def patch_blobs(text):
    """Split a commit patch into (path, added-lines-only text).

    Only the added lines are kept: a line number inside a commit that a later commit
    reverted has no meaning at head, and the seeder re-reads head for anything still
    there. The path comes from the `+++ b/` header, which is enough for a flag that a
    hunter must still verify.
    """
    blobs, path, lines = [], "", []
    for line in (text or "").splitlines():
        if line.startswith("+++ "):
            if path and lines:
                blobs.append((path, "\n".join(lines)))
            target = line[4:].strip()
            path = target[2:] if target.startswith("b/") else ""
            lines = []
        elif line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    if path and lines:
        blobs.append((path, "\n".join(lines)))
    return blobs


def seeder_drafts(source, cfg):
    """Deterministic seeder flags: committed credentials and privileged workflows."""
    blobs, workflows = [], []
    for path in source.changed_paths():
        text = head_text(source, path)
        if not text:
            continue
        blobs.append({"commit": cfg.head_sha, "path": path, "text": text, "is_head": True})
        if routing.matches_any(path, routing.CI_GLOBS):
            workflows.append({"path": path, "text": text})
    for sha in source.commits:
        try:
            patch = gitsrc.commit_patch(source.repo, sha)
        except gitsrc.GitError:
            continue
        if not patch.get("available"):
            continue
        for path, text in patch_blobs(patch.get("text", "")):
            blobs.append({"commit": sha, "path": path, "text": text, "is_head": False})
    return seeders.run(commit_blobs=blobs, workflows=workflows)


# ------------------------------------------------------------------------ P2 helpers

def launched_assignments(parent):
    """`ledger.apply_budget` answers (launched, deferred); the parent stores the pair."""
    stored = getattr(parent, "assignments", ()) or ()
    if len(stored) == 2 and all(isinstance(half, tuple) for half in stored):
        return list(stored[0])
    return list(stored)


def sink_of(record):
    """The trace entry a fingerprint is built from: the sink, else the last citation."""
    entries = [e for e in (record.get("trace") or []) if isinstance(e, dict)]
    sinks = [e for e in entries if e.get("kind") == "sink"]
    chosen = sinks[-1] if sinks else (entries[-1] if entries else None)
    if chosen is None:
        evidence = [e for e in (record.get("evidence") or []) if isinstance(e, dict)]
        chosen = evidence[0] if evidence else {}
    line = chosen.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        line = 1
    return chosen.get("file") or "", line


def name_candidates(records, units, source, taken):
    """Attach the parent's fingerprint to each hunter candidate (HUNTING.md:153).

    A candidate that chose its own fingerprint would be choosing its own identity across
    runs, so the class comes from the unit it was hunted under and the sink from its own
    trace. `taken` carries variants across hunters: two hunters reaching the same sink
    must not collapse into one lead.
    """
    named, skipped = [], []
    for record in records:
        path, line = sink_of(record)
        unit = _unit_for_path(units, path)
        class_ref = getattr(unit, "ordinary_attack_class_block", None) if unit else None
        if not path or not class_ref:
            skipped.append(record)
            continue
        try:
            base = fp.for_sink(class_ref, path, head_text(source, path), line)
        except fp.FingerprintError:
            skipped.append(record)
            continue
        variant, value = 1, base
        while value in taken:
            variant += 1
            value = fp.build(class_ref, path, fp.parse(base)["symbol"], variant=variant)
        taken.add(value)
        record["fingerprint"] = value
        named.append((record, unit))
    return named, skipped


def _unit_for_path(units, path):
    for unit in units:
        if path in (unit.starting_paths or ()):
            return unit
    return units[0] if units else None


def close_wave(parent, hunted, source, taken, notes):
    """Turn each hunter's submission into ledger state and fingerprinted candidates."""
    candidates = []
    for assignment, result in hunted:
        payload = result.result or {}
        units = [parent.ledger.get(cid) for cid in assignment.coverage_ids]
        named, skipped = name_candidates(payload.get("records") or [], units, source, taken)
        if skipped:
            notes.append("%s proposed %d candidate(s) with no usable sink; a lead with no "
                         "sink cannot be fingerprinted and is not reported"
                         % (assignment.agent_id, len(skipped)))
        by_unit = {}
        for record, unit in named:
            by_unit.setdefault(unit.coverage_id, []).append(record["fingerprint"])
            candidates.append(record)
        _close_units(parent, assignment, payload.get("units") or [], by_unit, notes)
    ledgermod.defer_untouched(parent.ledger, ledgermod.REASON_RESERVES)
    return candidates


def _close_units(parent, assignment, submitted, by_unit, notes):
    evidence = {}
    for raw in submitted:
        if isinstance(raw, dict) and isinstance(raw.get("coverage_id"), str):
            evidence[raw["coverage_id"]] = raw
    for coverage_id in assignment.coverage_ids:
        raw = evidence.get(coverage_id, {})
        checks = _checks_from(assignment.agent_id, raw)
        fingerprints = by_unit.get(coverage_id, [])
        try:
            if fingerprints and checks:
                parent.ledger.close_candidate(coverage_id, assignment.agent_id, checks,
                                              fingerprints)
            elif checks:
                parent.ledger.close_covered(coverage_id, assignment.agent_id, checks)
            else:
                parent.ledger.defer(coverage_id, ledgermod.REASON_MALFORMED)
        except ledgermod.LedgerError as exc:
            notes.append("%s: %s" % (coverage_id, exc))
            try:
                parent.ledger.defer(coverage_id, ledgermod.REASON_MALFORMED)
            except ledgermod.LedgerError:
                pass


def _checks_from(owner, raw):
    checks = []
    for entry in raw.get("local_checks") or []:
        if not isinstance(entry, dict):
            continue
        try:
            checks.append(ledgermod.source_check(owner, entry.get("reviewed_paths") or [],
                                                 entry.get("invariant") or "",
                                                 entry.get("result") or ""))
        except ledgermod.LedgerError:
            continue          # one unusable check must not void the unit's other evidence
    return checks


# ---------------------------------------------------------------------------- the driver

class Prior:
    """What earlier runs contribute to this one. Empty means a first-run review."""

    def __init__(self, plan=None, baseline=None):
        self.plan = plan
        self.baseline = baseline

    @property
    def usable(self):
        return self.plan is not None and self.plan.compatible

    def unit_status(self):
        return dict(self.plan.unit_status) if self.usable else None

    def architecture(self):
        """The baseline architecture.md as a framed prompt input, or None.

        It is model-written prose from an earlier run, so prompts.py frames it as data
        and says it may imitate the parent; here it only has to be accepted and fresh.
        """
        base = self.baseline
        if base is None or not base.accepted or not base.architecture:
            return None
        digest = hashlib.sha256(base.architecture.encode("utf-8")).hexdigest()
        return prompts.Architecture(text=base.architecture, origin="baseline",
                                    commit=base.head_sha, sha256=digest,
                                    age_days=base.age_days)

    def suppresses(self, fingerprint):
        return self.usable and state.suppresses(self.plan, fingerprint)

    def reverify(self):
        """Prior needs_validation leads. Carried only through a fresh verifier, never as-is."""
        if not self.usable:
            return []
        out = []
        for carry in self.plan.reverify:
            record = dict(carry.record)
            record["fingerprint"] = carry.fingerprint
            out.append(record)
        return out

    def retained(self):
        """Prior rejected records findings.json keeps (VALIDATION-AND-REPORTING.md:101)."""
        return list(state.carried_records(self.plan)) if self.usable else []

    def exempt(self):
        return list(self.plan.exempt_fingerprints()) if self.usable else []

    def source_state(self):
        """fingerprint -> changed | unchanged, for the publish job's thread handling.

        publish resolves a thread only when the cited source changed. Anything left out
        is read there as "unknown", which never resolves -- so a lead that simply stopped
        being reported is not mistaken for one that was fixed.
        """
        if not self.usable:
            return {}
        out = {fingerprint: "changed" for fingerprint in self.plan.changed}
        for item in (self.plan.suppressed + self.plan.expired + self.plan.reverify):
            out.setdefault(item.fingerprint, "unchanged")
        return out

    def history(self):
        return list(self.plan.suppression_history()) if self.usable else []

    def notes(self):
        return list(self.plan.notes) if self.usable else []

    def baseline_label(self):
        base = self.baseline
        if base is None or not base.accepted:
            return ""
        return "architecture.md from %s, %.1f days old" % (base.head_sha[:7], base.age_days)


def load_prior(cfg, services, repo, diff, notes):
    """Prior-run state and the baseline, both optional and both untrusted until proven.

    Nothing here is fatal: a missing or rejected prior bundle means this run reviews as
    if it were the first, and says so. A prior claim is only suppressed or carried when
    its cited source is byte-identical by blob OID (SKILL.md:98), never by stored ref.
    """
    if not services.has_github():
        notes.append("no GitHub token: prior-run state and the baseline were not loaded")
        return Prior()
    source = githubmod.ArtifactSource(services.github(), cfg.repository)
    provenance = state.Provenance(repository=cfg.repository,
                                  workflow_path=state.workflow_path(cfg.workflow_ref,
                                                                    cfg.repository))
    scratch = os.path.join(cfg.out_dir, "prior")
    renames = state.RenameMap([(e["old_path"], e["path"]) for e in diff.get("files") or ()
                               if e.get("old_path") and e.get("old_path") != e.get("path")])
    try:
        plan = _prior_plan(cfg, services, repo, source, provenance, scratch, renames, notes)
        baseline = _baseline(source, provenance, scratch, notes)
    except Exception as exc:
        # Prior state is an optional input. Failing to read it must not cost the review:
        # the run falls back to first-run semantics, which are sound on their own, and
        # says so. Suppression only ever narrows a report, so losing it is the safe side.
        notes.append("prior-run state ignored after an unexpected error: %s"
                     % type(exc).__name__)
        return Prior()
    return Prior(plan=plan, baseline=baseline)


def _prior_plan(cfg, services, repo, source, provenance, scratch, renames, notes):
    try:
        found = state.discover(source, provenance, state.KIND_STATE,
                               pr_number=cfg.pr_number)
        candidate = found.newest
        if candidate is None:
            notes.append("no earlier trusted run for this pull request; first-run review")
            return None
        bundle = state.fetch(source, candidate, os.path.join(scratch, "state"),
                             expect_pr=cfg.pr_number)
    except (state.StateError, githubmod.GitHubError) as exc:
        notes.append("prior-run state ignored: %s" % exc)
        return None
    if not bundle.compatible:
        notes.append("prior-run state ignored: %s" % bundle.reason)
        return None

    prior_head = str(bundle.metadata.get("head_sha") or "")
    if not config.SHA_RE.match(prior_head):
        notes.append("prior-run state ignored: it records no usable head sha")
        return None
    try:
        # The earlier head is fetched so its blobs can be compared by OID. Without it
        # nothing could be shown unchanged, and nothing may be suppressed on a guess.
        gitsrc.fetch_commits(repo, services.remote(cfg), [(prior_head, 1)],
                             token=services.token, protocols=services.protocols,
                             caps=cfg.caps)
        prior_index = gitsrc.tree_index(repo, prior_head)
        head_index = gitsrc.tree_index(repo, cfg.head_sha)
    except gitsrc.GitError as exc:
        notes.append("prior-run state ignored: earlier head unavailable (%s)" % exc)
        return None

    cited = set()
    for record in bundle.findings:
        cited.update(state.cited_paths(record))
    prior_oids = {p: prior_index[p]["oid"] for p in cited if p in prior_index}
    head_oids = {}
    for path in cited:
        current = renames.current(path)
        if current in head_index:
            head_oids[current] = head_index[current]["oid"]
    oracle = state.SourceOracle(prior_oids, head_oids, renames)
    return state.plan_prior(bundle, oracle, renames=renames)


def _baseline(source, provenance, scratch, notes):
    try:
        found = state.discover(source, provenance, state.KIND_BASELINE)
        candidate = found.newest
        if candidate is None:
            return None
        bundle = state.fetch(source, candidate, os.path.join(scratch, "baseline"))
    except (state.StateError, githubmod.GitHubError) as exc:
        notes.append("baseline ignored: %s" % exc)
        return None
    baseline = state.load_baseline(bundle)
    if not baseline.accepted:
        notes.append("baseline ignored: %s" % baseline.reason)
    return baseline


def progress(message):
    """Progress to stderr, one line at a time. Counts, statuses and times only."""
    sys.stderr.write("[security-review] %s\n" % message)
    sys.stderr.flush()


def drive(cfg, creds, services, writer, recon_agents=None):
    """P0..P5. Returns (parent, report inputs). Raises RunAborted or whatever broke."""
    validator = validatemod.Validator(cfg.vendor_dir, node=services.node)
    writer.validator = validator
    skill = skillpack.SkillPack(cfg.vendor_dir)

    facts_pr = services.pr_facts(cfg, writer.notes)
    if facts_pr["gated"]:
        gitsrc.check_pr_size(cfg.caps, facts_pr["changed_files"], facts_pr["additions"],
                             facts_pr["deletions"])
    merge_base = facts_pr["merge_base"]

    progress("fetching %s @ %s" % (cfg.repository, cfg.head_sha[:12]))
    repo = gitsrc.open_repo(os.path.join(cfg.out_dir, "scratch"), caps=cfg.caps)
    gitsrc.fetch_pr(repo, services.remote(cfg), cfg.head_sha, merge_base,
                    facts_pr["commits"], token=services.token,
                    protocols=services.protocols, caps=cfg.caps)
    commits = gitsrc.commits_between(repo, merge_base, cfg.head_sha)["commits"]
    diff = gitsrc.diff_index(repo, merge_base, cfg.head_sha, caps=cfg.caps)
    # The pre-fetch gate reads numbers we do not control; this one reads the objects.
    gitsrc.check_pr_size(cfg.caps, len(diff.get("files") or []),
                         sum(int(e.get("added") or 0) for e in diff.get("files") or []),
                         sum(int(e.get("removed") or 0) for e in diff.get("files") or []))

    changes = orchestrator.routing_changes(repo, merge_base, cfg.head_sha, diff)
    unreportable = validator.screen_paths([change["path"] for change in changes])
    for entry in unreportable:
        writer.note("cannot be reported: %s (%s)" % (entry.path, entry.reason))

    source = tools.RepoSource(repo, cfg.head_sha, merge_base, commits=commits,
                              caps=cfg.caps)
    drafts = seeder_drafts(source, cfg)
    secret_facts = [d for d in drafts if d.get("seeder") == "secret-scan"]
    other_drafts = [d for d in drafts if d.get("seeder") != "secret-scan"]

    prior = load_prior(cfg, services, repo, diff, writer.notes)
    architecture = prior.architecture()
    # The budget gate must reserve exactly what reconnaissance will spend. Orchestrator.
    # recon registers each shortfall from the skill's four calls as a deviation.
    if recon_agents is not None:
        recon_calls = len(recon_agents)
    elif architecture is not None:
        recon_calls = 1
    else:
        recon_calls = len(orchestrator.PR_RECON_AGENTS)

    provider = services.provider(cfg, creds)
    parent = orchestrator.Orchestrator(cfg, provider, validator, source, skill,
                                       progress=progress)
    writer.parent = parent
    writer.prior = prior
    facts = prompts.RunFacts.from_config(cfg, skill_commit=skill.commit,
                                         commit_count=len(commits))
    parent.plan(diff, changes, len(commits), symbol_resolver(source, diff),
                prior=prior.unit_status(), recon_calls=recon_calls)
    progress("planned %d coverage unit(s) over %d changed file(s); %d hunter(s)"
             % (len(parent.ledger.units), len(changes), len(parent.assignments)))

    changed_paths = source.changed_paths()
    recon_results = parent.recon(facts, architecture=architecture, changed_paths=changed_paths,
                                 agents=recon_agents)
    if not recon_results:
        parent.notes.append("no reconnaissance agent returned a usable result; companion "
                            "selection rests on the parent's routing alone")
    # Recon's facts become the architecture summary every later agent receives.
    architecture = parent.architecture_from(recon_results, baseline=architecture)

    taken = set()
    launched = launched_assignments(parent)
    hunted = parent.hunt(facts, launched, architecture=architecture,
                         secret_facts=secret_facts, drafts=other_drafts)
    note_empty_wave(parent, launched, hunted)
    candidates = close_wave(parent, hunted, source, taken, parent.notes)

    # A prior rejection suppresses only that exact claim, and only while its cited source
    # is unchanged (RECONNAISSANCE.md:68); the unit itself was still re-hunted above.
    suppressed = [c for c in candidates if prior.suppresses(c.get("fingerprint", ""))]
    candidates = [c for c in candidates if not prior.suppresses(c.get("fingerprint", ""))]
    # A prior needs_validation lead is never carried as-is: it goes back through a fresh
    # verifier like any new candidate (RECONNAISSANCE.md:67, VAL:91).
    fresh = {c.get("fingerprint") for c in candidates}
    candidates += [r for r in prior.reverify() if r.get("fingerprint") not in fresh]
    writer.suppressed = suppressed

    parent.critique(facts, candidates, architecture=architecture)
    records = parent.verify(facts, candidates, architecture=architecture)
    records += prior.retained()
    gate, units = finalize(cfg, parent, source, records, node=services.node,
                           exempt=prior.exempt())
    return parent, diff, gate, units, facts_pr


def note_empty_wave(parent, launched, hunted):
    """A wave where no hunter returned anything is not a run that found nothing.

    Every unit is already deferred with a reason and listed under "not reviewed", but the
    run-level status is what the check and the publish job read first.
    """
    if launched and not hunted:
        parent.incomplete(REASON_NO_HUNT,
                          "%d hunter assignment(s) were launched and none returned a "
                          "result" % len(launched))


def finalize(cfg, parent, source, records, node="node", exempt=()):
    """P5: the fail-closed gate over the whole document. Quarantines, never voids.

    `exempt` covers retained prior rejections: findings.json keeps them while their unit
    is re-reviewed and usually closes covered, which may carry no fingerprint.
    """
    units = parent.ledger.document()
    gate = validatemod.final_gate(parent.validator, records, units, cfg.vendor_dir,
                                  line_count=source.line_counter("head"),
                                  exempt_fingerprints=list(parent.unvalidated) + list(exempt),
                                  node=node)
    if not gate.ok:
        parent.incomplete(orchestrator.REASON_GATE, "; ".join(gate.errors[:5]))
    return gate, units


def render_bundle(cfg, writer, parent, diff, gate, units, facts_pr, sarif_enabled=False):
    """P6: model-free render of everything the publish job is allowed to see."""
    prior = getattr(writer, "prior", None) or Prior()
    parent.notes.extend(prior.notes())
    disclosure = render.Disclosure(mode=cfg.disclosure, public=not facts_pr["private"])
    report = render.RunReport(
        repository=cfg.repository, pr_number=cfg.pr_number, head_sha=cfg.head_sha,
        merge_base_sha=facts_pr["merge_base"], findings=gate.findings, units=units,
        diff=render.DiffIndex(diff.get("files") or ()), disclosure=disclosure,
        omissions=parent.omissions(),
        not_reviewed=parent.ledger.not_reviewed(), deviations=parent.deviations,
        coverage=parent.ledger.coverage_summary(),
        # Keyed as render._method_section reads them; the earlier "budget" spelling
        # printed "7 of ?" and "$0.31 of $0.00 ceiling" on every summary.
        usage={"conversations": parent.spent(),
               "max_conversations": cfg.caps.max_conversations,
               "usd": round(parent.meter.spent, 4), "max_usd": cfg.caps.max_usd,
               "latency_s": round(parent.clock() - parent.started, 1),
               "models": dict(cfg.models)},
        run_status=parent.status, incomplete_reason=parent.reason,
        quarantined=gate.quarantined, unvalidated=parent.unvalidated,
        suppressed=[c.get("fingerprint", "") for c in getattr(writer, "suppressed", ())],
        baseline=prior.baseline_label(),
        profile=writer.profile, run_id=cfg.run_id)
    writer.add("findings.json", gate.findings)
    writer.add("coverage-ledger.json", units)
    writer.add("summary.md", render.summary_markdown(report))
    writer.add("inline.json", render.inline_comments(report, diff=report.diff))
    writer.add("pr-annotations.json", render.annotations_sidecar(report))
    document = render.sarif(report, enabled=sarif_enabled)
    if document is not None:
        writer.add("sarif.json", document)
    writer.extra.update({
        "quarantined_fingerprints": list(gate.quarantined_fingerprints),
        "withheld_fingerprints": [lead.fingerprint for lead in report.withheld],
        # Read back by publish (thread resolution) and by the next run (suppression age).
        "prior_source_state": prior.source_state(),
        "suppressions": prior.history(),
        "disclosure": disclosure.mode, "public": disclosure.public,
    })
    return report


def cmd_analyze(args, env, services=None, profile="quick", scope="diff", recon_agents=None,
                sarif_enabled=False):
    apply_overrides(args, env)
    try:
        cfg, creds = config.load(env)
    except config.ConfigError as exc:
        # No out_dir we can trust and no head sha publish would accept, so there is no
        # bundle to write: the publish job reports the absence instead.
        sys.stderr.write("::error::%s\n" % exc)
        return EXIT_USAGE
    # config.load() hands the token back in creds as it removes it from the environment,
    # so nothing here reads os.environ for a secret.
    services = services or Services(token=creds.github_token)
    services.token = services.token or creds.github_token
    writer = BundleWriter(cfg, profile=profile, scope=scope)
    status = EXIT_OK
    try:
        parent, diff, gate, units, facts_pr = drive(cfg, creds, services, writer,
                                                    recon_agents=recon_agents)
        render_bundle(cfg, writer, parent, diff, gate, units, facts_pr,
                      sarif_enabled=sarif_enabled)
        if parent.status != orchestrator.COMPLETE:
            status = EXIT_INCOMPLETE
    except orchestrator.RunAborted as exc:
        writer.abort(exc.reason, exc.detail)
        status = EXIT_INCOMPLETE
    except gitsrc.SizeGateError as exc:
        writer.abort(orchestrator.REASON_SIZE, str(exc))
        status = EXIT_INCOMPLETE
    except ledgermod.LedgerError as exc:
        writer.abort(REASON_SEEDING, str(exc))
        status = EXIT_INCOMPLETE
    except Exception as exc:
        # A crash must never look like a clean run, so every exception still produces a
        # bundle that says so. The message is ours or a stdlib error's; no credential can
        # reach it, because config.load() already removed them from the process.
        writer.abort(REASON_CRASHED, "%s: %s" % (type(exc).__name__, exc))
        status = EXIT_INCOMPLETE
    finally:
        try:
            writer.write()
        finally:
            if writer.validator is not None:
                writer.validator.close()
    if status != EXIT_OK:
        reason = writer.reason or (writer.parent.reason if writer.parent else "")
        sys.stderr.write("::warning::incomplete run: %s\n" % (reason or "unrecorded"))
    parent = writer.parent
    if parent is not None:
        progress("done: %s, %d conversation(s), $%.4f, %.0fs; bundle in %s"
                 % (parent.status, parent.spent(), parent.meter.spent,
                    parent.clock() - parent.started,
                    os.path.join(cfg.out_dir, BUNDLE)))
    return status


# ------------------------------------------------------------------------------ publish

def _identity(env):
    """What publish needs, validated with config's own patterns.

    config.load() cannot serve this job: it demands a model credential, and the publish
    job is defined by not having one.
    """
    repository = (env.get("SA_REPOSITORY") or "").strip()
    head_sha = (env.get("SA_HEAD_SHA") or "").strip()
    pr_number = (env.get("SA_PR_NUMBER") or "").strip()
    if not config.REPO_RE.match(repository):
        raise config.ConfigError("SA_REPOSITORY is missing or malformed")
    if not config.SHA_RE.match(head_sha):
        raise config.ConfigError("SA_HEAD_SHA is missing or malformed")
    if not pr_number.isdigit() or not 0 < int(pr_number) < 10 ** 9:
        raise config.ConfigError("SA_PR_NUMBER is missing or malformed")
    return repository, int(pr_number), head_sha


def cmd_publish(args, env, services=None):
    apply_overrides(args, env)
    try:
        repository, pr_number, head_sha = _identity(env)
    except config.ConfigError as exc:
        sys.stderr.write("::error::%s\n" % exc)
        return EXIT_USAGE
    token = env.get("SA_GITHUB_TOKEN", "")
    services = services or Services(token=token)
    services.token = services.token or token
    if not services.has_github():
        sys.stderr.write("::error::SA_GITHUB_TOKEN is required to publish\n")
        return EXIT_USAGE
    vendor_dir = args.vendor_dir or env.get("SA_VENDOR_DIR") or default_vendor_dir()
    bundle_dir = args.bundle or env.get("SA_BUNDLE_DIR") or \
        os.path.join(env.get("SA_OUT_DIR") or ".", BUNDLE)
    fail_on = args.fail_on or env.get("SA_FAIL_ON") or "never"
    validator = validatemod.Validator(vendor_dir, node=services.node)
    try:
        result = publishmod.run(services.github(), repository, pr_number, head_sha,
                                bundle_dir, validator, vendor_dir, fail_on=fail_on,
                                node=services.node)
    finally:
        validator.close()
    for message in result.messages:
        sys.stderr.write("::notice::%s\n" % message)
    # "blocked" means the bundle did not pass the publish-side gate. The check run stays
    # neutral either way, so failing the job here costs no merge and hides no failure.
    return EXIT_INCOMPLETE if result.status == "blocked" else EXIT_OK


# ----------------------------------------------------------------------------- selftest

def strict_schema_problems(definition, where):
    """DeepSeek strict mode rejects a schema it cannot enforce; find that here, not live."""
    problems = []
    if definition.get("type") == "object" or "properties" in definition:
        if definition.get("additionalProperties") is not False:
            problems.append("%s: object schema must set additionalProperties: false" % where)
        properties = definition.get("properties") or {}
        required = set(definition.get("required") or [])
        missing = sorted(set(properties) - required)
        if missing:
            problems.append("%s: strict mode requires every property; missing %s"
                            % (where, ", ".join(missing)))
        for name, child in sorted(properties.items()):
            problems.extend(strict_schema_problems(child, "%s.%s" % (where, name)))
    items = definition.get("items")
    if isinstance(items, dict):
        problems.extend(strict_schema_problems(items, "%s[]" % where))
    return problems


def cmd_selftest(args, env, services=None):
    """Fail fast on a misconfigured runner, before a single token is spent."""
    services = services or Services()
    vendor_dir = args.vendor_dir or env.get("SA_VENDOR_DIR") or default_vendor_dir()
    problems = []
    try:
        gitsrc.assert_git_version()
    except gitsrc.GitError as exc:
        problems.append(str(exc))
    try:
        pack = skillpack.SkillPack(vendor_dir)
        problems.extend(pack.verify_lock())
        for name in skillpack.SYSTEM_BLOCKS:
            if not pack.has(name):
                problems.append("skill block does not resolve: %s" % name)
    except skillpack.SkillPackError as exc:
        problems.append(str(exc))
    validator = validatemod.Validator(vendor_dir, node=services.node)
    try:
        validator.ping()
        if validator.validate_findings([]):
            problems.append("the vendored findings validator rejects an empty document")
    except validatemod.ValidationBridgeError as exc:
        problems.append(str(exc))
    finally:
        validator.close()
    for role in config.ROLES:
        for definition in tools.tool_definitions(role, strict=True):
            function = definition["function"]
            if not function.get("strict"):
                problems.append("%s/%s is not declared strict" % (role, function["name"]))
            problems.extend(strict_schema_problems(function["parameters"],
                                                   "%s/%s" % (role, function["name"])))
    for problem in problems:
        sys.stderr.write("::error::%s\n" % problem)
    if not problems:
        sys.stdout.write("selftest ok: vendored skill, node bridge and tool schemas\n")
    return EXIT_OK if not problems else EXIT_INCOMPLETE


# ------------------------------------------------------------------- baseline and replay

def cmd_baseline(args, env, services=None):
    """The scheduled default-branch audit.

    `scope` says `default-branch-delta`, not `repository`: this runs the same base..head
    machinery over two default-branch commits. A true whole-repository sweep needs a fetch
    plan that does not start from a commit pair, and claiming the wider scope in the
    metadata would make a later run's coverage arithmetic wrong.
    """
    return cmd_analyze(args, env, services=services, profile="standard",
                       scope="default-branch-delta",
                       recon_agents=prompts.RECON_AGENTS)


def cmd_replay(args, env, services=None):
    if not (env.get("DEEPSEEK_API_KEY") or env.get("ANTHROPIC_API_KEY")):
        env["DEEPSEEK_API_KEY"] = REPLAY_PLACEHOLDER
    services = services or Services(provider=ReplayProvider(args.cassette, mode="replay"))
    return cmd_analyze(args, env, services=services)


COMMANDS = {"analyze": cmd_analyze, "publish": cmd_publish, "baseline": cmd_baseline,
            "selftest": cmd_selftest, "replay": cmd_replay}


def main(argv=None, env=None, services=None):
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    return COMMANDS[args.command](args, os.environ if env is None else env,
                                  services=services)


if __name__ == "__main__":
    sys.exit(main())
