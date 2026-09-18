"""Prior-run state: where it came from, how it is unpacked, and what it may change.

State from an earlier run is the one input to this action that an attacker can hope to
author, so this module is a trust boundary, not a cache layer. A fork pull request's run
must not be able to plant a bundle that a later run of the same pull request believes.

Three independent controls, in order:

1. PROVENANCE. An artifact is read only when `GET /actions/runs/{id}` shows it was
   produced by a run of the *trusted workflow definition* (`path` equals the path in
   `GITHUB_WORKFLOW_REF`), in this repository, from this repository's own head (never a
   fork), on an event whose definition GitHub takes from the default branch. For a PR
   state bundle that event is `pull_request_target`, whose workflow definition comes from
   the base of the pull request and never from its head (and, since the 2025-12-08
   change, always from the default branch). For a baseline bundle it may be `schedule`,
   `push` or `workflow_dispatch`, and then the run's `head_branch` must be the default
   branch as well -- a push to any other branch runs *that branch's* copy of the same
   path, which a contributor with write access controls.

   The design's "integrity anchor" (a sha256 marker in a `github-actions[bot]` comment)
   is deliberately NOT implemented. Every workflow's `GITHUB_TOKEN` posts as that same
   bot, so any same-repo writer could forge the marker -- either pinning an old bundle to
   resurrect an expired suppression, or forcing the real bundle to be read as
   "incompatible" so every carried lead is silently dropped. A control an attacker can
   write is not a control.

2. BOUNDED EFFECT. Provenance can fail; the blast radius is bounded so that it matters
   less if it does. Prior state can only do two things: suppress one byte-identical
   rejected claim, or ADD verifier work. It can never mark anything confirmed, never
   raise a severity (this run has none), never suppress a coverage unit, and never widen
   a budget or a path. Suppressions expire (`AgeLimits`), every one of them is listed in
   the summary, and in `mode: same-repo-only` the whole channel is switched off, because
   there the pull request under review controls the workflow that reviews it.

   Honest bound on poisoning, stated here because the design's original wording was
   wrong: prior content IS model-derived and a poisoned baseline `architecture.md` DOES
   reach hunters, since HUNTING.md:16 requires it verbatim in every hunter prompt. What
   that buys an attacker is false negatives and misrouting -- never a key, never code
   execution, never a fabricated "confirmed". The delta-reconnaissance call is the
   correction channel, and `MAX_BASELINE_AGE_DAYS` bounds how long a bad one survives.

3. SAFE UNPACKING. The zip is attacker-shaped bytes handed to a parser. Absolute paths,
   traversal, symlinks, device files, oversized members, lying size headers, duplicate
   names and compression bombs are all refused, and nothing is ever written outside one
   dedicated temporary directory.

On top of that this module applies the skill's prior-run rules (SKILL.md:96-105,
RECONNAISSANCE.md:61-71). Two of them are the reason this file exists at all: a prior
`needs_validation` record is never carried silently -- it is marked for re-verification
by a fresh verifier, which becomes its unit's owner (RECONNAISSANCE.md:67) -- and a prior
`rejected` record suppresses only that exact unchanged claim, never review of its unit
(RECONNAISSANCE.md:68). "Unchanged" is decided by comparing blob OIDs through
`SourceOracle`, never by trusting a stored source ref (SKILL.md:98).

The GitHub surface is injected, not imported, so nothing here reaches the network. The
caller passes any object with these three methods:

    list_artifacts(page, per_page) -> the `GET /repos/{repo}/actions/artifacts` body
    get_run(run_id)               -> the `GET /repos/{repo}/actions/runs/{id}` body
    download_artifact(artifact_id, max_bytes) -> the zip bytes

A carried `rejected` record has no candidate unit in the current ledger (its unit is
re-reviewed and usually closes `covered`), so `exempt_fingerprints()` hands the parent
exactly the set to subtract from `validate.check_fingerprint_parity`. Without that the
fingerprint-parity gate fails closed on the second push of any PR that had a rejection.
"""
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .fingerprint import FingerprintError, RenameMap

STATE_PREFIX = "ai-security-review-state-pr"
BASELINE_PREFIX = "ai-security-review-baseline"

KIND_STATE = "state"
KIND_BASELINE = "baseline"

# `pull_request_target` always runs the default-branch workflow definition, so a PR
# cannot edit the reviewer that produces its own prior state.
STATE_EVENTS = frozenset(("pull_request_target",))
# These three can run a non-default branch's copy of the same path, so they carry the
# extra `head_branch == default_branch` requirement in _check_run().
BASELINE_EVENTS = frozenset(("schedule", "push", "workflow_dispatch"))
BRANCH_PINNED_EVENTS = frozenset(("push", "workflow_dispatch"))

BUNDLE_FILES = frozenset((
    "run-metadata.json", "findings.json", "coverage-ledger.json", "architecture.md",
    "pr-annotations.json", "summary.md"))

MAX_BASELINE_AGE_DAYS = 14.0

BASELINE_DEVIATION = (
    "Reconnaissance consumed a prior `architecture.md` from the scheduled default-branch "
    "baseline run instead of spending this run's four reconnaissance calls "
    "(SKILL.md:123). This reuse is NOT part of the skill's sanctioned prior-run channel: "
    "RECONNAISSANCE.md:61 scopes that channel to `coverage-ledger.json` and "
    "`findings.json`, and RECONNAISSANCE.md:75 makes `architecture.md` a current-run "
    "synthesis. It is an action-authored deviation taken for cost, bounded by a maximum "
    "age of %.0f days and corrected by the delta-reconnaissance call.")

TRUST_BOUND = (
    "Prior-run state is accepted only from a run of the trusted workflow definition in "
    "this repository, on an event whose definition GitHub takes from the default branch. "
    "Its content is still model-derived: a poisoned baseline can cause missed findings "
    "and misrouting, and it does reach hunters through `architecture.md`. It can never "
    "produce a confirmed finding, a severity, a secret or code execution. Its only "
    "suppressing power is one byte-identical rejected claim, which expires.")


class StateError(Exception):
    """Raised when prior state cannot be used. The run continues without it, and says so."""


class UnsafeArchive(StateError):
    """Raised for an archive member that must never be written to disk."""


# ------------------------------------------------------------------------ provenance

@dataclass(frozen=True)
class Provenance:
    """What a workflow run must prove before this run reads a byte of its artifact."""
    repository: str
    workflow_path: str
    default_branch: str = "main"
    # False under `mode: same-repo-only`, where the PR controls its own reviewer.
    trusted: bool = True


@dataclass(frozen=True)
class Candidate:
    """One artifact that passed the provenance filter."""
    artifact_id: int
    name: str
    run_id: int
    kind: str
    event: str
    created_at: str
    head_sha: str
    head_branch: str
    size_bytes: int = 0


@dataclass(frozen=True)
class Discovery:
    accepted: tuple = ()
    rejected: tuple = ()          # (name, artifact_id, reason)

    @property
    def newest(self):
        return self.accepted[0] if self.accepted else None


def workflow_path(workflow_ref, repository=""):
    """`owner/repo/.github/workflows/x.yml@refs/heads/main` -> `.github/workflows/x.yml`."""
    path = (workflow_ref or "").split("@", 1)[0].strip()
    if repository and path.startswith(repository + "/"):
        return path[len(repository) + 1:]
    parts = path.split("/", 2)
    return parts[2] if len(parts) == 3 else path


def artifact_prefix(kind, pr_number=None):
    if kind == KIND_BASELINE:
        return BASELINE_PREFIX
    if pr_number is None:
        raise StateError("a state artifact prefix needs the pull-request number")
    return "%s%d" % (STATE_PREFIX, int(pr_number))


def _name_matches(name, prefix):
    # upload-artifact v4 refuses a duplicate name per run, so the workflow appends
    # `-<run_id>-<run_attempt>`; the separator keeps `...-pr1` from matching `...-pr12`.
    return name == prefix or name.startswith(prefix + "-")


def _full_name(value):
    if isinstance(value, dict):
        return value.get("full_name") or ""
    return value or ""


def _check_run(artifact, run, prov, kind):
    """Return the rejection reason, or "" when the run is a trusted producer."""
    if not prov.trusted:
        return "prior-state trust is disabled (same-repo-only mode)"
    if not isinstance(run, dict) or not run:
        return "workflow run could not be read"
    if artifact.get("expired"):
        return "artifact has expired"
    run_id = run.get("id")
    linked = (artifact.get("workflow_run") or {}).get("id")
    if linked is not None and run_id is not None and int(linked) != int(run_id):
        return "artifact is linked to run %s, not %s" % (linked, run_id)
    if run.get("status") != "completed":
        return "run status is %r, not 'completed'" % (run.get("status"),)
    if run.get("conclusion") != "success":
        return "run conclusion is %r, not 'success'" % (run.get("conclusion"),)
    path = run.get("path") or ""
    if not prov.workflow_path:
        return "the trusted workflow path is unknown; refusing every artifact"
    if path != prov.workflow_path:
        return ("produced by workflow %r, not the trusted definition %r"
                % (path, prov.workflow_path))
    if _full_name(run.get("repository")) != prov.repository:
        return ("produced in repository %r, not %r"
                % (_full_name(run.get("repository")), prov.repository))
    head_repo = _full_name(run.get("head_repository"))
    if head_repo and head_repo != prov.repository:
        # A fork PR's own run: exactly the producer this filter exists to refuse.
        return "produced from head repository %r, not %r" % (head_repo, prov.repository)
    event = run.get("event") or ""
    allowed = STATE_EVENTS if kind == KIND_STATE else BASELINE_EVENTS
    if event not in allowed:
        return ("produced by a %r run; only %s runs use the default-branch workflow "
                "definition here" % (event, "/".join(sorted(allowed))))
    if event in BRANCH_PINNED_EVENTS or kind == KIND_BASELINE:
        branch = run.get("head_branch") or ""
        if branch != prov.default_branch:
            # A push to any other branch runs that branch's copy of the same path.
            return "produced from branch %r, not the default branch %r" % (
                branch, prov.default_branch)
    return ""


def _created_key(entry):
    return (entry.get("created_at") or "", int(entry.get("id") or 0))


def discover(source, prov, kind, pr_number=None, pages=3, per_page=100, limit=10):
    """List artifacts newest first and keep only those a trusted run produced."""
    prefix = artifact_prefix(kind, pr_number)
    seen, accepted, rejected = {}, [], []
    for page in range(1, max(1, int(pages)) + 1):
        body = source.list_artifacts(page=page, per_page=per_page) or {}
        entries = body.get("artifacts") or []
        for entry in entries:
            if isinstance(entry, dict) and _name_matches(entry.get("name") or "", prefix):
                seen[int(entry.get("id") or 0)] = entry
        if len(entries) < per_page:
            break

    for entry in sorted(seen.values(), key=_created_key, reverse=True):
        if len(accepted) >= limit:
            break
        run_id = (entry.get("workflow_run") or {}).get("id")
        run = {}
        if run_id is not None:
            try:
                run = source.get_run(int(run_id)) or {}
            except Exception as exc:                       # an API failure is not trust
                rejected.append((entry.get("name"), entry.get("id"),
                                 "workflow run %s could not be read: %s"
                                 % (run_id, type(exc).__name__)))
                continue
        reason = _check_run(entry, run, prov, kind)
        if reason:
            rejected.append((entry.get("name"), entry.get("id"), reason))
            continue
        accepted.append(Candidate(
            artifact_id=int(entry.get("id")), name=entry.get("name") or "",
            run_id=int(run.get("id") or run_id or 0), kind=kind,
            event=run.get("event") or "", created_at=entry.get("created_at") or "",
            head_sha=run.get("head_sha") or "", head_branch=run.get("head_branch") or "",
            size_bytes=int(entry.get("size_in_bytes") or 0)))
    return Discovery(accepted=tuple(accepted), rejected=tuple(rejected))


# ---------------------------------------------------------------------- safe unzip

@dataclass(frozen=True)
class UnzipLimits:
    members: int = 64
    member_bytes: int = 8 * 1024 * 1024
    total_bytes: int = 20 * 1024 * 1024
    # Bundle members are JSON and Markdown, which compress well but not 200:1.
    ratio: int = 200
    ratio_floor: int = 64 * 1024
    name_bytes: int = 200
    chunk_bytes: int = 64 * 1024


_BAD_NAME = re.compile(r"[\x00-\x1f\x7f\\]")
_DRIVE = re.compile(r"^[A-Za-z]:")


def _check_member_name(name, limits):
    """Refuse every name that could place a file outside the destination directory."""
    if not name or name in (".", ".."):
        return "empty or dot member name"
    if len(name.encode("utf-8")) > limits.name_bytes:
        return "member name is longer than %d bytes" % limits.name_bytes
    if _BAD_NAME.search(name):
        return "member name contains a backslash or a control character"
    if name.startswith("/") or _DRIVE.match(name):
        return "absolute member name %r" % name
    for part in name.split("/"):
        if part == "..":
            return "member name traverses upward: %r" % name
    return ""


def _member_mode(info):
    """The POSIX file type a zip entry declares, or 0 when it declares none."""
    return (info.external_attr >> 16) & 0o170000


def safe_extract(data, dest_dir, allowed=BUNDLE_FILES, limits=UnzipLimits()):
    """Unpack a bundle zip into `dest_dir` and nowhere else. Returns {name: path}.

    Unsafe members raise; merely unknown ones are skipped, so the traversal, symlink and
    bomb checks stay meaningful instead of being masked by the name allowlist.
    """
    root = os.path.realpath(dest_dir)
    os.makedirs(root, exist_ok=True)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise StateError("prior bundle is not a readable zip: %s" % exc)

    with archive:
        infos = archive.infolist()
        if len(infos) > limits.members:
            raise UnsafeArchive("archive declares %d members, over the %d cap"
                                % (len(infos), limits.members))
        declared = sum(max(0, info.file_size) for info in infos)
        packed = sum(max(0, info.compress_size) for info in infos)
        if declared > limits.total_bytes:
            raise UnsafeArchive("archive declares %d uncompressed bytes, over the %d cap"
                                % (declared, limits.total_bytes))
        if declared > limits.ratio_floor and packed > 0 and declared // packed > limits.ratio:
            raise UnsafeArchive("archive compression ratio %d:1 is over the %d:1 cap"
                                % (declared // packed, limits.ratio))

        written, total, names = {}, 0, set()
        for info in infos:
            name = info.filename
            problem = _check_member_name(name, limits)
            if problem:
                raise UnsafeArchive(problem)
            if name in names:
                raise UnsafeArchive("duplicate member name %r" % name)
            names.add(name)
            if info.is_dir():
                continue
            mode = _member_mode(info)
            if mode and not stat.S_ISREG(mode):
                # Symlinks, fifos and device nodes: never materialised, never followed.
                raise UnsafeArchive("member %r is not a regular file (mode 0o%o)"
                                    % (name, mode))
            if info.file_size > limits.member_bytes:
                raise UnsafeArchive("member %r declares %d bytes, over the %d cap"
                                    % (name, info.file_size, limits.member_bytes))
            if (info.file_size > limits.ratio_floor and info.compress_size > 0
                    and info.file_size // info.compress_size > limits.ratio):
                raise UnsafeArchive("member %r compression ratio %d:1 is over the %d:1 cap"
                                    % (name, info.file_size // info.compress_size,
                                       limits.ratio))
            if name not in allowed:
                continue
            total += _extract_member(archive, info, root, limits, total)
            written[name] = os.path.join(root, name)
    return written


def _extract_member(archive, info, root, limits, total_so_far):
    """Stream one member out, enforcing the caps against real bytes, not the header."""
    target = os.path.join(root, info.filename)
    resolved = os.path.realpath(target)
    if resolved != root and not resolved.startswith(root + os.sep):
        raise UnsafeArchive("member %r resolves outside the extraction directory"
                            % info.filename)
    written = 0
    # Opened by the unresolved path with O_NOFOLLOW and O_EXCL, so a symlink planted at
    # the target is refused outright rather than written through -- the containment check
    # above only proves where it would have pointed.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with archive.open(info, "r") as member, os.fdopen(fd, "wb") as out:
            fd = None
            while True:
                chunk = member.read(limits.chunk_bytes)
                if not chunk:
                    break
                written += len(chunk)
                if written > limits.member_bytes:
                    raise UnsafeArchive("member %r exceeds %d bytes while unpacking; the "
                                        "size header lied" % (info.filename,
                                                              limits.member_bytes))
                if total_so_far + written > limits.total_bytes:
                    raise UnsafeArchive("archive exceeds %d bytes while unpacking"
                                        % limits.total_bytes)
                out.write(chunk)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    return written


# -------------------------------------------------------------------- bundle parsing

@dataclass(frozen=True)
class PriorBundle:
    candidate: object = None
    metadata: dict = field(default_factory=dict)
    findings: tuple = ()
    units: tuple = ()
    architecture: str = ""
    files: dict = field(default_factory=dict)
    compatible: bool = True
    reason: str = ""

    @property
    def head_sha(self):
        return self.metadata.get("head_sha") or ""

    @property
    def profile(self):
        return self.metadata.get("profile") or ""


def _load_json(path, expect):
    with open(path, "r", encoding="utf-8", errors="strict") as handle:
        value = json.load(handle)
    if not isinstance(value, expect):
        raise StateError("%s holds %s, expected %s"
                         % (os.path.basename(path), type(value).__name__,
                            expect.__name__))
    return value


def read_bundle(files, candidate=None, validate=None, expect_pr=None):
    """Parse an extracted bundle. An unparsable or invalid one is INCOMPATIBLE, not empty.

    RECONNAISSANCE.md:69 is explicit: record a missing or incompatible ledger rather than
    treating it as empty coverage, which would quietly turn a gap into "reviewed".
    """
    incompatible = lambda why: PriorBundle(candidate=candidate, files=dict(files),
                                           compatible=False, reason=why)
    if "run-metadata.json" not in files:
        return incompatible("bundle has no run-metadata.json")
    try:
        metadata = _load_json(files["run-metadata.json"], dict)
        findings = _load_json(files["findings.json"], list) if "findings.json" in files else []
        units = (_load_json(files["coverage-ledger.json"], list)
                 if "coverage-ledger.json" in files else [])
    except (OSError, ValueError, StateError) as exc:
        return incompatible("bundle could not be parsed: %s" % exc)

    if expect_pr is not None and metadata.get("pr_number") not in (None, expect_pr):
        return incompatible("bundle belongs to PR #%s, not #%s"
                            % (metadata.get("pr_number"), expect_pr))
    findings = tuple(r for r in findings if isinstance(r, dict))
    units = tuple(u for u in units if isinstance(u, dict))
    if validate is not None:
        errors = validate(findings, units)
        if errors:
            return incompatible("prior bundle fails the vendored validators: %s"
                                % "; ".join(str(e) for e in list(errors)[:3]))

    architecture = ""
    if "architecture.md" in files:
        try:
            with open(files["architecture.md"], "r", encoding="utf-8",
                      errors="replace") as handle:
                architecture = handle.read()
        except OSError as exc:
            return incompatible("architecture.md could not be read: %s" % exc)
    return PriorBundle(candidate=candidate, metadata=metadata, findings=findings,
                       units=units, architecture=architecture, files=dict(files))


def fetch(source, candidate, dest_dir, limits=UnzipLimits(), allowed=BUNDLE_FILES,
          validate=None, expect_pr=None):
    """Download, unpack and parse one accepted candidate."""
    data = source.download_artifact(candidate.artifact_id, max_bytes=limits.total_bytes)
    if not isinstance(data, (bytes, bytearray)):
        raise StateError("artifact download returned %s" % type(data).__name__)
    if len(data) > limits.total_bytes:
        raise UnsafeArchive("artifact zip is %d bytes, over the %d cap"
                            % (len(data), limits.total_bytes))
    files = safe_extract(bytes(data), dest_dir, allowed=allowed, limits=limits)
    return read_bundle(files, candidate=candidate, validate=validate, expect_pr=expect_pr)


# ------------------------------------------------------------------- unchanged source

class SourceOracle:
    """Answers "is this cited path byte-identical between the prior head and this one?".

    By blob OID, never by a stored source ref: SKILL.md:98 says plainly that "a prior
    source ref alone is not evidence that a path is unchanged". The rename map is applied
    first, so a file that only moved still compares equal and keeps its fingerprint.
    """

    def __init__(self, prior_oids=None, head_oids=None, renames=None):
        self.prior = dict(prior_oids or {})
        self.head = dict(head_oids or {})
        self.renames = renames if renames is not None else RenameMap()

    def current_path(self, path):
        return self.renames.current(path)

    def unchanged(self, path):
        before = self.prior.get(path)
        after = self.head.get(self.renames.current(path))
        return bool(before) and before == after

    def all_unchanged(self, paths):
        paths = [p for p in paths if p]
        if not paths:
            return False           # a claim citing nothing cannot prove itself unchanged
        return all(self.unchanged(path) for path in paths)

    def changed_paths(self, paths):
        return tuple(p for p in paths if p and not self.unchanged(p))


def cited_paths(record):
    """Every repository path a record's trace and evidence rest on."""
    paths = []
    for key in ("trace", "evidence"):
        for step in record.get(key) or []:
            if isinstance(step, dict) and isinstance(step.get("file"), str):
                paths.append(step["file"])
    seen, out = set(), []
    for path in paths:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return tuple(out)


# ----------------------------------------------------------------- prior-run planning

@dataclass(frozen=True)
class AgeLimits:
    """A suppression is a promise made about code nobody has re-read since."""
    max_pushes: int = 5
    max_days: float = 7.0


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    prior_fingerprint: str
    record: dict
    since: str
    pushes: int
    active: bool
    reason: str


@dataclass(frozen=True)
class Carry:
    """A prior lead linked to a current planned unit for mandatory re-verification."""
    fingerprint: str
    prior_fingerprint: str
    record: dict
    coverage_id: str
    prior_status: str
    paths: tuple
    reason: str
    requires_reverification: bool = True


@dataclass(frozen=True)
class PriorPlan:
    compatible: bool = False
    unit_status: dict = field(default_factory=dict)
    canonical_refs: dict = field(default_factory=dict)
    suppressed: tuple = ()
    expired: tuple = ()
    reverify: tuple = ()
    changed: tuple = ()
    notes: tuple = ()

    def exempt_fingerprints(self):
        """Fingerprints findings.json carries with no candidate unit of their own.

        A suppressed rejected record is retained (VALIDATION-AND-REPORTING.md:101) while
        its unit is re-reviewed and normally closes `covered`, whose result_fingerprints
        the ledger validator requires to be empty. Both sides of
        `validate.check_fingerprint_parity` must subtract these or the run fails closed.
        """
        return tuple(sorted(s.fingerprint for s in self.suppressed))

    def suppression_history(self):
        """What this run writes into run-metadata.json for the next one to age."""
        return [{"fingerprint": s.prior_fingerprint, "since": s.since, "pushes": s.pushes}
                for s in self.suppressed]


_UNIT_STATUS = {
    "blocked": "prior_blocked",
    "deferred": "prior_deferred",
    "out_of_scope": "prior_out_of_scope",
    "planned": "prior_deferred",         # never reached last run: a gap, so current work
    "in_progress": "prior_deferred",
    "not_applicable": "none",
}


def _now(now):
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return _parse_time(str(now)) or datetime.now(timezone.utc)


def _parse_time(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _history(metadata):
    table = {}
    for entry in metadata.get("suppressions") or []:
        if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
            table[entry["fingerprint"]] = entry
    return table


def plan_prior(bundle, oracle, now=None, age=AgeLimits(), renames=None):
    """Turn a trusted prior bundle into this run's carries, suppressions and unit states."""
    renames = renames if renames is not None else getattr(oracle, "renames", RenameMap())
    if bundle is None:
        return PriorPlan(notes=("No prior run state was found; this is a first pass over "
                                "this pull request.",))
    if not bundle.compatible:
        return PriorPlan(notes=("Prior run state was found but is incompatible (%s). It is "
                                "recorded as incompatible, not as empty coverage "
                                "(RECONNAISSANCE.md:69)." % bundle.reason,))

    moment = _now(now)
    history = _history(bundle.metadata)
    fallback_since = (bundle.metadata.get("generated_at")
                      or getattr(bundle.candidate, "created_at", "") or "")
    suppressed, expired, reverify, changed, notes = [], [], [], [], []

    for record in bundle.findings:
        prior_fp = record.get("fingerprint")
        verdict = record.get("verdict")
        if not isinstance(prior_fp, str) or not prior_fp:
            continue
        try:
            fingerprint = renames.translate(prior_fp)
        except FingerprintError:
            fingerprint = prior_fp          # a foreign scheme keeps its own bytes
        paths = cited_paths(record)
        current = tuple(oracle.current_path(p) for p in paths)
        unchanged = oracle.all_unchanged(paths)

        if verdict == "rejected":
            if not unchanged:
                changed.append(fingerprint)
                notes.append("Prior rejection %s no longer applies: %s changed."
                             % (fingerprint, ", ".join(oracle.changed_paths(paths))
                                or "its cited source"))
                continue
            entry = history.get(prior_fp) or {}
            since = entry.get("since") or fallback_since
            pushes = int(entry.get("pushes") or 0) + 1
            stale, why = _aged_out(since, pushes, moment, age)
            record_age = Suppression(fingerprint=fingerprint, prior_fingerprint=prior_fp,
                                     record=record, since=since, pushes=pushes,
                                     active=not stale, reason=why)
            if stale:
                expired.append(record_age)
                notes.append("Suppression %s aged out (%s); the claim is open again."
                             % (fingerprint, why))
            else:
                suppressed.append(record_age)
        elif verdict == "needs_validation":
            if not unchanged:
                changed.append(fingerprint)
                continue
            reverify.append(Carry(
                fingerprint=fingerprint, prior_fingerprint=prior_fp, record=record,
                coverage_id=_unit_for(bundle.units, prior_fp), paths=current,
                prior_status="prior_needs_validation",
                reason="prior needs_validation on unchanged source: a fresh verifier must "
                       "re-check it and becomes the unit's owner "
                       "(RECONNAISSANCE.md:67); it is never carried silently."))
        elif verdict == "confirmed":
            # Nothing in this action can produce or re-establish `confirmed`.
            changed.append(fingerprint)
            notes.append("Prior confirmed record %s is revalidation work; this run has no "
                         "execution lane and cannot carry a confirmed verdict." % fingerprint)

    verdicts = _lead_verdicts(bundle.findings, oracle)
    unit_status, refs = _unit_states(bundle.units, oracle, verdicts)
    notes.extend(_profile_notes(bundle))
    return PriorPlan(compatible=True, unit_status=unit_status, canonical_refs=refs,
                     suppressed=tuple(suppressed), expired=tuple(expired),
                     reverify=tuple(reverify), changed=tuple(sorted(set(changed))),
                     notes=tuple(notes))


def _aged_out(since, pushes, moment, age):
    if pushes > age.max_pushes:
        return True, "carried through %d pushes, over the cap of %d" % (pushes, age.max_pushes)
    started = _parse_time(since)
    if started is None:
        # An unreadable start date cannot be aged, so it does not get to suppress.
        return True, "the first-rejection timestamp %r is unreadable" % (since,)
    if moment - started > timedelta(days=age.max_days):
        return True, ("first rejected %s, over the cap of %.0f days"
                      % (started.date().isoformat(), age.max_days))
    return False, ("unchanged rejected claim, push %d of %d, first rejected %s"
                   % (pushes, age.max_pushes, started.date().isoformat()))


def _unit_for(units, fingerprint):
    for unit in units:
        if fingerprint in (unit.get("result_fingerprints") or []):
            return unit.get("coverage_id") or ""
    return ""


def _lead_verdicts(findings, oracle):
    """prior fingerprint -> the prior-status token its own unit should carry."""
    table = {}
    for record in findings:
        fingerprint = record.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            continue
        unchanged = oracle.all_unchanged(cited_paths(record))
        verdict = record.get("verdict")
        if verdict == "rejected":
            table[fingerprint] = ("prior_covered_same_source" if unchanged
                                  else "prior_rejected_claim_changed")
        elif verdict == "needs_validation":
            table[fingerprint] = "prior_needs_validation"
        elif verdict == "confirmed":
            table[fingerprint] = ("prior_confirmed_same_source" if unchanged
                                  else "prior_confirmed_changed_source")
    return table


# Lower wins when one candidate unit carried several leads: current work outranks a
# same-source re-pass, which is only a priority hint (SKILL.md:102).
_LEAD_RANK = ("prior_needs_validation", "prior_rejected_claim_changed",
              "prior_confirmed_changed_source", "prior_confirmed_same_source",
              "prior_covered_same_source")


def _unit_states(units, oracle, verdicts=None):
    """Prior unit statuses for ledger.seed(), plus canonical refs reused verbatim."""
    verdicts = verdicts or {}
    status, refs = {}, {}
    for unit in units:
        coverage_id = unit.get("coverage_id")
        if not isinstance(coverage_id, str) or not coverage_id:
            continue
        prior = unit.get("status")
        if prior == "covered":
            paths = tuple(unit.get("starting_paths") or [])
            status[coverage_id] = ("prior_covered_same_source"
                                   if oracle.all_unchanged(paths)
                                   else "prior_covered_changed_source")
        elif prior == "candidate":
            # A candidate unit's own leads say what it is now: a lead still needing
            # validation is current work, a rejection whose source moved is current work,
            # and an unchanged rejection is a same-source pass that only informs priority.
            carried = [verdicts[f] for f in unit.get("result_fingerprints") or []
                       if f in verdicts]
            status[coverage_id] = min(carried, key=_LEAD_RANK.index) if carried \
                else "prior_needs_validation"
        else:
            status[coverage_id] = _UNIT_STATUS.get(prior, "none")
        # RECONNAISSANCE.md:94 -- reusing the prior refs verbatim keeps coverage_ids stable.
        if isinstance(unit.get("canonical_refs"), dict):
            refs[coverage_id] = dict(unit["canonical_refs"])
    return status, refs


def _profile_notes(bundle):
    profile = bundle.profile or "unknown"
    return ("Prior ledger read at profile %r: it contributes its recorded evidence and "
            "gaps only, never an implied \"rest is fine\" (SKILL.md:103)." % profile,)


def suppresses(plan, fingerprint):
    """True when this run must drop a re-proposed claim before it reaches a verifier."""
    return any(s.fingerprint == fingerprint and s.active for s in plan.suppressed)


def carried_records(plan):
    """The prior rejected records findings.json retains (VALIDATION-AND-REPORTING.md:101)."""
    return tuple(dict(s.record, fingerprint=s.fingerprint) for s in plan.suppressed)


# ------------------------------------------------------------------------- baseline

@dataclass(frozen=True)
class Baseline:
    architecture: str = ""
    head_sha: str = ""
    generated_at: str = ""
    age_days: float = -1.0
    accepted: bool = False
    reason: str = ""
    deviation: str = ""


def load_baseline(bundle, now=None, max_age_days=MAX_BASELINE_AGE_DAYS):
    """Accept a scheduled default-branch `architecture.md`, or refuse it as stale.

    Reusing it is an action-authored deviation, not a skill-sanctioned channel; the
    register text says so instead of citing RECONNAISSANCE.md for it.
    """
    if bundle is None:
        return Baseline(reason="no baseline artifact passed the provenance filter")
    if not bundle.compatible:
        return Baseline(reason="baseline bundle is incompatible: %s" % bundle.reason)
    text = (bundle.architecture or "").strip()
    if not text:
        return Baseline(reason="baseline bundle carries no architecture.md")

    generated = bundle.metadata.get("generated_at") or getattr(
        bundle.candidate, "created_at", "")
    started = _parse_time(generated)
    if started is None:
        return Baseline(reason="baseline generation time %r is unreadable" % (generated,))
    age_days = (_now(now) - started).total_seconds() / 86400.0
    if age_days > max_age_days:
        return Baseline(head_sha=bundle.head_sha, generated_at=str(generated),
                        age_days=age_days,
                        reason="baseline is %.1f days old, over the %.0f-day maximum; "
                               "falling back to the four reconnaissance calls"
                               % (age_days, max_age_days))
    return Baseline(architecture=bundle.architecture, head_sha=bundle.head_sha,
                    generated_at=str(generated), age_days=age_days, accepted=True,
                    reason="baseline accepted, %.1f days old" % age_days,
                    deviation=BASELINE_DEVIATION % max_age_days)
