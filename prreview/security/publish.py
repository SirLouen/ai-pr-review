"""The trusted publish step: post a bundle the analyze job produced, or say why not.

This module holds the write token and no model key. The bundle it reads was built
in a job that had the model key, read attacker-controlled source and ran model
output through its own gates - so everything in it is untrusted input here, and is
re-checked before a single byte reaches the pull request:

  1. The bundle is loaded from an allowlist of file names with byte caps, its
     sha256 digests are checked against `run-metadata.json`, and both vendored
     validators plus the action's cross-checks run again over the findings and the
     ledger. Any failure and only an incomplete notice is posted.
  2. FRESHNESS. `run-metadata.head_sha` is compared against the head SHA GitHub
     reports for the pull request *right now*. It is deliberately not compared
     against the workflow input, which comes from the same event payload the
     analyze job read and would make the comparison a tautology. The check runs
     again immediately before every write, and `commit_id` on every review comment
     is pinned to the analysed head so a lead can never be anchored onto newer lines.
  3. Anchors are recomputed here from the live files API. The bundle's own anchor
     is only a hint; whether a line can carry a comment is GitHub's call. A 422
     falls back to a file-level comment - posted on its own, because `subject_type`
     is not accepted inside a review's `comments[]` array - and then to summary-only.
  4. Dedupe is by the fingerprint in the comment marker. A superseded comment is
     hidden as OUTDATED. A thread is resolved ONLY when the cited source actually
     changed: a lead that stops being reported while its cited blobs are untouched
     is a suspected suppression, not a fix, and resolving it would let an injected
     agent erase the visible record of a real lead.
  5. The check run is created `in_progress` from this trusted side before analyze
     starts, so a cancelled or killed analyze job leaves a visibly stuck check
     instead of silence. Its default conclusion is `neutral`; `fail-on` is opt-in
     and documented as unsafe to use as a required check, because prompt injection
     produces false negatives and a green check is therefore not a clean bill.

**Division of labour with render.py.** This module owns LIVE DATA and API calls; the
renderer owns anchor SELECTION and every string that reaches a GitHub surface. So:

  * publish fetches `GET /pulls/{n}/files`, builds a `render.DiffIndex` from those
    patches and asks `render.select_anchor` where each lead hangs. Design 6.3 wants
    the anchor computed in the publish job from live data - the DATA is live, the
    LOGIC is the renderer's, and there is exactly one implementation of it.
  * publish never sanitises. `render.sanitize_for_github` is not idempotent - it
    escapes `&` into `&amp;` - so a second pass here would post the renderer's own
    markdown as its escape sequence. Instead publish VERIFIES: every string it posts
    must pass `render.inert_problems` and `render.framing_problems`, and a body that
    fails is handed back to `render.rebuild_lead_body` rather than patched up here.
    Nothing in this file composes lead text.

`inline.json` is the authority on *what may be posted at all*: the disclosure mode
withholds leads at render time while leaving them in `findings.json` for the
validators, so publishing from `findings.json` would undo the withholding. No
`inline.json` means no inline comments.
"""
import datetime
import hashlib
import json
import os
import re

from . import github
from . import render
from . import validate


class PublishError(Exception):
    """The publish step cannot proceed safely. Nothing is posted but the notice."""


class Superseded(Exception):
    """The pull request moved to a new head. Stale lead text must not be posted."""


CHECK_NAME = "AI security review (partial)"

MAX_EXISTENCE_CHECKS = 25

BUNDLE_FILES = {
    "run-metadata.json": 4 * 1024 * 1024,
    "findings.json": 4 * 1024 * 1024,
    "coverage-ledger.json": 4 * 1024 * 1024,
    "summary.md": 512 * 1024,
    "inline.json": 2 * 1024 * 1024,
    "pr-annotations.json": 2 * 1024 * 1024,
    "architecture.md": 512 * 1024,
    "REPORT.md": 512 * 1024,
    "NEEDS-VALIDATION.md": 512 * 1024,
    "usage.json": 256 * 1024,
    "sarif.json": 8 * 1024 * 1024,
}
REQUIRED_FILES = ("run-metadata.json", "findings.json", "coverage-ledger.json")


# ------------------------------------------------------------------------ bundle

class Bundle:
    """The downloaded artifact, parsed and nothing more. Still untrusted."""

    def __init__(self, directory, files, metadata, findings, units, inline, summary,
                 annotations=None):
        self.directory = directory
        self.files = files           # name -> the raw bytes actually read
        self.metadata = metadata
        self.findings = findings
        self.units = units
        self.inline = inline
        self.summary = summary
        self.annotations = annotations or {}

    @property
    def head_sha(self):
        value = self.metadata.get("head_sha")
        return value if isinstance(value, str) else ""

    @property
    def run_id(self):
        value = self.metadata.get("run_id")
        return value if isinstance(value, str) else "unknown"

    @property
    def run_status(self):
        value = self.metadata.get("run_status")
        return value if isinstance(value, str) else "incomplete"

    @property
    def incomplete_reason(self):
        value = self.metadata.get("incomplete_reason")
        return value if isinstance(value, str) else ""

    def exempt_fingerprints(self):
        """Fingerprints the run accounted for outside findings.json.

        Parity subtracts these on both sides: budget-exhausted candidates, leads the
        disclosure mode withheld, and records the analyze-side gate quarantined.
        """
        out = set()
        for key in ("unvalidated_fingerprints", "withheld_fingerprints",
                    "quarantined_fingerprints"):
            for value in self.metadata.get(key) or []:
                if isinstance(value, str):
                    out.add(value)
        return out

    def prior_source_state(self):
        """fingerprint -> "changed" | "unchanged" | "unknown" for earlier leads.

        Only the analyze job can compute this: it has the git object store and the
        rename map, and compares blob OIDs. Anything absent is "unknown", and an
        unknown state never resolves a thread.
        """
        raw = self.metadata.get("prior_source_state")
        state = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(key, str) and value in ("changed", "unchanged", "unknown"):
                    state[key] = value
        return state

    def annotation_locations(self):
        """fingerprint -> (path, line) from pr-annotations.json.

        A seed for the anchor candidates, used when an inline.json entry predates the
        `candidates` field. It is only ever a hint: the live patch decides.
        """
        out = {}
        for lead in (self.annotations or {}).get("leads") or []:
            if not isinstance(lead, dict):
                continue
            reference = lead.get("reference")
            location = lead.get("location")
            if not isinstance(reference, str) or not isinstance(location, dict):
                continue
            path, line = location.get("path"), location.get("line")
            if isinstance(path, str) and _is_line(line):
                out[reference] = (path, line)
        return out


def _is_line(value):
    # bool is an int in Python; a JSON true would otherwise pass as line 1.
    return isinstance(value, int) and not isinstance(value, bool)


def _read_capped(directory, name, limit):
    """Read one bundle file without following a symlink and without reading past `limit`."""
    path = os.path.join(directory, name)
    try:
        handle = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        with os.fdopen(handle, "rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        raise PublishError("%s is larger than the %d byte limit for it" % (name, limit))
    return data


def _load_json(name, data, expected):
    try:
        value = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PublishError("%s is not valid UTF-8 JSON: %s" % (name, exc))
    if not isinstance(value, expected):
        raise PublishError("%s must be a JSON %s" % (name, expected.__name__))
    return value


def load_bundle(directory):
    """Parse an allowlisted subset of the downloaded bundle. Raises PublishError."""
    if not os.path.isdir(directory):
        raise PublishError("bundle directory %r does not exist" % str(directory)[:200])
    raw = {}
    for name, limit in BUNDLE_FILES.items():
        data = _read_capped(directory, name, limit)
        if data is not None:
            raw[name] = data
    for name in REQUIRED_FILES:
        if name not in raw:
            raise PublishError("bundle is missing %s" % name)
    metadata = _load_json("run-metadata.json", raw["run-metadata.json"], dict)
    findings = _load_json("findings.json", raw["findings.json"], list)
    units = _load_json("coverage-ledger.json", raw["coverage-ledger.json"], list)
    inline = _load_json("inline.json", raw["inline.json"], list) if "inline.json" in raw else []
    annotations = (_load_json("pr-annotations.json", raw["pr-annotations.json"], dict)
                   if "pr-annotations.json" in raw else {})
    summary = raw.get("summary.md", b"").decode("utf-8", "replace")
    if not isinstance(metadata.get("head_sha"), str) or \
            not re.fullmatch(r"[0-9a-f]{40}", metadata["head_sha"]):
        raise PublishError("run-metadata.head_sha is missing or malformed")
    return Bundle(directory, raw, metadata, findings, units, inline, summary, annotations)


def verify_integrity(bundle):
    """Compare every bundle file against the digests run-metadata.json records.

    run-metadata.json is excluded because it carries the digests. A file present with
    no digest, or a digest naming a file that is absent, is a failure: either means
    the bundle is not the one the analyze job signed off on.
    """
    digests = bundle.metadata.get("digests")
    if not isinstance(digests, dict):
        return ["run-metadata.json records no file digests"]
    messages = []
    for name, data in sorted(bundle.files.items()):
        if name == "run-metadata.json":
            continue
        expected = digests.get(name)
        if not isinstance(expected, str):
            messages.append("%s is in the bundle but has no recorded digest" % name)
            continue
        if hashlib.sha256(data).hexdigest() != expected.lower():
            messages.append("%s does not match its recorded digest" % name)
    for name in sorted(digests):
        if name != "run-metadata.json" and name not in bundle.files:
            messages.append("%s has a recorded digest but is not in the bundle" % name)
    return messages


def revalidate(bundle, validator, vendor_dir, node="node"):
    """Re-run the vendored validators and the cross-checks on the downloaded bundle."""
    return validate.final_gate(validator, bundle.findings, bundle.units, vendor_dir,
                               line_count=None,
                               exempt_fingerprints=bundle.exempt_fingerprints(), node=node)


def _record_paths(record):
    paths = []
    for field in ("trace", "evidence"):
        for entry in record.get(field) or []:
            if isinstance(entry, dict) and isinstance(entry.get("file"), str):
                if entry["file"] not in paths:
                    paths.append(entry["file"])
    return paths


def missing_cited_paths(gh, repo, head_sha, records, limit=MAX_EXISTENCE_CHECKS):
    """Cited paths that are not present at the analysed head.

    The vendored validators never open a source file, so a record can cite a path
    that does not exist. Each segment is percent-encoded: a file name may legally
    contain `#` or `?`, which would otherwise truncate the URL inside the one job
    that holds the write token. A transport failure is not evidence of absence.
    """
    seen, missing = set(), set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for path in _record_paths(record):
            if path in seen:
                continue
            seen.add(path)
            if len(seen) > limit:
                return missing
            try:
                gh.contents(repo, path, head_sha)
            except github.HTTPError as exc:
                if exc.status in (403, 404):
                    missing.add(path)
            except github.GitHubError:
                pass
    return missing


def quarantine_missing(gate, missing):
    """Drop records citing an absent path instead of voiding every other lead.

    One malfunctioning or injected agent must not be able to deny the whole report,
    so a record that cannot be anchored to real source is removed and named.
    """
    if not missing:
        return []
    kept, dropped = [], []
    for record in gate.findings:
        bad = [p for p in _record_paths(record) if p in missing] \
            if isinstance(record, dict) else []
        if bad:
            fingerprint = record.get("fingerprint") if isinstance(record, dict) else None
            if not isinstance(fingerprint, str):
                fingerprint = "<no fingerprint>"
            gate.quarantined.append(validate.Quarantined(
                fingerprint=fingerprint,
                messages=["cited file %r is not present at the analysed head" % bad[0][:120]]))
            dropped.append(fingerprint)
        else:
            kept.append(record)
    gate.findings = kept
    return dropped


# ------------------------------------------------------------------ API payloads

def review_comment_payload(anchor, body):
    """One entry in a review's `comments[]` array.

    `subject_type` is not accepted there, which is why a file-level anchor never
    travels this path; `side` is, so the deleted-control LEFT anchor does.
    """
    return {"path": anchor["path"], "line": anchor["line"], "side": anchor["side"],
            "body": body}


def standalone_payload(anchor, body, commit_id):
    """POST /pulls/{n}/comments - the only endpoint that takes `subject_type: file`."""
    payload = {"path": anchor["path"], "body": body, "commit_id": commit_id}
    if anchor.get("anchor") == "file":
        payload["subject_type"] = "file"
    else:
        payload["line"] = anchor["line"]
        payload["side"] = anchor["side"]
    return payload


def file_anchor(path):
    """The same shape `render.select_anchor` returns, for the post-422 degradation."""
    return {"anchor": "file", "path": path, "line": None, "side": None}


# ------------------------------------------------------------------ comment text

def _body_digest(body):
    """Identity of a comment's content, used only when the bundle supplied none."""
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def parse_marker(body):
    match = render.INLINE_MARKER_RE.search(body or "")
    return (match.group(1), match.group(2)) if match else (None, None)


def publishable(bundle, leads, gate):
    """Drop rendered leads whose record the publish-side gate removed.

    `inline.json` is rendered before this gate runs, so a body can outlive the record
    it came from. The marker on a posted lead carries that record's real fingerprint -
    a withheld lead posts no comment, so nothing published is ever named by a handle -
    which is what makes this match exact rather than a guess through a sidecar.
    """
    dropped = {entry.fingerprint for entry in gate.quarantined}
    if not dropped:
        return leads, []
    allowed = {record.get("fingerprint") for record in gate.findings
               if isinstance(record, dict)}
    kept, removed = [], []
    for lead in leads:
        if lead.reference in allowed:
            kept.append(lead)
        else:
            removed.append(lead.reference)
    return kept, removed


class InlineLead:
    """One lead as publish will post it: a reference, a body and where it could hang."""

    def __init__(self, reference, digest, body, candidates):
        self.reference = reference
        self.digest = digest
        self.body = body
        self.candidates = candidates


def build_inline(bundle, repo="", head_sha=""):
    """(leads, messages) from inline.json, the authority on what may be posted.

    The disclosure mode withholds leads at render time while leaving them in
    findings.json for the validators, so this list - not findings.json - decides
    what reaches the pull request.

    Nothing here writes lead text. A body is posted exactly as the renderer produced
    it, or, if it fails the inertness or framing check, is rebuilt by the renderer
    from the record; a lead whose record is gone is dropped to the summary.
    """
    records = {}
    for record in bundle.findings:
        if isinstance(record, dict) and isinstance(record.get("fingerprint"), str):
            records[record["fingerprint"]] = record
    locations = bundle.annotation_locations()
    leads, messages = [], []
    for entry in bundle.inline or []:
        if not isinstance(entry, dict):
            continue
        body = entry.get("body")
        reference = entry.get("fingerprint")
        if not isinstance(reference, str) or not isinstance(body, str) or not body.strip():
            messages.append("an inline.json entry had no reference or body and was dropped")
            continue
        marked_reference, marked_digest = parse_marker(body)
        reference = render.token(marked_reference or reference, render.FINGERPRINT_LIMIT)
        digest = render.token(marked_digest or entry.get("record_hash") or "", 64) \
            or _body_digest(body)
        record = records.get(reference)

        # Cap first: the cap could otherwise remove the very framing that was checked.
        body = render.cap_comment(body.strip())
        problems = render.inert_problems(body) + render.framing_problems(body)
        if problems:
            messages.append("a rendered lead body carried %s and was rebuilt by the "
                            "renderer" % ", ".join(problems))
            body = render.rebuild_lead_body(record, reference, repository=repo,
                                            head_sha=head_sha) if record else ""
            # The renderer's own output is inert by construction. Checking it again is
            # cheap, and a failure here means publish must post nothing rather than
            # trust an invariant that has just been shown not to hold.
            if not body or render.inert_problems(body) or render.framing_problems(body):
                messages.append("lead %s could not be rendered safely and is summary-only"
                                % reference)
                continue
            # The rebuilt body carries its own marker, so the dedupe digest follows it.
            _rebuilt_reference, rebuilt_digest = parse_marker(body)
            digest = rebuilt_digest or digest
        if not render.INLINE_MARKER_RE.search(body):
            body = (render.INLINE_MARKER % (reference, digest)) + "\n" + body

        seeded = []
        if isinstance(entry.get("path"), str) and _is_line(entry.get("line")):
            seeded.append((entry["path"], entry["line"]))
        if reference in locations:
            seeded.append(locations[reference])
        leads.append(InlineLead(reference, digest, body,
                                _candidates(entry, record, seeded)))
    return leads, messages


def _candidates(entry, record, seeded):
    """The ordered (path, line) pairs the renderer chose from, as live-checkable hints.

    The renderer puts them in the inline.json entry; a record is only consulted when an
    older bundle has none, and the renderer computes that order too.
    """
    pairs = []
    for item in entry.get("candidates") or ():
        if isinstance(item, (list, tuple)) and len(item) == 2:
            pairs.append((item[0], item[1]))
    if not pairs and record:
        pairs = render.anchor_candidates(record)
    return render.anchor_candidates({}, seeded=list(pairs) + list(seeded))


# -------------------------------------------------------------------- check runs

def start_check_run(gh, repo, head_sha, name=CHECK_NAME, details_url=None, now=None):
    """Create the check as in_progress BEFORE analyze runs, from the trusted side.

    A cancelled, killed or never-finished analyze job then leaves a visibly stuck
    check instead of silence, which is otherwise indistinguishable from the action
    not being configured at all.
    """
    payload = {"name": name, "head_sha": head_sha, "status": "in_progress",
               "started_at": _timestamp(now),
               "output": {"title": render.CHECK_RUNNING_TITLE,
                          "summary": render.CHECK_RUNNING_SUMMARY}}
    if details_url:
        payload["details_url"] = details_url
    return gh.create_check_run(repo, payload)


def find_check_run(gh, repo, head_sha, name=CHECK_NAME):
    """The check run the start step created, when its id was not handed over."""
    try:
        runs = gh.check_runs_for_ref(repo, head_sha, check_name=name)
    except github.GitHubError:
        return None
    unfinished = [r for r in runs if isinstance(r, dict) and r.get("status") != "completed"]
    chosen = unfinished or [r for r in runs if isinstance(r, dict)]
    return chosen[0].get("id") if chosen else None


def complete_check_run(gh, repo, check_run_id, conclusion, title, summary, now=None):
    payload = {"status": "completed", "conclusion": conclusion,
               "completed_at": _timestamp(now),
               "output": {"title": title[:255], "summary": summary[:60_000]}}
    return gh.update_check_run(repo, check_run_id, payload)


def decide_conclusion(gate_ok, run_complete, lead_count, fail_on="never", superseded=False):
    """Default neutral. `fail-on` is opt-in and unsafe to use as a required check."""
    if superseded or not gate_ok or not run_complete:
        return "neutral"
    if lead_count:
        return "failure" if fail_on == "any-lead" else "neutral"
    return "success"


def _timestamp(now=None):
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------- publisher

class PublishResult:
    def __init__(self, status):
        self.status = status               # published | superseded | blocked
        self.posted_line = 0
        self.posted_file = 0
        self.summary_only = []
        self.unchanged = 0                 # leads already current on the pull request
        self.hidden = []
        self.resolved = []
        self.suspected_suppression = []
        self.conclusion = "neutral"
        self.messages = []
        self.summary_comment_id = None

    @property
    def posted(self):
        return self.posted_line + self.posted_file


class Publisher:
    """Writes to the pull request. Every method here assumes its input is hostile."""

    def __init__(self, gh, repo, pr_number, analysed_head, check_run_id=None,
                 fail_on="never", now=None):
        self.gh = gh
        self.repo = repo
        self.pr_number = int(pr_number)
        self.analysed_head = analysed_head
        self.check_run_id = check_run_id
        self.fail_on = fail_on if fail_on in ("never", "any-lead") else "never"
        self.now = now
        self.log = gh.log
        self._live_head = None

    # -- freshness

    def live_head(self, refresh=True):
        if refresh or self._live_head is None:
            self._live_head = self.gh.live_head_sha(self.repo, self.pr_number)
        return self._live_head

    def is_fresh(self, refresh=True):
        """The analysed head is still the head GitHub reports for this pull request.

        Compared against the live API, never against the workflow input: the input
        and run-metadata both derive from the same event payload, so comparing them
        would always agree and would let stale lead text be anchored onto a new head.
        """
        return self.live_head(refresh) == self.analysed_head

    def _require_fresh(self):
        if not self.is_fresh():
            raise Superseded(self._live_head or "unknown")

    # -- the two failure paths

    def post_notice(self, body, result):
        """Post a parent-authored notice and hide this reviewer's earlier summaries."""
        earlier = self._earlier_summaries()
        comment = self.gh.create_issue_comment(self.repo, self.pr_number, body)
        result.summary_comment_id = comment.get("id")
        result.hidden.extend(self.gh.hide_outdated(earlier))
        return result

    def publish_incomplete(self, reasons, head_sha=None):
        result = PublishResult("blocked")
        result.messages = [str(r) for r in reasons]
        self.post_notice(render.gate_notice(head_sha or self.analysed_head, reasons),
                         result)
        result.conclusion = decide_conclusion(False, False, 0, self.fail_on)
        self.finish_check(result, "incomplete: bundle failed the publish-side gate",
                          "No lead text was posted. See the pull request comment.")
        return result

    def publish_superseded(self, live_head):
        result = PublishResult("superseded")
        result.messages = ["analysed %s but the head is now %s"
                           % (self.analysed_head[:12], (live_head or "unknown")[:12])]
        self.post_notice(render.superseded_notice(self.analysed_head, live_head or ""),
                         result)
        result.conclusion = decide_conclusion(True, False, 0, self.fail_on, superseded=True)
        self.finish_check(result, "superseded by a newer head",
                          "This run analysed %s; the pull request head has moved."
                          % self.analysed_head[:12])
        return result

    # -- the happy path

    def publish(self, bundle, gate):
        """Post the bundle's leads. `gate` is the GateResult from revalidate()."""
        try:
            return self._publish(bundle, gate)
        except Superseded as exc:
            return self.publish_superseded(str(exc))

    def _publish(self, bundle, gate):
        if not self.is_fresh():
            return self.publish_superseded(self._live_head)
        if gate.errors:
            return self.publish_incomplete(list(gate.errors))

        # The gate, not the artifact, decides what the document is.
        bundle.findings = list(gate.findings)
        result = PublishResult("published")
        leads, messages = build_inline(bundle, self.repo, self.analysed_head)
        result.messages.extend(messages)
        leads, removed = publishable(bundle, leads, gate)
        for reference in removed:
            result.messages.append("lead %s was removed by the publish-side gate"
                                   % render.token(reference, render.FINGERPRINT_LIMIT))
        if bundle.inline == [] and bundle.findings:
            result.messages.append("the bundle carried no inline.json, so the leads are "
                                   "in the summary only")

        pr = self.gh.pull_request(self.repo, self.pr_number)
        if (pr.get("head") or {}).get("sha") != self.analysed_head:
            return self.publish_superseded((pr.get("head") or {}).get("sha"))
        files, truncated = self.gh.pull_files(self.repo, self.pr_number,
                                              expected=pr.get("changed_files"))
        if truncated:
            result.messages.append("the files API did not return every changed file; "
                                   "anchors were computed from a short listing")
        # Live data, the renderer's index: whether a line can carry a comment is
        # decided by one implementation, against what GitHub is serving right now.
        diff = render.DiffIndex(files)

        existing = self._our_review_comments()
        self._post_leads(leads, diff, existing, result)
        self._retire_absent(existing, set(lead.reference for lead in leads),
                            bundle.prior_source_state(), result)
        self._post_summary(bundle, result)

        result.conclusion = decide_conclusion(True, bundle.run_status == "complete",
                                              len(leads), self.fail_on)
        self.finish_check(
            result,
            render.check_title(bundle.run_status, bundle.incomplete_reason, len(leads)),
            render.check_summary(self.analysed_head, len(leads), result.posted,
                                 result.unchanged))
        return result

    # -- inline comments

    def _post_leads(self, leads, diff, existing, result):
        review_comments, standalone, superseded = [], [], []
        for lead in leads:
            current, stale = _match_existing(existing, lead.reference, lead.digest)
            if current:
                result.unchanged += 1
                continue
            superseded.extend(stale)
            # The deleted-control LEFT anchor is opted into here, not in the renderer:
            # this job can post it, inside the review or on its own.
            anchor = render.select_anchor(lead.candidates, diff,
                                          allow_deleted_control=True)
            if anchor["anchor"] == "summary":
                result.summary_only.append(lead.reference)
                continue
            target = standalone if anchor["anchor"] == "file" else review_comments
            target.append((lead.reference, anchor, lead.body))

        if review_comments:
            self._post_review(review_comments, result)
        for reference, anchor, body in standalone:
            self._post_standalone(reference, anchor, body, result)
        if superseded:
            self._require_fresh()
            result.hidden.extend(self.gh.hide_outdated(superseded))

    def _post_review(self, review_comments, result):
        """One review with every line-anchored comment; on 422, one comment at a time.

        `subject_type: "file"` is not accepted inside a review's comments[] array,
        which is why file-level comments never travel this path.
        """
        self._require_fresh()
        payload = {"commit_id": self.analysed_head, "event": "COMMENT",
                   "comments": [review_comment_payload(a, b)
                                for _r, a, b in review_comments]}
        try:
            self.gh.create_review(self.repo, self.pr_number, payload)
            result.posted_line += len(review_comments)
            return
        except github.HTTPError as exc:
            if exc.status != 422:
                raise
            self.log("review rejected (422): falling back to one comment at a time")
        for reference, anchor, body in review_comments:
            self._post_standalone(reference, anchor, body, result, allow_file=True)

    def _post_standalone(self, reference, anchor, body, result, allow_file=False):
        """Post one comment on its own, degrading line -> file -> summary-only."""
        self._require_fresh()
        try:
            self.gh.create_review_comment(
                self.repo, self.pr_number,
                standalone_payload(anchor, body, self.analysed_head))
            if anchor["anchor"] == "file":
                result.posted_file += 1
            else:
                result.posted_line += 1
            return
        except github.HTTPError as exc:
            if exc.status != 422:
                raise
        if allow_file and anchor["anchor"] != "file":
            try:
                self.gh.create_review_comment(
                    self.repo, self.pr_number,
                    standalone_payload(file_anchor(anchor["path"]), body,
                                       self.analysed_head))
                result.posted_file += 1
                return
            except github.HTTPError as exc:
                if exc.status != 422:
                    raise
        result.summary_only.append(reference)
        self.log("could not anchor %s; it stays in the summary" % reference)

    # -- threads whose lead stopped being reported

    def _retire_absent(self, existing, current_references, source_state, result):
        """Reply to, and hide, threads for leads this run did not report.

        Only FIXED code resolves a thread. When a lead disappears while the source it
        cited is unchanged, resolving would let a hunter that was talked out of a real
        finding erase the visible record of it too - so the thread is left open, the
        reply says so, and the run counts a suspected suppression. An unknown state is
        treated exactly like an unchanged one, because publish cannot see blobs and
        silence is never evidence of a fix.
        """
        absent = {}
        for comment in existing:
            reference, _digest = parse_marker(comment.get("body"))
            if reference and reference not in current_references:
                absent.setdefault(reference, []).append(comment)
        if not absent:
            return
        threads = self._threads_by_comment_id()
        for reference in sorted(absent):
            comments = absent[reference]
            changed = source_state.get(reference) == "changed"
            if changed:
                text = ("This lead is no longer reported at `%s`: the source it cited "
                        "changed in this push." % self.analysed_head[:7])
            else:
                text = ("This lead was **not re-reported** at `%s`, and the source it "
                        "cited is unchanged. That is not evidence it was fixed - it is "
                        "counted as a suspected suppression and the thread stays open."
                        % self.analysed_head[:7])
                result.suspected_suppression.append(reference)
            self._reply_once(comments, text, result)
            self._require_fresh()
            result.hidden.extend(self.gh.hide_outdated(
                comments, classifier="RESOLVED" if changed else "OUTDATED"))
            if changed:
                self._resolve_threads(comments, threads, result)

    def _reply_once(self, comments, text, result):
        target = next((c for c in comments if c.get("id")), None)
        if target is None:
            return
        try:
            self._require_fresh()
            self.gh.reply_to_review_comment(self.repo, self.pr_number, target["id"], text)
        except github.GitHubError as exc:
            result.messages.append("could not reply to comment %s (%s)"
                                   % (target.get("id"), exc))

    def _resolve_threads(self, comments, threads, result):
        for comment in comments:
            thread_id = threads.get(comment.get("node_id"))
            if not thread_id:
                continue
            try:
                self.gh.resolve_review_thread(thread_id)
                result.resolved.append(thread_id)
            except github.GitHubError as exc:
                result.messages.append("could not resolve thread %s (%s)" % (thread_id, exc))

    def _threads_by_comment_id(self):
        """comment node id -> thread id, so a resolve targets the right thread."""
        mapping = {}
        try:
            threads = self.gh.review_threads(self.repo, self.pr_number)
        except github.GitHubError as exc:
            self.log("warning: could not read review threads (%s)" % exc)
            return mapping
        for thread in threads:
            for comment in thread.get("comments") or []:
                if comment.get("id"):
                    mapping[comment["id"]] = thread.get("id")
        return mapping

    # -- summary

    def _post_summary(self, bundle, result):
        extra = [render.unanchored_section(result.summary_only),
                 render.suppression_section(result.suspected_suppression)]
        body = render.framed_summary(bundle.summary, run_id=bundle.run_id,
                                     head_sha=self.analysed_head,
                                     run_status=bundle.run_status,
                                     incomplete_reason=bundle.incomplete_reason,
                                     extra_sections=extra)
        earlier = self._earlier_summaries()
        self._require_fresh()
        comment = self.gh.create_issue_comment(self.repo, self.pr_number, body)
        result.summary_comment_id = comment.get("id")
        self.log("posted summary comment %s" % comment.get("id"))
        result.hidden.extend(self.gh.hide_outdated(earlier))

    # -- check run

    def finish_check(self, result, title, summary):
        check_id = self.check_run_id or find_check_run(self.gh, self.repo, self.analysed_head)
        if not check_id:
            try:
                check_id = start_check_run(self.gh, self.repo, self.analysed_head,
                                           now=self.now).get("id")
            except github.GitHubError as exc:
                result.messages.append("could not create the check run (%s)" % exc)
                return
        try:
            complete_check_run(self.gh, self.repo, check_id, result.conclusion,
                               title, summary, now=self.now)
            self.check_run_id = check_id
        except github.GitHubError as exc:
            result.messages.append("could not complete the check run (%s)" % exc)

    # -- existing comment state

    def _our_review_comments(self):
        me = self.gh.reviewer_login()
        out = []
        for comment in self.gh.review_comments(self.repo, self.pr_number):
            if not isinstance(comment, dict):
                continue
            if (comment.get("user") or {}).get("login") != me:
                continue
            if render.INLINE_MARKER_RE.search(comment.get("body") or ""):
                out.append(comment)
        return out

    def _earlier_summaries(self):
        me = self.gh.reviewer_login()
        return [c for c in self.gh.issue_comments(self.repo, self.pr_number)
                if isinstance(c, dict)
                and render.MARKER_PREFIX in (c.get("body") or "")
                and (c.get("user") or {}).get("login") == me]


def _match_existing(existing, reference, digest):
    """(already current, comments to hide) for one lead.

    The key is the lead's real fingerprint, which is stable across pushes. An opaque
    per-run handle here would change whenever the run's set of leads changed and every
    comment would be reposted; a lead that is withheld posts no comment at all, so
    nothing that needs deduping is ever named by a handle. `render.Disclosure` has the
    whole argument - do not swap this back.

    A comment whose anchor GitHub has dropped reports `line: null`; its content may
    be identical but it no longer points anywhere, so it is superseded, not current.
    Markers are only ever used for duplicate avoidance: every workflow's token posts
    as github-actions[bot], so a same-repo writer can forge one, and a forged marker
    must at worst suppress a duplicate.
    """
    current, stale = False, []
    for comment in existing:
        found, found_digest = parse_marker(comment.get("body"))
        if found != reference:
            continue
        if found_digest == digest and comment.get("line") is not None:
            current = True
        else:
            stale.append(comment)
    return current, stale


# ------------------------------------------------------------------ entry point

def run(gh, repo, pr_number, analysed_head, bundle_dir, validator, vendor_dir,
        check_run_id=None, fail_on="never", node="node", now=None):
    """Load, re-validate and publish one bundle. Never raises for a bad bundle."""
    publisher = Publisher(gh, repo, pr_number, analysed_head,
                          check_run_id=check_run_id, fail_on=fail_on, now=now)
    try:
        bundle = load_bundle(bundle_dir)
    except PublishError as exc:
        return publisher.publish_incomplete([str(exc)])
    if bundle.head_sha != analysed_head:
        # The bundle claims a different head than this job was told to publish.
        return publisher.publish_incomplete(
            ["the bundle analysed %s but this job was asked to publish %s"
             % (bundle.head_sha[:12], analysed_head[:12])], head_sha=bundle.head_sha)
    reasons = verify_integrity(bundle)
    if reasons:
        return publisher.publish_incomplete(reasons, head_sha=bundle.head_sha)
    gate = revalidate(bundle, validator, vendor_dir, node=node)
    if gate.ok:
        quarantine_missing(gate, missing_cited_paths(gh, repo, analysed_head, gate.findings))
    result = publisher.publish(bundle, gate)
    for entry in gate.quarantined:
        result.messages.append("discarded %s: %s"
                               % (entry.fingerprint, "; ".join(entry.messages)[:200]))
    return result
