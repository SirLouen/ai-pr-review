"""Fail-closed validation gates around the vendored security-audit validators.

The vendored validators are the schema authority, but they only check format and
internal consistency: they never open a source file, never check that a cited
file or line exists, never cross-check findings against the coverage ledger, and
they accept a fabricated `execution.observed_result`. This module is the bridge to
them plus exactly the cross-checks they do not perform.

Three gates live here:

  * per record, inside a `submit_*` tool call - schema, verdict policy, existence;
    a failure returns the validator's own messages to the same conversation at most
    twice and then discards it. The parent never edits a record's content, which is
    what VALIDATION-AND-REPORTING.md:89 forbids.
  * whole document, at the end of analyze and again in publish - the vendored CLIs
    over a real regular file, plus fingerprint parity against the ledger.
  * a path screen at the start of a run - the skill's own path predicate rejects
    legal git paths, so a PR author can name a file such that any finding in it is
    unrepresentable. Those files have to be named in the report, not dropped.

Nothing here can ever accept a `confirmed` verdict or a severity: this action
executes no repository code, and both need an observed result that only execution
can produce.
"""
import json
import os
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from queue import Empty, Queue

HELPER_TIMEOUT_S = 60
CLI_TIMEOUT_S = 120

# VALIDATION-AND-REPORTING.md:89: a malformed result is discarded, not repaired. Two
# rounds is what the model needs to fix a shape mistake; a third means it cannot.
MAX_FEEDBACK_ROUNDS = 2

# Keys a model routinely emits as an explicit null when it has nothing to say, and
# which report-schema.json forbids outright for that verdict. Stripping these is the
# difference between "the agent left it out" and "the agent wrote null", not a repair.
#
# This list is an allowlist on purpose. A blanket null-strip destroys fields the
# skill requires to be PRESENT and null - a source check's "artifact": null, an
# unassigned unit's "agent_id": null - and turns a healthy run into a fail-closed
# one. It is never applied to a coverage unit or a check.
NULL_STRIP_KEYS = frozenset({
    "severity", "execution", "remediation", "reason", "root_cause", "blockers",
    "validation_plan", "claimed_root_cause", "code_changes", "local", "deployment",
})

_INDEX_RE = re.compile(r"^\$\[(\d+)\]")
_SORT_ERROR = "must be sorted lexicographically"


class ValidationBridgeError(Exception):
    """The helper process is unusable. Always fatal: the run cannot validate anything."""


def default_helper_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "node", "sa-helper.cjs"))


# --------------------------------------------------------------------------- bridge

class Validator:
    """A long-lived `node sa-helper.cjs` child, one NDJSON request/response per call.

    A run validates one record per submission and re-validates after feedback, so a
    process per record would cost more wall clock than the model calls it guards.
    """

    def __init__(self, vendor_dir, helper_path=None, node="node", timeout_s=HELPER_TIMEOUT_S):
        self.vendor_dir = os.path.abspath(vendor_dir)
        self.helper_path = os.path.abspath(helper_path or default_helper_path())
        self.node = node
        self.timeout_s = timeout_s
        self._proc = None
        self._replies = Queue()
        self._stderr = []
        self._seq = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    # -- process lifecycle

    def _child_env(self):
        """The helper needs nothing from the ambient environment.

        It handles model-authored records, so it is started with a minimal env
        rather than inheriting one that a later change might put a key back into.
        """
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}

    def _ensure(self):
        if self._proc is not None:
            if self._proc.poll() is None:
                return self._proc
            raise ValidationBridgeError(
                "sa-helper exited with status %s: %s" % (self._proc.poll(), self._stderr_tail()))
        for required in (self.helper_path,
                         os.path.join(self.vendor_dir, "validate-findings.cjs"),
                         os.path.join(self.vendor_dir, "validate-coverage-ledger.cjs"),
                         os.path.join(self.vendor_dir, "report-schema.json")):
            if not os.path.isfile(required):
                raise ValidationBridgeError("missing validator file: %s" % required)
        try:
            self._proc = subprocess.Popen(
                [self.node, self.helper_path, self.vendor_dir],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._child_env(), text=True, encoding="utf-8", bufsize=1,
                cwd=self.vendor_dir)
        except OSError as exc:
            raise ValidationBridgeError("cannot start %s: %s" % (self.node, exc))
        _pump(self._proc.stdout, self._replies.put,
              on_close=lambda: self._replies.put(None))
        _pump(self._proc.stderr, self._note_stderr)
        return self._proc

    def _note_stderr(self, line):
        if len(self._stderr) < 200:   # a looping child must not grow the parent's heap
            self._stderr.append(line)

    def close(self):
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError, AttributeError):
                pass

    def _stderr_tail(self):
        return " | ".join(line.strip() for line in self._stderr[-5:] if line.strip())

    # -- request/response

    def _call(self, op, **payload):
        proc = self._ensure()
        self._seq += 1
        payload["id"] = self._seq
        payload["op"] = op
        # ensure_ascii keeps every request on exactly one line, whatever a model put
        # in a record: NDJSON framing is the only thing standing between a crafted
        # string and a desynchronised bridge.
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        try:
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise ValidationBridgeError("sa-helper stdin closed (%s): %s"
                                        % (exc, self._stderr_tail()))
        try:
            raw = self._replies.get(timeout=self.timeout_s)
        except Empty:
            self.close()
            raise ValidationBridgeError("sa-helper did not answer %r within %ss"
                                        % (op, self.timeout_s))
        if raw is None:
            raise ValidationBridgeError("sa-helper closed its output: %s" % self._stderr_tail())
        reply = json.loads(raw)
        if reply.get("id") != self._seq:
            self.close()
            raise ValidationBridgeError("sa-helper answered out of order")
        if not reply.get("ok"):
            raise ValidationBridgeError("sa-helper rejected %r: %s" % (op, reply.get("error")))
        return reply

    # -- vendored functions

    def validate_findings(self, records):
        """validateDocument(records, report-schema.json). Returns its exact messages."""
        return list(self._call("validate_findings", records=list(records))["errors"])

    def validate_ledger(self, units):
        return list(self._call("validate_ledger", units=list(units))["errors"])

    def coverage_id(self, canonical_refs):
        """canonicalCoverageId. The only legal source of a coverage_id."""
        return self._call("coverage_id", canonical_refs=canonical_refs)["coverage_id"]

    def ping(self):
        return self._call("ping")

    def screen_paths(self, paths):
        """Run the vendored path predicates over repository paths.

        Returns one UnreportablePath per path that either validator rejects, in
        input order. The parent must mark those units blocked and name the files in
        the summary: a finding citing such a path cannot be represented at all, so
        silence would let a PR author suppress a lead by choosing a filename.
        """
        paths = list(paths)
        if not paths:
            return []
        reply = self._call("screen_paths", paths=paths)
        source, ledger = reply["safe_source"], reply["safe_ledger"]
        unreportable = []
        for index, path in enumerate(paths):
            failed = []
            if not source[index]:
                failed.append("findings.json (isSafeRelativeSourcePath)")
            if not ledger[index]:
                failed.append("coverage-ledger.json (isSafeRelativePath)")
            if failed:
                unreportable.append(UnreportablePath(
                    path=path,
                    reason="path is rejected by the skill's own validator for "
                           + " and ".join(failed)))
        return unreportable


def _pump(stream, sink, on_close=None):
    """Drain a child stream on a daemon thread so a full pipe can never block us."""
    def run():
        try:
            for line in stream:
                sink(line)
        except (OSError, ValueError):
            pass   # close() may pull the stream out from under us; EOF is EOF
        finally:
            if on_close is not None:
                on_close()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@dataclass(frozen=True)
class UnreportablePath:
    path: str
    reason: str


# ------------------------------------------------------------------- normalisation

def strip_optional_nulls(record):
    """Copy `record` without the NULL_STRIP_KEYS whose value is exactly null.

    Dropping a key the model set to null is not repairing content: an absent
    optional key and a null one mean the same thing to the model and only one of
    them is legal. Everything else, including a required-and-null field, is left
    exactly as submitted so the validator can reject it.
    """
    if isinstance(record, dict):
        return {key: strip_optional_nulls(value) for key, value in record.items()
                if not (value is None and key in NULL_STRIP_KEYS)}
    if isinstance(record, list):
        return [strip_optional_nulls(item) for item in record]
    return record


# --------------------------------------------------------------------- cross-checks

def check_verdicts(records):
    """No `confirmed`, no severity: this run executes nothing.

    `validate-findings.cjs` accepts `"observed_result": "Not executed"` on a
    confirmed record, so the vendored validator cannot be the control here. The
    parent is.
    """
    errors = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        if record.get("verdict") == "confirmed":
            errors.append((index, '$[%d].verdict: "confirmed" requires an observed result from '
                                  "executed code and this run executes none; report the missing "
                                  "sandbox as a needs_validation blocker" % index))
        for location in _key_paths(record, "severity"):
            errors.append((index, "$[%d]%s: severity is not permitted; only a confirmed finding "
                                  "carries severity" % (index, location)))
    return errors


def check_existence(records, line_count):
    """Every cited file must exist at the analysed ref, every line inside it.

    `line_count(path)` returns the file's line count at that ref, or None when the
    path is not in the tree. Passing it in keeps this check free of any git or
    filesystem dependency, and testable without either.
    """
    errors = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        for field_name in ("trace", "evidence"):
            entries = record.get(field_name)
            if not isinstance(entries, list):
                continue
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                where = "$[%d].%s[%d]" % (index, field_name, position)
                path, line = entry.get("file"), entry.get("line")
                if not isinstance(path, str):
                    continue
                count = line_count(path)
                if count is None:
                    errors.append((index, "%s.file: %r does not exist at the analysed commit"
                                   % (where, path)))
                elif _is_line_number(line) and not 1 <= line <= count:
                    errors.append((index, "%s.line: %d is outside %r, which has %d lines at the "
                                   "analysed commit" % (where, line, path, count)))
    return errors


def check_fingerprint_parity(records, units, exempt=()):
    """Parity between findings.json and the ledger's candidate units, both ways.

    Neither vendored validator ever reads the other document, so a finding with no
    coverage unit - or a candidate unit whose lead silently vanished - passes both.

    `exempt` is subtracted from both sides. It carries the fingerprints the run has
    deliberately accounted for elsewhere: candidates left unvalidated by the budget,
    records withheld by the disclosure mode, and records quarantined by this gate.
    """
    exempt = set(exempt)
    found = {}
    for index, record in enumerate(records):
        if isinstance(record, dict) and isinstance(record.get("fingerprint"), str):
            found.setdefault(record["fingerprint"], index)
    claimed = set()
    for unit in units:
        if not isinstance(unit, dict) or unit.get("status") != "candidate":
            continue
        for fingerprint in unit.get("result_fingerprints") or []:
            if isinstance(fingerprint, str):
                claimed.add(fingerprint)

    errors = []
    for fingerprint in sorted(set(found) - claimed - exempt):
        errors.append((found[fingerprint],
                       "$[%d].fingerprint: %r has no candidate coverage unit; every reported "
                       "finding must be owned by a unit" % (found[fingerprint], fingerprint)))
    for fingerprint in sorted(claimed - set(found) - exempt):
        # No record can be removed to fix this: a candidate unit promises a lead that
        # the document does not carry, which is a run-level bookkeeping failure.
        errors.append((None, "coverage-ledger.json: candidate unit fingerprint %r has no finding "
                             "and is not disclosed as unvalidated" % fingerprint))
    return errors


def _is_line_number(value):
    # bool is an int in Python; a JSON true would otherwise compare as line 1.
    return isinstance(value, int) and not isinstance(value, bool)


def _key_paths(value, key, prefix=""):
    """Yield every location under `value` where `key` appears, as a JSON-path suffix."""
    if isinstance(value, dict):
        for name, item in value.items():
            here = "%s.%s" % (prefix, name)
            if name == key:
                yield here
            yield from _key_paths(item, key, here)
    elif isinstance(value, list):
        for position, item in enumerate(value):
            yield from _key_paths(item, key, "%s[%d]" % (prefix, position))


# ------------------------------------------------------------------ per-record gate

@dataclass
class Submission:
    """The outcome of one `submit_*` call."""
    action: str              # accept | feedback | discard
    errors: list = field(default_factory=list)   # the validator's exact messages
    record: dict = None      # the normalised record, only when action == "accept"
    round: int = 0

    @property
    def accepted(self):
        return self.action == "accept"


class RecordGate:
    """The per-record gate for ONE model conversation.

    On failure the caller returns `submission.errors` verbatim to that same
    conversation and lets the agent resubmit. After MAX_FEEDBACK_ROUNDS rejections
    the action becomes "discard": the caller drops the conversation and starts a
    fresh agent. The parent never rewrites a record - that is the repair the skill
    forbids (VALIDATION-AND-REPORTING.md:89).

    Read-coverage and quote-grounding need the conversation's read log and belong to
    the tool loop; this gate is the part that only needs the record and the tree.
    """

    def __init__(self, validator, line_count=None, expected_fingerprints=None,
                 max_rounds=MAX_FEEDBACK_ROUNDS):
        self.validator = validator
        self.line_count = line_count
        self.expected_fingerprints = None if expected_fingerprints is None \
            else frozenset(expected_fingerprints)
        self.max_rounds = max_rounds
        self.rounds = 0

    def submit_json(self, text):
        """Strict parse, then submit. A prose-wrapped or truncated result is a failure."""
        try:
            record = json.loads(text)
        except (ValueError, TypeError) as exc:
            return self._reject(["the submitted result is not valid JSON: %s" % exc])
        return self.submit(record)

    def submit(self, record):
        self.rounds += 1
        if not isinstance(record, dict):
            return self._reject(["$: expected one finding object, got %s"
                                 % type(record).__name__])
        candidate = strip_optional_nulls(record)
        errors = self.validator.validate_findings([candidate])
        errors.extend(message for _index, message in check_verdicts([candidate]))
        if self.line_count is not None:
            errors.extend(message for _index, message in
                          check_existence([candidate], self.line_count))
        if self.expected_fingerprints is not None:
            fingerprint = candidate.get("fingerprint")
            if fingerprint not in self.expected_fingerprints:
                errors.append("$[0].fingerprint: must be one of %s; the parent assembles "
                              "fingerprints and a result cannot choose its own"
                              % ", ".join(sorted(repr(f) for f in self.expected_fingerprints)))
        if errors:
            return self._reject(errors)
        return Submission(action="accept", record=candidate, round=self.rounds)

    def _reject(self, errors):
        # max_rounds counts feedback returns, not submissions: two rejections come
        # back with the messages, the third ends the conversation.
        action = "feedback" if self.rounds <= self.max_rounds else "discard"
        return Submission(action=action, errors=list(errors), round=self.rounds)


# ------------------------------------------------------------------ vendored CLIs

def parse_validator_output(stderr):
    """Pull a vendored CLI's own messages out of its stderr.

    'ERROR: <message>' lines are the per-record diagnostics. The 'Failed to ...'
    lines are whole-file refusals - not a regular file, a symlink, not UTF-8, over
    the byte limit, unparseable - and must fail the gate too, or a document the
    validator could not read would look like a document with no errors.
    """
    messages = []
    for line in (stderr or "").splitlines():
        line = line.rstrip("\r")
        if line.startswith("ERROR: "):
            messages.append(line[len("ERROR: "):])
        elif line.startswith("Failed to ") or line.startswith("Usage: "):
            messages.append(line)
    return messages


def run_cli_validator(script, document, vendor_dir, node="node", timeout_s=CLI_TIMEOUT_S):
    """Run one vendored CLI over `document` and return its messages.

    The validators open their input with O_NOFOLLOW|O_NONBLOCK and refuse anything
    that is not a regular file, so the document has to be written to a real file in
    a directory only this process can reach - stdin, a pipe or a symlink is rejected.
    """
    with tempfile.TemporaryDirectory(prefix="sa-validate-") as work_dir:
        target = os.path.join(work_dir, os.path.basename(script).replace(
            "validate-", "").replace(".cjs", "") + ".json")
        # O_EXCL|O_NOFOLLOW: this process creates the file it is about to have
        # validated, so nothing can swap a symlink in between the write and the read.
        handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False)
            stream.write("\n")
        try:
            done = subprocess.run(
                [node, os.path.join(vendor_dir, script), target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", timeout=timeout_s,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ["%s could not be run: %s" % (script, exc)]
        messages = parse_validator_output(done.stderr)
        if done.returncode != 0 and not messages:
            messages = ["%s exited with status %d and no diagnostic"
                        % (script, done.returncode)]
    return messages


def run_cli_validators(records, units, vendor_dir, node="node", timeout_s=CLI_TIMEOUT_S):
    """The §8.4 pair, as the skill's README runs them. Returns (findings, ledger)."""
    return (run_cli_validator("validate-findings.cjs", records, vendor_dir, node, timeout_s),
            run_cli_validator("validate-coverage-ledger.cjs", units, vendor_dir, node, timeout_s))


# -------------------------------------------------------------------- final gate

@dataclass
class Quarantined:
    fingerprint: str
    messages: list


@dataclass
class GateResult:
    ok: bool
    findings: list = field(default_factory=list)
    quarantined: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def quarantined_fingerprints(self):
        return [entry.fingerprint for entry in self.quarantined]


def final_gate(validator, records, units, vendor_dir, line_count=None,
               exempt_fingerprints=(), node="node"):
    """The whole-document gate: quarantine what is broken, publish what survives.

    Voiding the report on any failure would hand a single malfunctioning or injected
    agent a run-wide denial of every other agent's leads. So a record that fails is
    removed, the surviving subset is re-validated as its own document, and the
    quarantined fingerprints are reported with the validator's exact message.

    Only two things are fatal: a document-level failure that no record removal can
    fix, and a coverage ledger that does not validate - the ledger is the run's
    account of what was looked at, and subsetting it would falsify that account.
    """
    current = list(records)
    exempt = set(exempt_fingerprints)
    quarantined, fatal = [], []
    rounds = len(current) + 2

    def drop(messages_by_index):
        # Highest index first so the lower ones stay valid while we remove.
        for index in sorted(messages_by_index, reverse=True):
            record = current.pop(index)
            fingerprint = record.get("fingerprint") if isinstance(record, dict) else None
            if not isinstance(fingerprint, str):
                fingerprint = "<no fingerprint>"
            quarantined.append(Quarantined(fingerprint=fingerprint,
                                           messages=messages_by_index[index]))
            # The record is gone from the document but its coverage unit still names
            # it, so parity has to stop expecting it.
            exempt.add(fingerprint)

    # Per record first: a schema, verdict or existence failure belongs to exactly one
    # record, and removing it cannot make any other record invalid.
    per_record = {}
    for index, record in enumerate(current):
        messages = list(validator.validate_findings([record]))
        messages.extend(message for _index, message in check_verdicts([record]))
        if line_count is not None:
            messages.extend(message for _index, message in check_existence([record], line_count))
        if messages:
            per_record[index] = [_reindex(message, index) for message in messages]
    drop(per_record)

    # Then the document-level checks, which only exist over the whole array.
    reordered = False
    for _round in range(rounds):
        messages = validator.validate_findings(current)
        if not messages:
            break
        if not reordered and all(_SORT_ERROR in message for message in messages):
            # Document order is the parent's own bookkeeping, not record content, so
            # sorting costs no lead. Fingerprints are ASCII by schema, which is why
            # Python's ordering and the validator's UTF-16 comparison agree here.
            current.sort(key=lambda record: str(record.get("fingerprint") or ""))
            reordered = True
            continue
        by_index = {}
        unattributable = []
        for message in messages:
            index = _index_of(message)
            if index is None:
                unattributable.append(message)
            else:
                by_index.setdefault(index, []).append(message)
        if not by_index:
            fatal.extend(unattributable)
            break
        drop(by_index)

    # Parity last, because quarantining a record removes its fingerprint from the
    # document while its coverage unit still claims it.
    for _round in range(rounds):
        parity = check_fingerprint_parity(current, units, exempt)
        by_index = {}
        for index, message in parity:
            if index is not None:
                by_index.setdefault(index, []).append(message)
        if not by_index:
            fatal.extend(message for index, message in parity if index is None)
            break
        drop(by_index)

    # The CLIs are the authority; everything above only decides what to send them.
    # Both run again in publish, over the downloaded artifact.
    findings_errors, ledger_errors = run_cli_validators(current, units, vendor_dir, node=node)
    fatal.extend(findings_errors)
    fatal.extend("coverage-ledger.json: " + message for message in ledger_errors)
    return GateResult(ok=not fatal, findings=current, quarantined=quarantined,
                      errors=_unique(fatal))


def _unique(messages):
    seen, ordered = set(), []
    for message in messages:
        if message not in seen:
            seen.add(message)
            ordered.append(message)
    return ordered


def _index_of(message):
    match = _INDEX_RE.match(message)
    return int(match.group(1)) if match else None


def _reindex(message, index):
    """Rewrite a one-record document's `$[0]` prefix to the record's real position."""
    return _INDEX_RE.sub("$[%d]" % index, message, count=1) if message.startswith("$[") \
        else message
