"""The model-facing tool surface. This module is the security boundary of the run.

An agent can do exactly what is declared here and nothing else: seven read-only
functions over git objects in a bare repository, plus one terminal submit tool. There
is no shell, no filesystem path, no network, no environment and no sub-agent. Nothing
from the pull request is ever checked out or executed, so the run can never observe a
runtime result and therefore never emits `confirmed` or a severity.

Four properties hold here and nowhere else:

* every argument is checked against the declared schema before it reaches git, and
  paths are resolved structurally through the in-memory tree index (`gitsrc`);
* every result is wrapped by `DataFramer`, so the model can tell repository content
  from parent instruction, and repo-derived text never lands in a bare prompt slot;
* everything the conversation read is recorded line by line in a `ReadLog`, which is
  what makes VALIDATION-AND-REPORTING.md:5 ("re-read every cited current source
  location") mechanically enforceable instead of an instruction;
* nothing is dropped in silence: an unreadable blob, a truncated grep, a capped diff
  or an exhausted budget becomes an `Omission` the report has to list.

Errors are returned to the model as tool results so it can recover; they are never
raised into the conversation loop. The single exception is budget exhaustion, which
returns the finalize notice.
"""
import re
import threading

from . import gitsrc, routing, validate
from .config import Caps, SHA_RE
from .dataframe import DataFramer
from .gitsrc import GitError, PathError, SizeGateError

FINALIZE_NOTICE = "BUDGET_EXHAUSTED: submit your result now"
ACCEPTED_NOTICE = "ACCEPTED: the parent recorded your result. Make no further tool calls."
FEEDBACK_HEADER = ("VALIDATION FAILED. The parent does not edit results. Correct yours and call "
                   "%s again. Exact validator messages follow, one per line:")
DISCARD_NOTICE = ("VALIDATION FAILED for the last time; this conversation is over. Exact validator "
                  "messages follow, one per line:")

MAX_SUBMIT_ROUNDS = validate.MAX_FEEDBACK_ROUNDS
MAX_LINE_CHARS = 500
MAX_ECHO_CHARS = 200
MAX_MESSAGE_CHARS = 400
MIN_USEFUL_BYTES = 512
CHANGED_PAGE = 200
MAX_COMMIT_INDEXES = Caps().max_commit_indexes  # resource caps live together in config
MAX_CONTEXT_LINES = 10
# ">3 rejected out-of-tree paths, pathspec-magic attempts or forged-delimiter hits in one
# conversation" (design 8.1). Ordinary misses -- a path that simply is not in the tree --
# are not counted, so an honest agent that mistypes a filename never trips this.
MAX_PROBES = 3

BLOCKER_TAGS = ("[execution] ", "[deployment] ", "[context] ")
BLOCKER_KINDS = ("execution", "deployment", "context")

# Markers that make a *rejected* path read as an attempt to leave the repository rather
# than a typo. They are only ever consulted after normalize_path() has already refused
# the path, so an in-repo `.env` or `config` file never matches.
_PROBE_MARKERS = ("/proc", "/sys", "/dev/", "/etc/", "/root", "/var/run", "/home/",
                  ".ssh", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
                  ".git/config", ".git/hooks", ".aws", ".kube", ".docker/config",
                  ".netrc", ".npmrc", "environ", "cmdline", "passwd", "shadow",
                  "runner/work/_temp", "github_token", "actions/runner")

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class ToolError(Exception):
    """A tool refused the call. Returned to the model as a tool result, never raised
    into the loop: an agent that is told why a call failed can correct it, and an agent
    that sees a crash just stops."""

    def __init__(self, message, probe=False):
        Exception.__init__(self, message)
        self.probe = probe          # counts toward the suspected-injection signal


class SurfaceError(Exception):
    """The tool surface itself is misconfigured. Fatal: the run stops before any call."""


def safe_text(value, limit=MAX_ECHO_CHARS):
    """Make model- or repo-derived text safe to put in a bare prompt slot.

    Paths and patterns are attacker-chosen (a path may legally contain a newline, a
    bidi override or the text `<<<END ...>>>`), and a tool error is parent prose, not a
    DATA frame. Control, format and bidi characters go, whitespace collapses, and the
    result is length-capped. This runs over whole messages too, so it must leave the
    backticks `safe_path` added intact.
    """
    return routing.sanitize(str(value), limit)


def safe_path(value, limit=MAX_ECHO_CHARS):
    """A repo-derived path, backtick-escaped and length-capped for a prompt slot.

    The backticks come off the value and go around it, so the fragment cannot end its
    own quoting and continue as parent prose.
    """
    text = safe_text(value, limit).replace("`", "'")
    return "`%s`" % text if text else "`<empty>`"


def _is_line(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _type_name(value):
    return {dict: "object", list: "array", str: "string", bool: "boolean",
            int: "integer", float: "number"}.get(type(value), "null")


# --------------------------------------------------------------------------- schemas

def _schema(kind, description, nullable=False, **extra):
    types = [kind, "null"] if nullable else kind
    out = {"type": types, "description": description}
    out.update(extra)
    return out


def _string(description, nullable=False, enum=None):
    extra = {"enum": list(enum) + ([None] if nullable else [])} if enum else {}
    return _schema("string", description, nullable, **extra)


def _integer(description, nullable=False):
    return _schema("integer", description, nullable)


def _boolean(description, nullable=False):
    return _schema("boolean", description, nullable)


def _array(items, description, nullable=False):
    return _schema("array", description, nullable, items=items)


def _object(properties, description, nullable=False):
    """A strict-compatible object: every property required, no additional properties.

    DeepSeek's `/beta` strict tool mode requires exactly this and rejects the
    cardinality keywords (`minLength`, `minItems`, `maxItems`), so optionality is
    expressed as a nullable type and cardinality is enforced by `_cardinality()` on
    the parsed arguments instead of by the schema.
    """
    return _schema("object", description, nullable,
                   properties=properties, required=sorted(properties),
                   additionalProperties=False)


REF_DESC = ("`head`, `base`, or one of the commit SHAs returned by list_commits. No other "
            "commit is addressable in this run.")

READ_SCHEMAS = {
    "read_file": _object({
        "path": _string("Repository-relative path, exactly as list_changed_files or "
                        "list_dir spells it. No absolute path, no `..`, no glob."),
        "ref": _string(REF_DESC),
        "start_line": _integer("First line to return, 1-based. null starts at line 1.",
                               nullable=True),
        "end_line": _integer("Last line to return, inclusive. null reads one window.",
                             nullable=True),
    }, "Read a window of one text file at one ref. Output is line-numbered."),

    "grep": _object({
        "pattern": _string("Literal text, or a POSIX extended regex when fixed_string is "
                           "false. At most 200 characters, no newline."),
        "ref": _string(REF_DESC),
        "path_glob": _string("Restrict the search, e.g. `src/**` or `*.ts`. null searches "
                             "the whole tree. Only [A-Za-z0-9._/*?[]{}!-] is accepted.",
                             nullable=True),
        "fixed_string": _boolean("Treat the pattern as literal text. null means true.",
                                 nullable=True),
        "ignore_case": _boolean("Case-insensitive match. null means false.", nullable=True),
    }, "Search file contents at one ref. Dot-directories such as .github/workflows are "
       "searched."),

    "list_dir": _object({
        "path": _string("Directory to list. null lists the repository root.", nullable=True),
        "ref": _string(REF_DESC),
        "recursive": _boolean("List every descendant instead of one level. null means false.",
                              nullable=True),
    }, "List the entries of one directory at one ref."),

    "list_changed_files": _object({
        "page": _integer("1-based page of %d entries. null means page 1." % CHANGED_PAGE,
                         nullable=True),
    }, "Every file this pull request changes, with its status, line counts and whether "
       "this run can read it."),

    "get_diff": _object({
        "path": _string("A path from list_changed_files."),
        "context": _integer("Context lines around each hunk, 0 to %d. null means 3."
                            % MAX_CONTEXT_LINES, nullable=True),
        "start_hunk": _integer("0-based hunk to resume from when a previous call was "
                               "capped. null starts at the first hunk.", nullable=True),
    }, "The merge-base..head diff for one changed file, with old and new line numbers."),

    "list_commits": _object(
        {}, "The commits of this pull request, oldest first. These SHAs are the only ones "
            "read_file and get_commit_patch accept besides head and base."),

    "get_commit_patch": _object({
        "sha": _string("A commit SHA from list_commits."),
        "path": _string("Restrict the patch to one path. null returns the whole commit.",
                        nullable=True),
    }, "The patch of one pull-request commit against its parent. This is how a secret "
       "added in one commit and removed in a later one is still visible."),
}

READ_TOOLS = tuple(sorted(READ_SCHEMAS))

_TRACE_ITEM = _object({
    "kind": _string("Which step of the path this is.",
                    enum=["entrypoint", "propagation", "sink"]),
    "file": _string("Repository-relative path at head."),
    "line": _integer("1-based line at head. You must have read this line."),
    "scope": _string("The enclosing function, class or block, as the source spells it."),
    "description": _string("What happens at this line."),
}, "One step from the untrusted entry point to the sink.")

_EVIDENCE_ITEM = _object({
    "file": _string("Repository-relative path at head."),
    "line": _integer("1-based line at head. You must have read this line."),
    "description": _string("What this line shows."),
}, "One source location that supports the claim.")

_VALIDATION_PLAN = _object({
    "local": _string("The concrete local task that would settle this, naming test files "
                     "and symbols that exist at head. Required when any blocker is "
                     "[execution].", nullable=True),
    "deployment": _string("The deployment fact that would settle this.", nullable=True),
}, "How a human would settle the claim.", nullable=True)


def _record_schema(verdict_key, verdict_enum, extra=None):
    """A strict-compatible projection of report-schema.json's needs_validation and
    rejected branches, flattened into one object.

    The vendored schema is a `oneOf` with per-branch required lists and `minItems`
    cardinality, none of which a strict tool schema can express. The projection carries
    the union of both branches with branch-specific fields nullable; `validate.Validator`
    then checks the real schema, and `_cardinality()` checks what strict mode dropped.
    The `confirmed` branch is absent on purpose: this run executes nothing, so a
    confirmation is not merely rejected downstream, it is unsayable here.
    """
    properties = {
        verdict_key: _string("The only verdicts this run can express. `confirmed` requires "
                             "an observed result from executed code and this run executes "
                             "none.", enum=list(verdict_enum)),
        "fingerprint": _string("The fingerprint the parent assigned you."),
        "title": _string("One line naming the boundary crossing."),
        "description": _string("What an attacker can do, in the target's own terms."),
        "claimed_root_cause": _string("The control that is missing or wrong."),
        "trace": _array(_TRACE_ITEM, "Entry point to sink, in order."),
        "evidence": _array(_EVIDENCE_ITEM, "Source locations you read."),
        "blockers": _array(_string("Each blocker starts with `[execution] `, `[deployment] ` "
                                   "or `[context] `."),
                           "What stops this from being demonstrated. null when rejected.",
                           nullable=True),
        "validation_plan": _VALIDATION_PLAN,
        "reason": _string("Why the claim does not hold. null unless rejected.", nullable=True),
    }
    properties.update(extra or {})
    return _object(properties, "One finding record.")


VERIFIER_RECORD = _record_schema("verdict", ("needs_validation", "rejected"))

HUNTER_CANDIDATE = _record_schema(
    "proposed_verdict", ("needs_validation",),
    {"coverage_id": _string("The coverage unit this candidate came out of.")})

_UNIT_CHECK = _object({
    "agent_id": _string("Your own agent id."),
    "invariant": _string("The property you checked."),
    "method": _string("Always `source`: this run executes nothing.", enum=["source"]),
    "result": _string("What re-reading the source established."),
    "reviewed_paths": _array(_string("A path you actually opened."),
                             "Paths this check read."),
    "artifact": _string("Always null: this run produces no artifacts.", nullable=True),
}, "One recorded source check.")

_UNIT = _object({
    "coverage_id": _string("The id the parent assigned this unit."),
    "status": _string("How this unit ended.",
                      enum=["covered", "candidate", "blocked", "deferred", "planned",
                            "out_of_scope"]),
    "agent_id": _string("Your own agent id, or null when you did not work this unit.",
                        nullable=True),
    "reviewed_paths": _array(_string("A path you actually opened."),
                             "Exactly the union of this unit's checks' reviewed_paths."),
    "local_checks": _array(_UNIT_CHECK, "The source checks you performed."),
    "result_fingerprints": _array(_string("A fingerprint the parent assigned."),
                                  "Empty unless the status is candidate."),
    "unresolved": _array(_string("What is still open."),
                         "Non-empty when the status is blocked or deferred."),
}, "One coverage unit's outcome.")

SUBMIT_SCHEMAS = {
    "submit_verdict": _object({
        "decision": _string("Must equal record.verdict.",
                            enum=["needs_validation", "rejected"]),
        "record": VERIFIER_RECORD,
        "same_root_cause_as": _string("A prior fingerprint from the offered list, or null.",
                                      nullable=True),
    }, "Return your verdict on the candidate. Call this exactly once."),

    "submit_hunt": _object({
        "candidates": _array(HUNTER_CANDIDATE, "Source-grounded candidates, possibly empty."),
        "units": _array(_UNIT, "Every coverage unit you were assigned, exactly once."),
    }, "Return your hunt result. Call this exactly once."),

    "submit_recon": _object({
        "units": _array(_UNIT, "The coverage units you propose."),
        "boundaries": _array(_string("One boundary you found in source, as `path#symbol`."),
                             "Trust boundaries you located."),
        "notes": _array(_string("One coverage consequence."),
                        "Coverage consequences only, no free prose."),
    }, "Return your reconnaissance result. Call this exactly once."),

    "submit_critique": _object({
        "units": _array(_UNIT, "Units whose status you are correcting, possibly empty."),
        "gaps": _array(_string("One concrete coverage gap."), "Gaps you found."),
        "clean": _boolean("True only when you found no gap."),
    }, "Return your coverage critique. Call this exactly once."),
}

SUBMIT_TOOLS = {"recon": "submit_recon", "hunter": "submit_hunt",
                "critic": "submit_critique", "verifier": "submit_verdict"}


def tool_definitions(role, strict=True):
    """The provider-format tool catalogue for one role.

    `strict` asks DeepSeek's `/beta` strict mode to enforce the schema. It is a
    convenience, never a control: `check_schema()` re-checks every argument here.
    """
    if role not in SUBMIT_TOOLS:
        raise SurfaceError("unknown role %r" % role)
    names = list(READ_TOOLS) + [SUBMIT_TOOLS[role]]
    schemas = dict(READ_SCHEMAS)
    schemas.update(SUBMIT_SCHEMAS)
    tools = []
    for name in names:
        schema = schemas[name]
        function = {"name": name, "description": schema["description"],
                    "parameters": _parameters(schema)}
        if strict:
            function["strict"] = True
        tools.append({"type": "function", "function": function})
    return tools


def _parameters(schema):
    parameters = dict(schema)
    parameters.pop("description", None)
    return parameters


# ------------------------------------------------------------------ argument checking

def check_schema(schema, value, where="arguments"):
    """Validate one tool call's arguments against the declared schema.

    Unknown fields and missing fields are both errors. Strict mode may already have
    enforced this provider-side; this run does not depend on that.
    """
    errors = []
    _check(schema, value, where, errors)
    return errors


def _check(schema, value, where, errors):
    types = schema["type"]
    types = list(types) if isinstance(types, list) else [types]
    if value is None:
        if "null" not in types:
            errors.append("%s: must not be null" % where)
        return
    if "object" in types and isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in sorted(value):
            if key not in properties:
                errors.append("%s: unknown field %s; this tool accepts exactly %s"
                              % (where, safe_path(key, 60),
                                 ", ".join(sorted(properties)) or "no arguments"))
        for key in sorted(properties):
            if key not in value:
                errors.append("%s: missing required field `%s`; send null when it does not "
                              "apply" % (where, key))
            else:
                _check(properties[key], value[key], "%s.%s" % (where, key), errors)
        return
    if "array" in types and isinstance(value, list):
        for index, item in enumerate(value):
            _check(schema["items"], item, "%s[%d]" % (where, index), errors)
        return
    if "string" in types and isinstance(value, str):
        allowed = [option for option in schema.get("enum") or [] if option is not None]
        if allowed and value not in allowed:
            errors.append("%s: must be one of %s, got %s"
                          % (where, ", ".join(repr(o) for o in allowed), safe_path(value, 60)))
        return
    if "integer" in types and isinstance(value, int) and not isinstance(value, bool):
        return
    if "boolean" in types and isinstance(value, bool):
        return
    errors.append("%s: expected %s, got %s"
                  % (where, "/".join(t for t in types if t != "null"), _type_name(value)))


def _cardinality(name, args):
    """The bounds a strict tool schema cannot carry.

    Strict mode rejects minLength/minItems/maxItems, so every non-empty and every range
    constraint is checked here instead. Losing them silently would let an empty units
    list read as a completed hunt.
    """
    errors = []

    def non_empty(key, label):
        value = args.get(key)
        if isinstance(value, str) and not value.strip():
            errors.append("arguments.%s: %s must not be empty" % (key, label))
        if isinstance(value, list) and not value:
            errors.append("arguments.%s: %s must not be empty" % (key, label))

    if name == "read_file":
        non_empty("path", "path")
        start, end = args.get("start_line"), args.get("end_line")
        if start is not None and start < 1:
            errors.append("arguments.start_line: must be 1 or greater")
        if end is not None and end < 1:
            errors.append("arguments.end_line: must be 1 or greater")
        if start is not None and end is not None and end < start:
            errors.append("arguments.end_line: must not be smaller than start_line")
    elif name == "grep":
        non_empty("pattern", "pattern")
    elif name == "get_diff":
        non_empty("path", "path")
        context = args.get("context")
        if context is not None and not 0 <= context <= MAX_CONTEXT_LINES:
            errors.append("arguments.context: must be between 0 and %d" % MAX_CONTEXT_LINES)
        start_hunk = args.get("start_hunk")
        if start_hunk is not None and start_hunk < 0:
            errors.append("arguments.start_hunk: must be 0 or greater")
    elif name == "list_changed_files":
        page = args.get("page")
        if page is not None and page < 1:
            errors.append("arguments.page: must be 1 or greater")
    elif name == "get_commit_patch":
        non_empty("sha", "sha")
    elif name == "submit_hunt":
        # A hunter must account for every unit it was assigned, so an empty list is an
        # unfinished hunt. Reconnaissance only PROPOSES units on top of the parent's own
        # floor, and the critic only proposes corrections: demanding one there would make
        # "I found nothing to add" unsayable and push the model to invent a unit.
        non_empty("units", "units")
    return errors


# ------------------------------------------------------------------------- omissions

class Omission:
    """One thing the conversation could not see, or could not see all of.

    The report's "Not reviewed" section is built from these. A gap that is not recorded
    here is a gap that closes silently, which HUNTING.md:247 forbids being read as
    coverage.
    """

    __slots__ = ("kind", "path", "ref", "reason", "detail")

    def __init__(self, kind, path="", ref="", reason="", detail=""):
        self.kind = kind
        self.path = path
        self.ref = ref
        self.reason = reason
        self.detail = detail

    @property
    def key(self):
        return (self.kind, self.path, self.ref, self.detail)

    def as_dict(self):
        return {"kind": self.kind, "path": self.path, "ref": self.ref,
                "reason": self.reason, "detail": self.detail}

    def __repr__(self):
        return "Omission(%s, %s)" % (self.kind, safe_text(self.path, 40))


class Omissions:
    """Every omission of one conversation, deduplicated by key and kept in order."""

    def __init__(self):
        self._seen = set()
        self._items = []

    def record(self, kind, path="", ref="", reason="", detail=""):
        omission = Omission(kind, path, ref, reason, detail)
        if omission.key in self._seen:
            return omission
        self._seen.add(omission.key)
        self._items.append(omission)
        return omission

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def kinds(self):
        return sorted({item.kind for item in self._items})

    def paths(self):
        return sorted({item.path for item in self._items if item.path})

    def as_dicts(self):
        return [item.as_dict() for item in self._items]


# --------------------------------------------------------------------------- read log

class ReadLog:
    """Line-granular record of what one conversation actually read.

    VALIDATION-AND-REPORTING.md:5 requires a verifier to "re-read every cited current
    source location". Without execution this is the only mechanical enforcement
    available, and it has to be line-granular: a file-level or pack-level check lets a
    steered verifier cite a real file at a real in-range line that says nothing about
    the claim.
    """

    def __init__(self):
        self._ranges = {}                  # (ref, path) -> sorted, merged [start, end]
        self.sources = {}                  # which tool contributed how many lines

    def record(self, path, ref, start, end, source="read_file"):
        if not isinstance(path, str) or not path:
            return
        start, end = max(1, int(start)), int(end)
        if end < start:
            return
        key = (ref, path)
        merged = self._ranges.setdefault(key, [])
        merged.append([start, end])
        merged.sort()
        collapsed = [merged[0]]
        for low, high in merged[1:]:
            # Adjacent ranges join: lines 1-10 and 11-20 are one read, not two.
            if low <= collapsed[-1][1] + 1:
                collapsed[-1][1] = max(collapsed[-1][1], high)
            else:
                collapsed.append([low, high])
        self._ranges[key] = collapsed
        self.sources[source] = self.sources.get(source, 0) + (end - start + 1)

    def grep_hit(self, path, ref, line):
        self.record(path, ref, line, line, source="grep")

    def pack(self, path, ref, start, end):
        """Warm-start pack content counts as read: the parent put it in the first user
        message, so the agent has seen those exact lines (design 8.1 step 4)."""
        self.record(path, ref, start, end, source="pack")

    def covered(self, path, ref, line):
        if not _is_line(line):
            return False
        for low, high in self._ranges.get((ref, path), ()):
            if low <= line <= high:
                return True
        return False

    def ranges(self, path, ref):
        return [list(pair) for pair in self._ranges.get((ref, path), ())]

    def paths(self, ref=None):
        return sorted({path for (key_ref, path) in self._ranges
                       if ref is None or key_ref == ref})

    def line_total(self):
        return sum(high - low + 1 for ranges in self._ranges.values()
                   for low, high in ranges)

    def summary(self):
        by_ref = {}
        for (ref, path), ranges in sorted(self._ranges.items()):
            by_ref.setdefault(ref, {})[path] = [list(pair) for pair in ranges]
        return {"reviewed_paths": self.paths(), "lines": self.line_total(),
                "by_ref": by_ref, "sources": dict(sorted(self.sources.items()))}


# ------------------------------------------------------------------------ repo source

class RepoSource:
    """The immutable per-run view of the repository, shared by every conversation.

    Tree indexes and the diff are computed once here rather than per conversation:
    they are the same objects for everyone, and building them once keeps a hunter from
    spending its tool budget on work the parent already did.
    """

    def __init__(self, repo, head_sha, base_sha, commits=(), caps=None, path_tags=None):
        gitsrc.require_sha(head_sha)
        gitsrc.require_sha(base_sha)
        self.repo = repo
        self.head_sha = head_sha
        self.base_sha = base_sha
        self.caps = caps or getattr(repo, "caps", None) or Caps()
        self.commits = tuple(dict.fromkeys(commits))
        self.commit_shas = frozenset(self.commits)
        self.path_tags = dict(path_tags or {})
        self._index_lock = threading.Lock()
        self._indexes = {"head": gitsrc.tree_index(repo, head_sha),
                         "base": gitsrc.tree_index(repo, base_sha)}
        self._changed = None
        self._commit_meta = None
        self._lines = {}

    def index_for(self, label):
        # Agents share one RepoSource and now run concurrently; without the lock two of
        # them could both pass the cap check and index past it.
        with self._index_lock:
            index = self._indexes.get(label)
            if index is not None:
                return index
            if len(self._indexes) - 2 >= MAX_COMMIT_INDEXES:
                raise ToolError("this run indexes at most %d pull-request commits; use head, "
                                "base or a commit already read" % MAX_COMMIT_INDEXES)
            index = gitsrc.tree_index(self.repo, label)
            self._indexes[label] = index
            return index

    def resolve_ref(self, raw):
        """head, base, or one of THIS run's commits. Nothing else is addressable.

        A model-supplied SHA that is merely well formed would otherwise reach the
        baseline or prior-head trees, which the fetch plan also puts in this object
        store and which this conversation was never assigned.
        """
        if not isinstance(raw, str) or not raw:
            raise ToolError("ref must be 'head', 'base' or a commit SHA from list_commits")
        label = raw.strip()
        if label in ("head", "base"):
            return label, getattr(self, label + "_sha")
        if SHA_RE.match(label):
            if label not in self.commit_shas:
                raise ToolError("commit %s is not one of this pull request's commits; "
                                "list_commits returns the only SHAs you may address"
                                % safe_path(label[:12]), probe=True)
            return label, label
        raise ToolError("ref must be 'head', 'base' or a commit SHA from list_commits, got %s"
                        % safe_path(label, 60))

    def changed(self):
        if self._changed is None:
            self._changed = gitsrc.diff_index(self.repo, self.base_sha, self.head_sha,
                                              caps=self.caps)
        return self._changed

    def changed_paths(self):
        entries = self.changed()["files"]
        paths = {entry["path"] for entry in entries}
        paths.update(entry["old_path"] for entry in entries if entry["old_path"])
        return paths

    def changed_entry(self, path):
        for entry in self.changed()["files"]:
            if entry["path"] == path or entry["old_path"] == path:
                return entry
        return None

    def commit_meta(self):
        """SHA, author date and subject for each PR commit, in one git call."""
        if self._commit_meta is not None:
            return self._commit_meta
        meta = [{"sha": sha, "date": "", "subject": ""} for sha in self.commits]
        if self.commits:
            try:
                out = gitsrc.run_git(self.repo,
                                     ["log", "--no-walk=unsorted",
                                      "--format=%H%x1f%aI%x1f%s%x1e"] + list(self.commits)).out
                found = {}
                for record in out.decode("utf-8", "replace").split("\x1e"):
                    fields = record.strip("\n").split("\x1f")
                    if len(fields) == 3:
                        found[fields[0]] = {"sha": fields[0], "date": fields[1],
                                            "subject": fields[2]}
                meta = [found.get(sha, {"sha": sha, "date": "", "subject": ""})
                        for sha in self.commits]
            except GitError:
                pass                     # SHAs alone are still a usable answer
        self._commit_meta = meta
        return meta

    def readable(self, path, ref="head"):
        """Can this run read `path` as source at `ref`? Returns (readable, reason)."""
        entry = self.index_for(ref).get(path)
        if entry is None:
            return False, "not present at %s" % ref
        if entry["type"] == "submodule":
            return False, "submodule, not fetched"
        if entry["type"] == "symlink":
            return True, ""
        if entry["size"] > self.caps.blob_bytes:
            return False, "blob is %d bytes, over the %d-byte limit" % (entry["size"],
                                                                        self.caps.blob_bytes)
        changed = self.changed_entry(path)
        if changed is not None and changed["binary"]:
            reason = "git reports this file as binary"
            if changed["suspected_suppression"]:
                reason += "; its bytes look like text, so a .gitattributes rule may be hiding it"
            return False, reason
        return True, ""

    def line_count(self, path, ref="head"):
        """Line count of a readable text blob, or None when the run cannot read it.

        None is deliberately fail-closed: a record citing a file this run could not open
        must not pass the existence check just because the path exists in the tree.
        """
        key = (ref, path)
        if key in self._lines:
            return self._lines[key]
        count = None
        entry = self.index_for(ref).get(path)
        if entry is not None and entry["type"] != "submodule":
            try:
                result = gitsrc.read_entry(self.repo, entry, self.caps)
                if result["kind"] in ("text", "symlink"):
                    text = result.get("text", result.get("target", ""))
                    count = len(text.splitlines()) or 1
            except (GitError, PathError):
                count = None
        self._lines[key] = count
        return count

    def line_counter(self, ref="head"):
        return lambda path: self.line_count(path, ref)


# ---------------------------------------------------------------------- tool results

class ToolResult:
    """One dispatched tool call: the text the model sees, plus what the parent learned."""

    __slots__ = ("text", "ok", "terminal", "outcome", "tool")

    def __init__(self, text, ok=True, terminal=False, outcome=None, tool=""):
        self.text = text
        self.ok = ok
        self.terminal = terminal
        self.outcome = outcome
        self.tool = tool


class SubmitOutcome:
    """The result of a terminal submit_* call."""

    __slots__ = ("action", "errors", "payload", "round")

    def __init__(self, action, errors=(), payload=None, round=0):
        self.action = action              # accept | feedback | discard
        self.errors = list(errors)
        self.payload = payload
        self.round = round

    @property
    def accepted(self):
        return self.action == "accept"


# ----------------------------------------------------------------------- record gates

def check_blocker_tags(record, index=0):
    """Design 8.1 step 9.

    The blocker tag is what the sidecar's `blocker_kinds` is derived from, and it is the
    difference between "the source trace is complete and only a runtime observation is
    missing" and "the reviewer could not see enough". An untagged blocker would silently
    become the latter. An [execution] blocker without a local plan is a lead a developer
    cannot settle, which is the whole promise of the no-execution mode.
    """
    errors = []
    blockers = record.get("blockers")
    if blockers is None:
        return errors
    if not isinstance(blockers, list):
        return errors
    execution = False
    for position, blocker in enumerate(blockers):
        where = "$[%d].blockers[%d]" % (index, position)
        if not isinstance(blocker, str):
            continue
        if not blocker.startswith(BLOCKER_TAGS):
            errors.append("%s: must start with '[execution] ', '[deployment] ' or "
                          "'[context] '; the tag is what decides how this lead is ranked "
                          "and presented" % where)
            continue
        if blocker.startswith("[execution] "):
            execution = True
    if execution:
        plan = record.get("validation_plan")
        local = plan.get("local") if isinstance(plan, dict) else None
        if not isinstance(local, str) or not local.strip():
            errors.append("$[%d].validation_plan.local: an [execution] blocker means the trace "
                          "is complete and only a runtime observation is missing, so it "
                          "requires a non-empty local plan a developer can run" % index)
    return errors


def blocker_kinds(record):
    """The tags present on a record, in the skill's ranking order. Parent-derived."""
    blockers = record.get("blockers") or []
    present = set()
    for blocker in blockers:
        if isinstance(blocker, str):
            for kind in BLOCKER_KINDS:
                if blocker.startswith("[%s] " % kind):
                    present.add(kind)
    return [kind for kind in BLOCKER_KINDS if kind in present]


def check_read_coverage(record, read_log, ref="head", index=0):
    """Design 8.1 step 4: every cited (file, line) must be inside a range this
    conversation actually read."""
    errors = []
    for field in ("trace", "evidence"):
        entries = record.get(field)
        if not isinstance(entries, list):
            continue
        for position, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            path, line = entry.get("file"), entry.get("line")
            if not isinstance(path, str) or not _is_line(line):
                continue
            if not read_log.covered(path, ref, line):
                errors.append("$[%d].%s[%d]: you did not read %s line %d in this conversation; "
                              "every cited current source location must be re-read before it "
                              "is cited" % (index, field, position, safe_path(path), line))
    return errors


def check_cited_readable(record, source, ref="head", index=0):
    """A citation into a blob this run could not open is a citation into nothing.

    Without this the generic existence check reports such a path as "does not exist",
    which sends the agent hunting for a typo that is not there.
    """
    errors = []
    seen = set()
    for field in ("trace", "evidence"):
        for entry in record.get(field) or []:
            if not isinstance(entry, dict):
                continue
            path = entry.get("file")
            if not isinstance(path, str) or path in seen:
                continue
            seen.add(path)
            if source.index_for(ref).get(path) is None:
                continue
            readable, reason = source.readable(path, ref)
            if not readable:
                errors.append("$[%d].%s: %s exists but this run could not read it (%s), so it "
                              "cannot support a citation" % (index, field, safe_path(path),
                                                             safe_text(reason, 120)))
    return errors


UNIT_STATUSES = ("covered", "candidate", "blocked", "deferred", "out_of_scope",
                 "not_applicable")


def check_unit_patch(units, index_base=0):
    """The state rules a submitted unit patch must satisfy on its own.

    These mirror RECONNAISSANCE.md:141-152, restricted to the fields an agent sends. The
    full ledger, with the parent's own dimensions attached, is what the vendored validator
    checks afterwards.
    """
    errors = []
    for position, unit in enumerate(units):
        if not isinstance(unit, dict):
            continue
        where = "$[%d]" % (index_base + position)
        status = unit.get("status")
        if status not in UNIT_STATUSES:
            errors.append("%s.status: %r is not one of %s"
                          % (where, safe_text(str(status), 40), ", ".join(UNIT_STATUSES)))
            continue
        checks = unit.get("local_checks") or []
        paths = unit.get("reviewed_paths") or []
        unresolved = [u for u in unit.get("unresolved") or [] if str(u).strip()]
        fingerprints = unit.get("result_fingerprints") or []
        if status in ("covered", "candidate", "blocked"):
            if not checks:
                errors.append("%s.local_checks: a %s unit records at least one check"
                              % (where, status))
            if not paths:
                errors.append("%s.reviewed_paths: a %s unit names the paths it reviewed"
                              % (where, status))
        if status == "candidate" and not fingerprints:
            errors.append("%s.result_fingerprints: a candidate unit carries the "
                          "fingerprint of what it found" % where)
        if status != "candidate" and fingerprints:
            errors.append("%s.result_fingerprints: only a candidate unit carries "
                          "fingerprints" % where)
        if status in ("blocked", "deferred", "out_of_scope") and not unresolved:
            errors.append("%s.unresolved: a %s unit states what is still open"
                          % (where, status))
    return errors


def check_unit_paths(units, read_log, index_base=0):
    """Design 8.1 step 5: reviewed_paths must be paths that were opened, and a unit's
    list must be exactly the union of its checks' lists (HUNTING.md:213)."""
    errors = []
    opened = set(read_log.paths())
    for position, unit in enumerate(units):
        if not isinstance(unit, dict):
            continue
        where = "$[%d]" % (index_base + position)
        declared = [p for p in unit.get("reviewed_paths") or [] if isinstance(p, str)]
        for path in declared:
            if path not in opened:
                errors.append("%s.reviewed_paths: %s was never opened in this conversation"
                              % (where, safe_path(path)))
        union = set()
        for check in unit.get("local_checks") or []:
            if isinstance(check, dict):
                union.update(p for p in check.get("reviewed_paths") or []
                             if isinstance(p, str))
        if union and set(declared) != union:
            errors.append("%s.reviewed_paths: must be exactly the union of this unit's "
                          "local_checks reviewed_paths" % where)
    return errors


# -------------------------------------------------------------------------- session

class ToolSession:
    """The tool surface of ONE model conversation.

    Everything that is per-conversation lives here: the read log, the cumulative tool
    output budget, the omissions, the suspected-injection counter and the submit round
    counter. Two conversations share the `RepoSource` and nothing else, which is what
    makes the read-honesty check meaningful -- it can only pass on lines this agent read.
    """

    def __init__(self, source, framer=None, role="hunter", model="deepseek-flash",
                 agent_id="", validator=None, expected_fingerprints=None,
                 offered_fingerprints=None, caps=None):
        if role not in SUBMIT_TOOLS:
            raise SurfaceError("unknown role %r" % role)
        self.source = source
        self.framer = framer or DataFramer()
        self.role = role
        self.model = model
        self.agent_id = agent_id
        self.validator = validator
        self.caps = caps or source.caps
        self.expected_fingerprints = expected_fingerprints
        self.offered_fingerprints = None if offered_fingerprints is None \
            else frozenset(offered_fingerprints)
        self.submit_tool = SUBMIT_TOOLS[role]

        self.read_log = ReadLog()
        self.omissions = Omissions()
        self.budget = self.caps.tool_output_budget(model)
        self.used = 0
        self.exhausted = False
        self.calls = 0
        self.rounds = 0
        self.probes = 0
        self.blocked = False
        self.block_reason = ""
        self.finished = False
        self.result = None

    # ------------------------------------------------------------------ catalogue

    def tools(self, strict=True):
        return tool_definitions(self.role, strict=strict)

    # -------------------------------------------------------------------- budget

    def remaining(self):
        return max(0, self.budget - self.used)

    def _budget_gone(self):
        return self.exhausted or self.remaining() < MIN_USEFUL_BYTES

    def _slice_cap(self, default):
        return max(MIN_USEFUL_BYTES, min(default, self.remaining()))

    def _charge(self, text):
        self.used += len(text.encode("utf-8", "replace"))
        if self.used >= self.budget and not self.exhausted:
            self._exhaust()

    def _exhaust(self):
        self.exhausted = True
        self.omissions.record("tool_budget_exhausted",
                              reason="the conversation spent its %d-byte tool-output budget "
                                     "and was told to finalize" % self.budget,
                              detail="used=%d" % self.used)

    def _finalize(self):
        if not self.exhausted:
            self._exhaust()
        return ToolResult(FINALIZE_NOTICE, ok=False, tool="")

    # ------------------------------------------------------------------ dispatch

    def dispatch(self, call):
        """Execute one ToolCall and return the text the model sees.

        Nothing raises out of here except a programming error: a model that is told why
        a call failed can correct it, and the loop keeps going.
        """
        name = getattr(call, "name", "")
        args = getattr(call, "arguments", None)
        self.calls += 1
        if self.finished:
            return self._error(name, "this conversation already submitted its result; "
                                     "make no further tool calls")
        if name not in READ_SCHEMAS and name != self.submit_tool:
            return self._error(name, "there is no tool called %s in this conversation; "
                                     "available: %s" % (safe_path(name, 60),
                                                        ", ".join(list(READ_TOOLS) +
                                                                  [self.submit_tool])))
        parse_error = getattr(call, "error", "")
        if parse_error:
            message = ("your %s call could not be read: %s. Resend it with every string "
                       "value in double quotes, including globs and patterns."
                       % (safe_path(name, 60), safe_text(parse_error, 160)))
            if name == self.submit_tool:
                # Same round budget and discard rule as any other malformed submit, so an
                # agent that cannot produce valid JSON ends instead of looping to max_turns.
                self.rounds += 1
                return self._feedback([message])
            return self._error(name, message)
        if not isinstance(args, dict):
            return self._error(name, "arguments must be a JSON object, got %s"
                               % _type_name(args))
        self._watch_for_forged_frame(args)

        schema = READ_SCHEMAS.get(name) or SUBMIT_SCHEMAS[self.submit_tool]
        errors = check_schema(schema, args) + _cardinality(name, args)
        if name == self.submit_tool:
            # A malformed submit costs a round like any other: otherwise an agent that
            # cannot produce the argument shape loops until max_turns instead of ending.
            self.rounds += 1
        elif errors:
            return self._error(name, "; ".join(errors[:6]))
        elif self._budget_gone():
            return self._finalize()
        try:
            if name == self.submit_tool:
                return self._feedback(errors) if errors else self._submit(args)
            return getattr(self, "_" + name)(args)
        except ToolError as exc:
            return self._error(name, str(exc), probe=exc.probe)
        except PathError as exc:
            return self._error(name, safe_text(str(exc), MAX_MESSAGE_CHARS),
                               probe=_looks_like_probe(args))
        except SizeGateError as exc:
            return self._error(name, safe_text(str(exc), MAX_MESSAGE_CHARS))
        except GitError as exc:
            return self._error(name, "the repository could not answer that: %s"
                               % safe_text(str(exc), MAX_MESSAGE_CHARS))

    def _watch_for_forged_frame(self, value):
        """An agent echoing the run nonce back is trying to forge a frame boundary."""
        nonce = self.framer.nonce
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, str) and nonce in item:
                self._note_probe()
                return
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)

    def _note_probe(self):
        self.probes += 1
        if self.probes > MAX_PROBES and not self.blocked:
            self.blocked = True
            self.block_reason = "suspected_injection"
            self.omissions.record("suspected_injection",
                                  reason="%d attempts in this conversation to read outside the "
                                         "repository, to use pathspec magic, to address an "
                                         "unassigned commit, or to forge a data frame"
                                         % self.probes)

    def _error(self, tool, message, probe=False):
        if probe:
            self._note_probe()
        text = "ERROR: " + self._neutralise(message)
        self._charge(text)
        return ToolResult(text, ok=False, tool=tool)

    def _neutralise(self, text):
        """Keep the run nonce out of anything the parent says in its own voice."""
        return str(text).replace(self.framer.nonce, "[redacted-frame-marker]")

    def _frame(self, body, kind, **attrs):
        # DataFramer neutralises the nonce inside content but not inside attribute
        # values, and every path attribute here is repo-derived. The nonce is
        # unguessable, so this is belt and braces rather than a live hole.
        attrs = {key: self._neutralise(value) if isinstance(value, str) else value
                 for key, value in attrs.items()}
        text = self.framer.wrap(body, kind, **attrs)
        self._charge(text)
        return ToolResult(text, tool=kind)

    # --------------------------------------------------------------- read tools

    def _ref(self, raw):
        label, sha = self.source.resolve_ref(raw)
        return label, sha, self.source.index_for(label)

    def _read_file(self, args):
        label, _sha, index = self._ref(args["ref"])
        entry = gitsrc.resolve_path(index, args["path"])
        path = entry["path"]
        result = gitsrc.read_entry(self.source.repo, entry, self.caps)
        kind = result["kind"]

        if kind == "submodule":
            self.omissions.record("submodule", path, label,
                                  "submodule commit %s is not fetched" % result["commit"][:12])
            return self._frame("submodule at commit %s; its contents are not part of this run"
                               % result["commit"], "submodule", path=path, ref=label)
        if kind == "symlink":
            # The link's own blob text IS the file: it is never dereferenced, so a link
            # to /proc/self/environ is just a harmless string here.
            self.read_log.record(path, label, 1, 1, source="read_file")
            return self._frame(result["target"], "symlink", path=path, ref=label,
                               blob=result["oid"])
        if kind == "oversize":
            self.omissions.record("oversize", path, label,
                                  "blob is %d bytes, over the %d-byte limit"
                                  % (result["size"], result["limit"]))
            raise ToolError("%s is %d bytes, over this run's %d-byte limit; it is recorded as "
                            "not reviewed" % (safe_path(path), result["size"], result["limit"]))
        if kind == "lfs":
            self.omissions.record("lfs", path, label, "git-lfs object was not fetched")
            raise ToolError("%s is a git-lfs pointer and the object was not fetched; it is "
                            "recorded as not reviewed" % safe_path(path))
        if kind == "binary":
            self.omissions.record("binary", path, label,
                                  "binary content (NUL byte in the first 8 KiB)")
            raise ToolError("%s is binary and cannot be read as source; it is recorded as not "
                            "reviewed" % safe_path(path))

        lines = result["text"].splitlines()
        total = len(lines)
        start = args["start_line"] or 1
        if start > total:
            raise ToolError("%s has %d lines at %s; start_line %d is past the end"
                            % (safe_path(path), total, label, start))
        requested_end = args["end_line"] or (start + self.caps.read_lines - 1)
        window_end = min(requested_end, total, start + self.caps.read_lines - 1)
        byte_cap = self._slice_cap(self.caps.read_bytes)

        out, used, cut_long, delivered = [], 0, False, start - 1
        for number in range(start, window_end + 1):
            line = lines[number - 1]
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
                cut_long = True
            rendered = "%6d\t%s" % (number, line)
            if used + len(rendered) > byte_cap and delivered >= start:
                break
            out.append(rendered)
            used += len(rendered) + 1
            delivered = number

        if delivered < start:
            raise ToolError("no budget left to return even one line of %s" % safe_path(path))
        self.read_log.record(path, label, start, delivered, source="read_file")
        if delivered < requested_end and delivered < total:
            self.omissions.record("read_truncated", path, label,
                                  "lines %d-%d were requested; %d-%d were returned"
                                  % (start, min(requested_end, total), start, delivered),
                                  detail="next_line=%d" % (delivered + 1))
        if cut_long:
            self.omissions.record("long_lines_cut", path, label,
                                  "one or more lines were cut at %d characters"
                                  % MAX_LINE_CHARS)
        body = "\n".join(out)
        if delivered < total:
            body += ("\n[%d of %d lines shown; call read_file again with start_line=%d]"
                     % (delivered - start + 1, total, delivered + 1))
        return self._frame(body, "file", path=path, ref=label, blob=entry["oid"],
                           lines="%d-%d" % (start, delivered), total=total)

    def _grep(self, args):
        label, sha, index = self._ref(args["ref"])
        fixed = True if args["fixed_string"] is None else args["fixed_string"]
        result = gitsrc.grep(self.source.repo, sha, args["pattern"], index,
                             path_glob=args["path_glob"], fixed_string=fixed,
                             ignore_case=bool(args["ignore_case"]), caps=self.caps)
        byte_cap = self._slice_cap(self.caps.grep_bytes)
        out, used, shown = [], 0, 0
        for hit in result["hits"]:
            rendered = "%s:%d: %s" % (hit["path"], hit["line"], hit["text"])
            if used + len(rendered) > byte_cap and shown:
                break
            out.append(rendered)
            used += len(rendered) + 1
            shown += 1
            self.read_log.grep_hit(hit["path"], label, hit["line"])
        cut = shown < len(result["hits"])
        if result["truncated"] or cut:
            self.omissions.record("grep_truncated", "", label,
                                  "the search returned more than the %d hits shown; results "
                                  "for this pattern are incomplete" % shown,
                                  detail="pattern_chars=%d" % len(args["pattern"]))
        body = "\n".join(out) if out else "no match"
        if result["truncated"] or cut:
            body += "\n[truncated: narrow the pattern or the path_glob]"
        return self._frame(body, "grep", ref=label, hits=shown,
                           files=result["matched_files"])

    def _list_dir(self, args):
        label, _sha, index = self._ref(args["ref"])
        result = gitsrc.list_dir(index, args["path"] or "", bool(args["recursive"]),
                                 caps=self.caps)
        rows = ["%-9s %10s  %s" % (entry["type"],
                                   entry["size"] if entry["size"] >= 0 else "-",
                                   entry["path"])
                for entry in result["entries"]]
        if result["truncated"]:
            self.omissions.record("list_dir_truncated", args["path"] or "", label,
                                  "%d of %d entries were listed"
                                  % (len(result["entries"]), result["total"]))
            rows.append("[%d of %d entries shown]" % (len(result["entries"]),
                                                      result["total"]))
        return self._frame("\n".join(rows) or "empty", "dir",
                           path=args["path"] or "/", ref=label, total=result["total"])

    def _list_changed_files(self, args):
        entries = self.source.changed()["files"]
        page = args["page"] or 1
        start = (page - 1) * CHANGED_PAGE
        window = entries[start:start + CHANGED_PAGE]
        if not window and entries:
            raise ToolError("page %d is past the end; this pull request changes %d files"
                            % (page, len(entries)))
        rows = []
        for entry in window:
            path = entry["path"]
            readable, reason = self.source.readable(path) if entry["status"] != "D" \
                else (False, "deleted by this pull request")
            if not readable:
                self.omissions.record("unreadable_changed_file", path, "head", reason)
            tags = self.source.path_tags.get(path) or []
            rows.append("%s %-4s +%-5d -%-5d %-9s %s%s%s"
                        % (entry["status"],
                           "bin" if entry["binary"] else "text",
                           entry["added"], entry["removed"],
                           "readable" if readable else "SKIPPED",
                           path,
                           "  <- %s" % entry["old_path"] if entry["old_path"] else "",
                           "  [%s]" % ",".join(sorted(tags)) if tags else ""))
            if not readable:
                rows.append("        not reviewed: %s" % reason)
            if entry["hunks_omitted"]:
                self.omissions.record("hunks_omitted", path, "head",
                                      "this pull request changes more files than the run "
                                      "computes hunks for")
        totals = self.source.changed()["totals"]
        body = "\n".join(rows)
        body += ("\n[page %d of %d; %d files, +%d -%d, %d binary]"
                 % (page, max(1, -(-len(entries) // CHANGED_PAGE)), totals["files"],
                    totals["added"], totals["removed"], totals["binary"]))
        return self._frame(body, "changed_files", ref="head", page=page)

    def _get_diff(self, args):
        path = gitsrc.normalize_path(args["path"])
        entry = self.source.changed_entry(path)
        if entry is None:
            raise ToolError("%s is not changed by this pull request; list_changed_files has "
                            "the %d paths that are"
                            % (safe_path(path), self.source.changed()["totals"]["files"]))
        if entry["binary"]:
            reason = "git reports this file as binary"
            if entry["suspected_suppression"]:
                reason += ("; its bytes look like text, so a .gitattributes rule may be "
                           "hiding the diff")
            self.omissions.record("binary_diff", entry["path"], "head", reason)
            raise ToolError("no textual diff for %s: %s" % (safe_path(entry["path"]), reason))

        context = 3 if args["context"] is None else args["context"]
        byte_cap = self._slice_cap(self.caps.tool_output_bytes)
        diff = gitsrc.diff_text(self.source.repo, self.source.base_sha, self.source.head_sha,
                                entry["path"], entry["old_path"], context=context,
                                max_bytes=byte_cap)
        hunks = _split_hunks(diff["text"])
        first = args["start_hunk"] or 0
        if first and first >= len(hunks):
            raise ToolError("%s has %d hunks; start_hunk %d is past the end"
                            % (safe_path(entry["path"]), len(hunks), first))

        out, used, lines_used, shown = [], 0, 0, first
        for position in range(first, len(hunks)):
            header, body_lines, old_range, new_range = hunks[position]
            block = "\n".join([header] + body_lines)
            if (lines_used + len(body_lines) + 1 > self.caps.diff_lines
                    or used + len(block) > byte_cap) and shown > first:
                break
            out.append(block)
            used += len(block) + 1
            lines_used += len(body_lines) + 1
            shown = position + 1
            if new_range:
                self.read_log.record(entry["path"], "head", new_range[0], new_range[1],
                                     source="diff")
            if old_range and entry["old_path"]:
                self.read_log.record(entry["old_path"], "base", old_range[0], old_range[1],
                                     source="diff")
            elif old_range:
                self.read_log.record(entry["path"], "base", old_range[0], old_range[1],
                                     source="diff")

        if shown < len(hunks) or diff["truncated"]:
            self.omissions.record("diff_truncated", entry["path"], "head",
                                  "hunks %d-%d of %d were not shown"
                                  % (shown, len(hunks) - 1, len(hunks)),
                                  detail="next_hunk=%d" % shown)
        body = "\n".join(out) or "no textual hunks"
        if shown < len(hunks):
            body += "\n[hunks %d-%d not shown; call get_diff with start_hunk=%d]" % (
                shown, len(hunks) - 1, shown)
        return self._frame(body, "diff", path=entry["path"], ref="merge_base..head",
                           blob=entry["new_oid"], hunks="%d-%d" % (first, max(first, shown - 1)),
                           total=len(hunks))

    def _list_commits(self, args):
        meta = self.source.commit_meta()
        if not meta:
            return self._frame("this pull request has no commits of its own", "commits",
                               ref="head")
        rows = ["%s  %s  %s" % (item["sha"], item["date"] or "-", item["subject"])
                for item in meta]
        body = "\n".join(rows)
        if len(meta) >= 250:
            self.omissions.record("commits_truncated", "", "head",
                                  "this pull request has more commits than the run lists")
        return self._frame(body, "commits", ref="head", count=len(meta))

    def _get_commit_patch(self, args):
        label, sha = self.source.resolve_ref(args["sha"])
        if label in ("head", "base"):
            raise ToolError("get_commit_patch takes a commit SHA from list_commits, not a "
                            "ref name")
        byte_cap = self._slice_cap(self.caps.tool_output_bytes)
        patch = gitsrc.commit_patch(self.source.repo, sha, args["path"], max_bytes=byte_cap)
        if not patch["available"]:
            self.omissions.record("shallow_boundary", args["path"] or "", sha,
                                  "the parent of %s is outside the fetched depth"
                                  % sha[:12])
            raise ToolError("the parent of commit %s was not fetched, so its patch cannot be "
                            "computed here" % safe_path(sha[:12]))
        text = patch["text"]
        lines = text.splitlines()
        if len(lines) > self.caps.diff_lines:
            lines = lines[:self.caps.diff_lines]
            patch["truncated"] = True
        if patch["truncated"]:
            self.omissions.record("commit_patch_truncated", args["path"] or "", sha,
                                  "the patch of %s is longer than this run shows" % sha[:12])
        # Recorded against the commit, never against head: reading a historical patch is
        # not reading the current source a citation has to rest on.
        body = "\n".join(lines) or "this commit changed nothing on that path"
        if patch["truncated"]:
            body += "\n[patch truncated]"
        return self._frame(body, "commit_patch", ref=sha, path=args["path"] or "",
                           parent=(patch["parent"] or "root"))

    # ------------------------------------------------------------------- submit

    def _submit(self, args):
        records, units, errors = self._extract(args)
        for index, record in enumerate(records):
            errors.extend(self.gate_record(record, index))
        if units:
            errors.extend(check_unit_paths(units, self.read_log))
            errors.extend(check_unit_patch(units))
            # Not validate_ledger(): what an agent submits is a PATCH to a unit the parent
            # owns -- status, owner, checks, fingerprints -- while the vendored validator
            # requires a whole ledger unit (canonical_refs, surface, boundary, subsystem,
            # attack_class). Running it here produced 28 errors on a perfectly good
            # submission, so no hunter could ever finish. The parent merges the patch into
            # its own unit and runs the vendored validator over the complete ledger.
        if errors:
            return self._feedback(errors)

        payload = {"role": self.role, "agent_id": self.agent_id,
                   "records": records, "units": units,
                   "blocker_kinds": [blocker_kinds(record) for record in records],
                   "same_root_cause_as": args.get("same_root_cause_as")}
        self.finished = True
        self.result = payload
        outcome = SubmitOutcome("accept", payload=payload, round=self.rounds)
        text = ACCEPTED_NOTICE
        self._charge(text)
        return ToolResult(text, terminal=True, outcome=outcome, tool=self.submit_tool)

    def _extract(self, args):
        """Split a submit payload into findings-shaped records and ledger units.

        A hunter names its verdict `proposed_verdict` (HUNTING.md:208-211) and the
        vendored schema knows only `verdict`. Renaming that one key is a projection, not
        a repair: no content changes, and the value is still whatever the model chose.
        """
        errors = []
        if self.role == "verifier":
            record = dict(args["record"])
            if args["decision"] != record.get("verdict"):
                errors.append("$[0].verdict: must equal arguments.decision")
            offered = self.offered_fingerprints
            prior = args["same_root_cause_as"]
            if prior is not None and offered is not None and prior not in offered:
                errors.append("arguments.same_root_cause_as: must be null or one of the prior "
                              "fingerprints the parent offered")
            return [record], [], errors
        if self.role == "hunter":
            records = []
            for candidate in args["candidates"]:
                record = dict(candidate)
                record["verdict"] = record.pop("proposed_verdict", None)
                record.pop("coverage_id", None)
                records.append(record)
            return records, list(args["units"]), errors
        return [], list(args.get("units") or []), errors

    def gate_record(self, record, index=0):
        """Design 8.1 for one record. The parent never edits content (VAL:89)."""
        errors = []
        if not isinstance(record, dict):
            return ["$[%d]: expected one finding object" % index]
        candidate = validate.strip_optional_nulls(record)
        errors.extend(message for _i, message in validate.check_verdicts([candidate]))
        errors.extend(check_blocker_tags(candidate, index))
        errors.extend(check_cited_readable(candidate, self.source, "head", index))
        errors.extend(message for _i, message in
                      validate.check_existence([candidate], self.source.line_counter("head")))
        if self.role == "verifier":
            errors.extend(check_read_coverage(candidate, self.read_log, "head", index))
        if self.expected_fingerprints is not None:
            fingerprint = candidate.get("fingerprint")
            allowed = set(self.expected_fingerprints)
            if self.offered_fingerprints:
                allowed |= set(self.offered_fingerprints)
            if fingerprint not in allowed:
                errors.append("$[%d].fingerprint: must be one of %s; the parent assembles "
                              "fingerprints and a result cannot choose its own"
                              % (index, ", ".join(sorted(repr(f) for f in allowed))))
        if self.validator is not None:
            errors.extend(_reindex(self.validator.validate_findings([candidate]), index))
        record.clear()
        record.update(candidate)
        return errors

    def _feedback(self, errors):
        """Return the validator's exact messages to this same conversation, at most twice.

        Only control, format and bidi characters are stripped: those would let a message
        that quotes a model-chosen path close a data frame or reverse the text around it.
        The wording itself is untouched, because a paraphrased error is a repair.
        """
        cleaned = [self._neutralise(safe_text(message, MAX_MESSAGE_CHARS))
                   for message in _unique(errors)]
        discard = self.rounds > MAX_SUBMIT_ROUNDS
        header = DISCARD_NOTICE if discard else FEEDBACK_HEADER % self.submit_tool
        text = header + "\n" + "\n".join("- " + message for message in cleaned)
        self._charge(text)
        if discard:
            self.finished = True
        outcome = SubmitOutcome("discard" if discard else "feedback", errors=cleaned,
                                round=self.rounds)
        return ToolResult(text, ok=False, terminal=discard, outcome=outcome,
                          tool=self.submit_tool)

    # -------------------------------------------------------------------- report

    def state(self):
        """Everything the ledger and the report need to know about this conversation.

        `reviewed_paths` backs the ledger; `omitted` backs the "Not reviewed" section.
        A unit whose conversation ended with `tool_budget_exhausted` or `blocked` set
        must never be recorded as covered.
        """
        return {
            "role": self.role,
            "agent_id": self.agent_id,
            "model": self.model,
            "tool_calls": self.calls,
            "tool_output_bytes": self.used,
            "tool_output_budget": self.budget,
            "tool_budget_exhausted": self.exhausted,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "suspected_injection_attempts": self.probes,
            "submit_rounds": self.rounds,
            "reviewed_paths": self.read_log.paths(),
            "read": self.read_log.summary(),
            "omitted": self.omissions.as_dicts(),
        }


def _looks_like_probe(args):
    """A rejected path that reads as an attempt to leave the repository.

    Only consulted after `normalize_path` has already refused the value, so an honest
    in-repo `.npmrc` or `.env` never reaches this test.
    """
    for key in ("path", "path_glob", "sha"):
        value = args.get(key)
        if not isinstance(value, str) or not value:
            continue
        if value[0] in ("/", "~", ":", "-") or "\\" in value:
            return True
        if ".." in value.split("/"):
            return True
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            return True
        lowered = value.lower()
        if any(marker in lowered for marker in _PROBE_MARKERS):
            return True
    return False


def _split_hunks(text):
    """Split a unified diff into (header, body, old_range, new_range) per hunk.

    The `diff --git` preamble is dropped: its quoted, escaped filenames are model-facing
    noise, and the path the tool was asked for is the authoritative answer.
    """
    hunks, current = [], None
    for line in text.split("\n"):
        match = _HUNK_RE.match(line)
        if match:
            old_start, old_lines, new_start, new_lines = match.groups()
            old_lines = 1 if old_lines is None else int(old_lines)
            new_lines = 1 if new_lines is None else int(new_lines)
            old_range = (int(old_start), int(old_start) + old_lines - 1) if old_lines else None
            new_range = (int(new_start), int(new_start) + new_lines - 1) if new_lines else None
            current = [line, [], old_range, new_range]
            hunks.append(current)
        elif current is not None:
            current[1].append(line)
    return [(header, body, old_range, new_range)
            for header, body, old_range, new_range in hunks]


def _reindex(messages, index):
    """Rewrite the `$[0]` prefix of a one-record document onto the record's real slot."""
    if index == 0:
        return list(messages)
    return [message.replace("$[0]", "$[%d]" % index, 1) if message.startswith("$[0]")
            else message for message in messages]


def _unique(messages):
    seen, out = set(), []
    for message in messages:
        if message not in seen:
            seen.add(message)
            out.append(message)
    return out
