"""Turning verified records into everything the publish job posts.

Every string in a record was written by a model that read pull-request content, so
this module treats all of it -- titles, descriptions, blockers, validation plans, and
the repository paths the records cite -- as attacker-controlled text that must be made
inert before it reaches a GitHub surface. Rendering is entirely deterministic: no model
is consulted here, and no model output ever names a GitHub resource. Code picks the
anchors, the links, the order and the wording around the quoted text.

Three properties this module exists to guarantee:

1. Nothing a record says can forge structure. Mentions and issue references are
   neutralised with HTML entities (`&#64;`, `&#35;`) rather than invisible characters,
   because bidi/zero-width stripping is a final pass elsewhere and would restore a
   U+2060-separated mention into a live ping. Entities are ASCII and survive it.
2. Nothing a record says is presented as a command to run. `validation_plan.local` is
   the one field the UX asks a human to act on, so it renders as labelled, quoted,
   model-written text -- never a copy-ready fenced shell block -- and plans shaped like
   an install, a fetch, a pipe into a shell, `sudo`, `chmod` or a redirection are
   flagged above the quote.
3. Nothing the run failed to look at disappears. The summary always carries the
   partial-coverage statement and the "Not reviewed" list, even when both are empty.

Nothing here carries a severity. The run executes no code, so findings.json holds only
`needs_validation` and `rejected`, and the P1/P2/P3 label is an ordering derived from
HUNTING.md:7, stated as such on every surface that shows it.

**This module is the single owner of both.** It writes every string that reaches a
GitHub surface, and it decides where an inline comment hangs. `publish.py` owns the live
data and the API calls: it fetches the pull request's files at the analysed head, builds
a `DiffIndex` from those patches, asks `select_anchor` where each lead goes, and posts
what comes back byte for byte. Design 6.3 requires the anchor to be computed in the
publish job from live data -- the DATA is live, the LOGIC is here. The split exists
because `sanitize_for_github` is not idempotent: it escapes `&` into `&amp;`, so text
that passed through two sanitising modules would render as its own escape sequence. The
rule is that text is made inert here, exactly once, and publish verifies it with
`inert_problems` rather than escaping it again.
"""
import hashlib
import hmac
import json
import re
import unicodedata
import urllib.parse

from . import fingerprint as fpmod
from .tools import blocker_kinds

# ------------------------------------------------------------------------ constants

TITLE_LIMIT = 160
BODY_LIMIT = 1_200
PATH_LIMIT = 200
PLAN_LIMIT = 900
SUMMARY_LIMIT = 60_000
INLINE_LIMIT = 6_000
MAX_TRACE_LINES = 8
MAX_LEADS_IN_SUMMARY = 25
MAX_NOT_REVIEWED = 60
# Every list below a lead is model-derived and therefore unbounded at the source.
MAX_LIST_ITEMS = 100

# The markers live here because this module writes them; publish only matches on them.
MARKER_PREFIX = "<!-- ai-security-review v1"
MARKER = MARKER_PREFIX + " run=%s -->"
INLINE_MARKER = "<!-- sa-fp:%s rh:%s -->"
INLINE_MARKER_RE = re.compile(r"<!--\s*sa-fp:(\S+)\s+rh:([0-9a-f]{6,64})\s*-->")
# A fingerprint is `sa1:<class>:<path>@<symbol>:r<n>`, each component capped by the
# fingerprint module, so it can run to several hundred characters. The dedupe marker
# carries it whole, and the limit is derived from that module rather than guessed:
# truncating the key would make two leads on one long path collide, and a collision
# here silently suppresses a comment.
FINGERPRINT_LIMIT = fpmod.MAX_COMPONENT * 2 + 80

TRUNCATED = " \\[truncated\\]"

PARTIAL_NOTICE = (
    "This is a **partial, diff-scoped, quick-profile pass** over "
    "`merge-base...head` only. No pull-request code was executed, so nothing below is a "
    "confirmed vulnerability and nothing has a severity -- these are leads to check. "
    "It is advisory: it is not a merge gate, and because prompt injection in the "
    "reviewed content can suppress a finding, a green check is not a clean bill.")

# The one phrase both the analyze-side document and the publish-side frame use to
# announce a gap, so publish can tell whether the document already said it.
INCOMPLETE_HEADING = "**Incomplete run**"

ORDER_FOOTNOTE = (
    "\\* Order groups leads by the skill's hunting order (lowest-trust entry, then "
    "asset value, then whether the trace touches changed lines). It is **not** a "
    "severity: `needs_validation` has no severity.")

# Every comment, not only the summary, has to say what kind of pass produced it: an
# inline comment is read on its own, far from the summary that frames the run.
INLINE_FOOTER = ("<sub>From a partial, diff-scoped, quick-profile pass over "
                 "merge-base...head. No pull-request code was executed, so this is a "
                 "lead rather than a confirmed vulnerability and it has no severity. "
                 "This check does not block a merge by default, and a green check is "
                 "not a clean bill.</sub>")

# The words every posted surface is checked for. They appear in PARTIAL_NOTICE, in
# ORDER_FOOTNOTE, in INLINE_FOOTER and in the check-run output, so a surface that has
# lost them has lost its framing and is rebuilt rather than posted with a patch applied.
FRAMING_WORDS = ("partial", "severity")

CHECK_RUNNING_TITLE = "Running"
CHECK_RUNNING_SUMMARY = ("A partial, diff-scoped, quick-profile security review is "
                         "running. No pull-request code is executed, so nothing it "
                         "reports will carry a severity. It does not block a merge by "
                         "default.")

PLAN_LABEL = ("To settle it locally -- **model-written, unverified**. It was produced by "
              "a language model from pull-request content; read it before you act on it, "
              "and never paste it into a shell unchecked:")

PLAN_WARNING = ("**Do not run this as written.** The plan matches %s. A validation plan "
                "is model-written text derived from the pull request, not a command this "
                "action vetted.")

# Cc control, Cf format (bidi overrides, zero-width joiners, U+2060), Zl/Zp separators.
_STRIP_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))
# Default_Ignorable code points that are not Cf, so `unicodedata.category` misses them.
_EXTRA_INVISIBLE = frozenset((
    "ᅟ", "ᅠ", "឴", "឵", "⠀", "ㅤ", "ﾠ"))

# Escaped everywhere: each one starts a GFM inline or block construct.
_MD_CHARS = "`*_[]()!|~{}"
_MD_ESCAPE = {ch: "\\" + ch for ch in _MD_CHARS}
# Only meaningful at the start of a line, where they open a list or a thematic break.
# The ordered-list case escapes the dot, not the digit: a backslash before a digit is
# not a markdown escape, so it would be rendered as a literal backslash.
_LINE_LEAD = re.compile(r"^([-+=])")
_LINE_ORDERED = re.compile(r"^(\d{1,9})\.")
_SCHEME = re.compile(r"(?i)\b([A-Za-z][A-Za-z0-9+.-]{0,20})://")
_BARE_HOST = re.compile(r"(?i)\bwww\.")
_DANGER_SCHEME = re.compile(r"(?i)\b(javascript|data|vbscript|file):")
_TOKEN_CHARS = re.compile(r"[^A-Za-z0-9._:/@+-]")

# Shapes a human should not be handed as a ready-to-run instruction. Matched against the
# RAW plan text, before escaping, because escaping rewrites the very characters
# (`|`, `://`) that make a pipeline or a fetch recognisable.
PLAN_SHAPES = (
    ("package-install", re.compile(
        r"(?i)\b(?:npm|pnpm|yarn|bun|npx|pip|pip3|pipx|uv|gem|cargo|go|apt|apt-get|dnf|"
        r"yum|apk|brew|composer|poetry|conda)\s+(?:-\S+\s+)*(?:install|add|get|i)\b")),
    ("network-fetch", re.compile(
        r"(?i)(\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|invoke-webrequest|iwr)\b"
        r"|\bhttps?://)")),
    ("shell-pipeline", re.compile(
        r"(?i)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|python3?|node|deno|perl|ruby|"
        r"php|tee|xargs)\b")),
    ("sudo", re.compile(r"(?i)(?:^|[;&|\s])(?:sudo|doas|runas)\b")),
    ("chmod", re.compile(r"(?i)(?:^|[;&|\s])(?:chmod|chown|chattr|chgrp|setfacl)\b")),
    ("redirection", re.compile(r"(?:^|\s)>{1,2}\s*[\w./~$'\"-]|\b\d?>&\d\b")),
)

# Every kind `tools.Omissions` can record, plus the parent-side gates, in one place so
# the "Not reviewed" section never prints a bare machine word at a reviewer.
OMISSION_REASONS = {
    "oversize": "over the blob read limit",
    "binary": "binary content",
    "binary_diff": "git reported the diff as binary",
    "lfs": "git-lfs object was not fetched",
    "submodule": "submodule, not fetched",
    "read_truncated": "read truncated at the line limit",
    "long_lines_cut": "long lines cut",
    "grep_truncated": "search results truncated",
    "list_dir_truncated": "directory listing truncated",
    "unreadable_changed_file": "changed file could not be read",
    "hunks_omitted": "diff hunks omitted (PR-size gate)",
    "diff_truncated": "diff truncated",
    "commits_truncated": "commit list truncated",
    "shallow_boundary": "commit parent beyond the shallow fetch",
    "commit_patch_truncated": "commit patch truncated",
    "tool_budget_exhausted": "tool-output budget exhausted",
    "pack_truncated": "warm-start context pack truncated",
    "suspected_injection": "suspected injection; that result was discarded",
    "size_gate": "pull-request size gate",
    "api_truncated": "GitHub API response truncated",
}

UNIT_REASONS = {
    "planned": "planned but never assigned",
    "in_progress": "assigned but never closed",
    "deferred": "deferred",
    "blocked": "blocked",
    "out_of_scope": "out of scope for this diff",
    "not_applicable": "not applicable",
    "unrepresentable": "the skill's validator cannot represent this path",
}

PRIORITIES = ("P1", "P2", "P3")
SARIF_LEVELS = {"P1": "warning", "P2": "note", "P3": "note"}
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
                "sarif-schema-2.1.0.json")
SARIF_RULE_DESCRIPTION = (
    "Lead reported by the security-audit skill running with execution disabled. The "
    "SARIF level is derived from this run's P1/P2/P3 ordering (P1 -> warning, P2 and P3 "
    "-> note), which orders leads by the skill's hunting order and is NOT a severity: "
    "no code was executed, so no result here is a confirmed vulnerability and none "
    "carries a severity. partialFingerprints are set by this action; GitHub cannot "
    "compute primaryLocationLineHash because the repository is never checked out.")


class RenderError(Exception):
    """Raised only for programming errors here -- never for record content."""


# ------------------------------------------------------------------------ sanitiser

def strip_unsafe_characters(text):
    """Remove bidi, zero-width, format and control characters; fold exotic spaces.

    Run before escaping and never after: if it ran last it would undo any invisible
    separator used to break up a mention, which is exactly why mentions are neutralised
    with ASCII entities instead.
    """
    out = []
    for ch in text:
        if ch in "\n\r\t":
            out.append(ch)
            continue
        if ch in _EXTRA_INVISIBLE:
            continue
        category = unicodedata.category(ch)
        if category in _STRIP_CATEGORIES:
            continue
        out.append(" " if category == "Zs" else ch)
    return "".join(out)


def sanitize_for_github(text, limit=BODY_LIMIT, allow_newlines=False):
    """Make one untrusted string inert on every GitHub markdown surface.

    The passes are ordered, and the order is load-bearing. Entity insertion has to come
    last and `#` has to be entitied before `@`, `:` and `.`, because every entity this
    function inserts (`&#64;`, `&#58;`, `&#46;`) itself contains a `#` that must not be
    rewritten a second time.
    """
    raw = "" if text is None else (text if isinstance(text, str) else str(text))
    raw = strip_unsafe_characters(raw)
    if allow_newlines:
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw).strip()
    else:
        raw = re.sub(r"\s+", " ", raw).strip()
    cut = False
    if limit and len(raw) > limit:
        raw, cut = raw[:limit], True
    escaped = _escape(raw)
    return escaped + TRUNCATED if cut else escaped


def sanitize_path(path, limit=PATH_LIMIT):
    """A repository path is chosen by whoever opened the pull request.

    It reaches the same surfaces as record text -- the leads list, "Not reviewed",
    inline bodies, link labels -- so it gets the same treatment and its own shorter cap.
    """
    return sanitize_for_github(path, limit=limit, allow_newlines=False)


def _escape(raw):
    """HTML-escape, then markdown-escape, then entity the linkifying characters."""
    text = raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\\", "\\\\")
    text = "".join(_MD_ESCAPE.get(ch, ch) for ch in text)
    text = "\n".join(_LINE_ORDERED.sub(r"\1\\.", _LINE_LEAD.sub(r"\\\1", line))
                     for line in text.split("\n"))
    # `#` first: every entity inserted below contains one.
    text = text.replace("#", "&#35;")
    text = text.replace("@", "&#64;")
    text = _SCHEME.sub(r"\1&#58;//", text)
    text = _DANGER_SCHEME.sub(r"\1&#58;", text)
    return _BARE_HOST.sub("www&#46;", text)


def token(value, limit=PATH_LIMIT):
    """A parent-owned identifier (fingerprint, handle, coverage id) fit for a marker.

    Anything outside the schema's own fingerprint charset is dropped rather than
    escaped, so an HTML comment cannot be closed from inside one.
    """
    text = _TOKEN_CHARS.sub("", strip_unsafe_characters(str(value or "")))
    return text[:limit]


def code(value, limit=64):
    """A code span for parent-generated identifiers only: SHAs, counts, handles.

    `@` is dropped rather than kept, so a fingerprint routed here by mistake cannot
    become a mention. GitHub very probably does not linkify inside a code span, but
    nothing in this module rests on "very probably"; anything carrying an `@` goes
    through `reference_markup` instead.
    """
    return "`%s`" % token(value, limit).replace("@", "")


def reference_markup(value):
    """A fingerprint or an opaque handle as displayed text, never as a code span.

    A raw fingerprint is `class:path@symbol`, and `@symbol` is a plausible GitHub
    login. Escaped plain text entities the `@` and cannot ping anyone.
    """
    return sanitize_for_github(token(value), limit=PATH_LIMIT)


def blob_url(repository, ref, path, line=None):
    """A permalink built by the parent, from a percent-encoded path.

    The path may legally contain `#` or `?`, which would otherwise split the URL and,
    in the write-scoped publish job, the REST paths built next to it.
    """
    quoted = urllib.parse.quote(path or "", safe="/")
    url = "https://github.com/%s/blob/%s/%s" % (token(repository, 140), token(ref, 64),
                                                quoted)
    return url + ("#L%d" % int(line) if line else "")


def link(label, url):
    """A markdown link whose label is already escaped, so it cannot close early."""
    return "[%s](%s)" % (label, url.replace(")", "%29").replace(" ", "%20"))


# --------------------------------------------------------------- inertness checks

# Characters that survive a naive escape and still change what a reader sees, plus the
# three markdown shapes no correctly rendered body can contain.
_UNSAFE_RUNES = re.compile(
    "[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f\\u200b-\\u200f"
    "\\u2028\\u2029\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]")
_IMAGE_EMBED = re.compile(r"(?<!\\)!\[")
_SUGGESTION = re.compile(r"`{3,}\s*suggestion", re.IGNORECASE)
_OFFSITE_LINK = re.compile(r"\]\(\s*(?!https://github\.com/)[A-Za-z][A-Za-z0-9+.-]*:")


def inert_problems(text):
    """Why a finished string may not be posted as it stands.

    This is a verification, not a sanitisation. `sanitize_for_github` already made each
    model string inert field by field, and running it again over the finished document
    would escape this module's own markdown -- `&amp;` would become `&amp;amp;` and every
    `\\*` a literal backslash. So the publish job checks instead of escaping, and what it
    checks for is the small set of shapes a correctly rendered body cannot contain. A
    body that fails is rebuilt from its record here, never patched up there.
    """
    problems = []
    if _UNSAFE_RUNES.search(text or ""):
        problems.append("control, bidi or zero-width characters")
    if _IMAGE_EMBED.search(text or ""):
        problems.append("an image embed")
    if _SUGGESTION.search(text or ""):
        problems.append("a suggestion block")
    if _OFFSITE_LINK.search(text or ""):
        problems.append("a link that does not point at github.com")
    return problems


def framing_problems(text):
    """Whether a surface still says what kind of pass produced it.

    An inline comment is read on its own, far from the summary that frames the run, so a
    body that does not name the pass as partial and disclaim severity is not publishable.
    """
    lowered = (text or "").lower()
    if any(word not in lowered for word in FRAMING_WORDS):
        return ["no partial-pass framing"]
    return []


_CUT_NOTICE = ("\n\n_This comment reached its length limit; the rest is in the run "
               "artifact._")


def _cut(text, limit, notice=_CUT_NOTICE):
    """Cut a composed document at a line boundary, closing anything the cut opened.

    Cutting inside a collapsed section would swallow everything after it, including the
    notice that says the text was cut; cutting mid-line could split an HTML entity and
    leave a live `&` behind.
    """
    if not limit or len(text) <= limit:
        return text
    kept = text[:max(0, limit - len(notice) - 32)].rsplit("\n", 1)[0]
    kept += "</details>" * max(0, kept.count("<details>") - kept.count("</details>"))
    return kept + notice


def cap_comment(text, limit=INLINE_LIMIT):
    """Cap a finished comment at a length GitHub accepts, without breaking its markup.

    The publish job caps a bundle's body BEFORE checking it, because a cut that removed
    the partial-pass footer would otherwise leave a body that passed the check and was
    posted without its framing.
    """
    return _cut(text or "", limit)


# ------------------------------------------------------------- validation plan

def plan_flags(plan_text):
    """Which dangerous command shapes a validation plan matches, in a stable order."""
    raw = plan_text if isinstance(plan_text, str) else ""
    return [name for name, pattern in PLAN_SHAPES if pattern.search(raw)]


def render_validation_plan(plan_text, limit=PLAN_LIMIT):
    """Render a plan as inert, labelled, quoted text -- never a runnable block.

    A fenced block on GitHub comes with a copy button, which turns model output derived
    from the pull request into a one-click command on a reviewer's workstation. The
    blockquote keeps it readable while making that impossible, and the flag line above
    it names the shapes that were matched.
    """
    raw = plan_text if isinstance(plan_text, str) else ""
    if not raw.strip():
        return ""
    flags = plan_flags(raw)
    body = sanitize_for_github(raw, limit=limit, allow_newlines=True)
    lines = [PLAN_LABEL]
    if flags:
        lines.append("")
        lines.append("> [!WARNING]")
        lines.append("> " + PLAN_WARNING % ", ".join("`%s`" % name for name in flags))
    lines.append("")
    lines.extend("> " + part if part else ">" for part in body.split("\n"))
    return "\n".join(lines)


# ------------------------------------------------------------------- diff index

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffIndex:
    """The lines the pull request actually changed, per side.

    An inline comment can only anchor to a line GitHub itself shows in the diff. This
    index is what decides that, so an anchor is never taken from a record's claim about
    where a line is.

    Two shapes arrive here. `GET /pulls/{n}/files` serves a unified `patch`, which is
    walked line by line: a hunk header alone would accept a line the patch does not
    show, and an anchor GitHub rejects 422s the whole review. `gitsrc` supplies hunk
    dicts with no line detail, so those degrade to the header's range -- good enough for
    the analyze-side hint, which the publish job re-checks against the live patch.
    """

    def __init__(self, files=()):
        self._right = {}          # path -> exact new-side lines, from a patch body
        self._ranges = {}         # path -> [(low, high)], from hunk headers only
        self._removals = {}       # path -> [(old_line, new-side boundary)]
        self._paths = set()
        for entry in files or ():
            self._add(entry)

    def _add(self, entry):
        if not isinstance(entry, dict):
            return
        path = entry.get("path") or entry.get("filename") or ""
        if not isinstance(path, str) or not path:
            return
        self._paths.add(path)
        old_path = entry.get("old_path") or entry.get("previous_filename")
        if isinstance(old_path, str) and old_path:
            self._paths.add(old_path)
        hunks = entry.get("hunks")
        if hunks:
            self._add_hunks(path, hunks)
        elif entry.get("patch"):
            self._add_patch(path, entry["patch"])

    def _add_hunks(self, path, hunks):
        for hunk in hunks or ():
            if not isinstance(hunk, dict):
                continue
            new_start = int(hunk.get("new_start") or 0)
            new_lines = int(hunk.get("new_lines") or 0)
            old_start = int(hunk.get("old_start") or 0)
            old_lines = int(hunk.get("old_lines") or 0)
            if new_lines > 0 and new_start > 0:
                self._ranges.setdefault(path, []).append(
                    (new_start, new_start + new_lines - 1))
            if old_lines > 0 and old_start > 0:
                self._removals.setdefault(path, []).append((old_start, new_start))

    def _add_patch(self, path, patch):
        old_line = new_line = 0
        for line in str(patch or "").split("\n"):
            match = _HUNK_RE.match(line)
            if match:
                old_line, new_line = int(match.group(1)), int(match.group(3))
                continue
            if not line:
                continue
            marker = line[0]
            if marker == "+":
                self._right.setdefault(path, set()).add(new_line)
                new_line += 1
            elif marker == "-":
                self._removals.setdefault(path, []).append((old_line, new_line))
                old_line += 1
            elif marker == " ":
                self._right.setdefault(path, set()).add(new_line)
                old_line += 1
                new_line += 1
            # "\\ No newline at end of file" and any other prefix move no counter.

    def has_path(self, path):
        return path in self._paths

    def paths(self):
        return sorted(self._paths)

    def right(self, path, line):
        if not _is_line(line):
            return False
        if line in self._right.get(path, ()):
            return True
        return any(low <= line <= high for low, high in self._ranges.get(path, ()))

    def removal_near(self, path, line, within=3):
        """The old-side line of the nearest removal bordering `line` on the new side.

        A removed control has no head line to point at, so the comment goes on the old
        side next to where it used to be (the deleted-control case, design 6.3).
        """
        if not _is_line(line):
            return None
        best, best_distance = None, within + 1
        for old_line, boundary in self._removals.get(path, ()):
            distance = abs(boundary - line)
            if distance <= within and distance < best_distance:
                best, best_distance = old_line, distance
        return best

    def touched(self, path):
        return any(bool(table.get(path))
                   for table in (self._right, self._ranges, self._removals))


def _is_line(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


# --------------------------------------------------------------- classification

def introduced_by_pr(record, diff):
    """`pr`, `pre_existing` or `unknown`, computed from the diff and never claimed.

    A trace or evidence line that the diff shows on the right side was introduced or
    modified here; one that only borders a removal is the deleted-control case and
    counts as introduced too, because the pull request is what removed the control.
    """
    if diff is None:
        return "unknown"
    cited = _cited(record)
    if not cited:
        return "unknown"
    for path, line in cited:
        if diff.right(path, line):
            return "pr"
    for path, line in cited:
        if diff.removal_near(path, line) is not None:
            return "pr"
    return "pre_existing"


def _cited(record):
    out = []
    for field in ("trace", "evidence"):
        for entry in record.get(field) or ():
            if not isinstance(entry, dict):
                continue
            path, line = entry.get("file"), entry.get("line")
            if isinstance(path, str) and path and _is_line(line):
                out.append((path, line))
    return out


def lead_priority(kinds, unit_rank=(2, 2), touches_changed=False):
    """P1/P2/P3 from HUNTING.md:7, as an ordering and never as a severity.

    `unit_rank` is the first two components of `ledger.rank` for the owning coverage
    unit: 0 trust means a lowest-trust or unauthenticated entry surface, and a value of
    0 or 1 means the boundary protects credentials, code execution, release authority
    or cross-tenant data.
    """
    kinds = list(kinds or ())
    trust = unit_rank[0] if len(unit_rank) > 0 else 2
    value = unit_rank[1] if len(unit_rank) > 1 else 2
    lowest_trust = trust == 0
    valuable = value <= 1
    execution_only = kinds == ["execution"]
    reasons = []
    if lowest_trust:
        reasons.append("lowest-trust entry surface")
    if valuable:
        reasons.append("high-value resource behind the boundary")
    if execution_only:
        reasons.append("source trace complete; only a runtime observation is missing")
    if touches_changed:
        reasons.append("the trace touches lines this pull request changed")
    # A lead the reviewer could not see enough of is never ordered above one it could.
    if kinds == ["context"] or not kinds:
        return "P3", "the reviewer could not see enough to order this any higher"
    if lowest_trust and valuable and execution_only and touches_changed:
        return "P1", "; ".join(reasons)
    if reasons or ("deployment" in kinds and valuable):
        if "deployment" in kinds and valuable and not reasons:
            reasons.append("a deployment fact is missing on a high-value boundary")
        return "P2", "; ".join(reasons)
    return "P3", "no lowest-trust entry, high-value resource or changed-line overlap"


def record_hash(record):
    """Stable identity of the record's content, for "same lead, changed text" dedupe."""
    blob = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------- disclosure

class Disclosure:
    """What may be published, and under what identity.

    On a public repository `auto` posts only the leads the pull request itself
    introduced; a pre-existing lead is unfixed code that is already public but not yet
    advertised, so it is withheld.

    Two cases, and they pull in opposite directions:

    * A WITHHELD lead posts no comment at all, so nothing about it is ever deduped and
      nothing has to name it -- only aggregates do (a count, a "never validated" list).
      There an opaque handle is right: `sa1:<class>:<path>@<symbol>` is the attack class,
      the file and the function, and printing it would advertise exactly what withholding
      the lead was for.
    * A POSTED lead is the opposite. Its comment already prints its own file and its own
      line, so its fingerprint reveals nothing the body did not. It is therefore
      referenced by its real fingerprint everywhere, including the dedupe marker.

    Do not "fix" the marker back to a handle. The default handle is a position in one
    run, so it changes as soon as the set of leads changes -- a marker built from it
    would stop matching on the next push and repost every comment. Cross-push dedupe
    needs a stable key, and for a lead that is being posted anyway the stable key costs
    nothing.
    """

    MODES = ("auto", "all", "summary-only")

    def __init__(self, mode="auto", public=True, key=b""):
        if mode not in self.MODES:
            raise RenderError("unknown disclosure mode %r" % (mode,))
        self.mode = mode
        self.public = bool(public)
        # An HMAC is only opaque while its key is secret. Keying it with something the
        # comment already prints -- the head sha -- would turn the handle into a
        # commitment anyone can confirm against a guessed `class:path@symbol`. So the
        # default handle is a per-run index, which leaks nothing beyond a count that the
        # summary states outright. It is never a dedupe key, so its instability across
        # runs costs nothing; the HMAC path is for a deployment that has a per-repo
        # secret and wants the withheld counts to line up between pushes.
        self._key = key if isinstance(key, bytes) else str(key or "").encode("utf-8")
        self._index = {}

    @property
    def opaque(self):
        """True when a fingerprint with no comment of its own must not be printed."""
        return self.public and self.mode == "auto"

    @property
    def inline_allowed(self):
        return self.mode != "summary-only"

    @property
    def sarif_allowed(self):
        return self.mode != "summary-only"

    def allows(self, lead):
        if self.mode == "all" or not self.public:
            return True
        return lead.introduced == "pr"

    def assign(self, fingerprints):
        """Reserve a handle for every fingerprint in the run, published or withheld.

        Sorted, so the handle is a stable position in the run and never the order in
        which leads happened to be found.
        """
        for value in sorted({token(value) for value in fingerprints if value}):
            self._index.setdefault(value, "L%d" % (len(self._index) + 1))

    def handle(self, fingerprint):
        value = token(fingerprint)
        if self._key:
            digest = hmac.new(self._key, value.encode("utf-8"), hashlib.sha256)
            return "sa-" + digest.hexdigest()[:16]
        self.assign([value])
        return self._index[value]

    def posted_reference(self, fingerprint):
        """How a lead that IS being posted is named: always its real fingerprint."""
        return token(fingerprint, FINGERPRINT_LIMIT)

    def withheld_reference(self, fingerprint):
        """How a fingerprint with no comment of its own is named in an aggregate."""
        if self.opaque:
            return self.handle(fingerprint)
        return token(fingerprint, FINGERPRINT_LIMIT)


# ------------------------------------------------------------------------- leads

class Lead:
    """One `needs_validation` record as the pull-request surface presents it."""

    def __init__(self, record, unit=None, diff=None):
        self.record = record
        self.fingerprint = record.get("fingerprint") or ""
        self.title = record.get("title") or ""
        self.description = record.get("description") or ""
        self.claimed_root_cause = record.get("claimed_root_cause") or ""
        self.trace = [e for e in record.get("trace") or () if isinstance(e, dict)]
        self.evidence = [e for e in record.get("evidence") or () if isinstance(e, dict)]
        self.blockers = [b for b in record.get("blockers") or () if isinstance(b, str)]
        self.kinds = blocker_kinds(record)
        plan = record.get("validation_plan")
        plan = plan if isinstance(plan, dict) else {}
        self.plan_local = plan.get("local") or ""
        self.plan_deployment = plan.get("deployment") or ""
        self.plan_flags = plan_flags(self.plan_local)
        self.introduced = introduced_by_pr(record, diff)
        self.unit = unit
        rank = tuple(unit.priority[:2]) if unit is not None and unit.priority else (2, 2)
        self.priority, self.priority_rationale = lead_priority(
            self.kinds, rank, self.introduced == "pr")
        self.record_hash = record_hash(record)
        self.coverage_id = getattr(unit, "coverage_id", "") if unit is not None else ""
        self.class_token = _class_token(self.fingerprint)

    @property
    def sink(self):
        for entry in reversed(self.trace):
            if entry.get("kind") == "sink":
                return entry
        return self.trace[-1] if self.trace else None

    @property
    def entrypoint(self):
        for entry in self.trace:
            if entry.get("kind") == "entrypoint":
                return entry
        return self.trace[0] if self.trace else None

    @property
    def location(self):
        sink = self.sink
        if not sink:
            return "", None
        line = sink.get("line")
        return sink.get("file") or "", line if _is_line(line) else None

    @property
    def sort_key(self):
        introduced_rank = {"pr": 0, "unknown": 1, "pre_existing": 2}.get(
            self.introduced, 1)
        priority_rank = PRIORITIES.index(self.priority) if self.priority in PRIORITIES else 3
        return (priority_rank, introduced_rank, self.fingerprint)


def _class_token(value):
    try:
        return fpmod.parse(value)["token"]
    except (fpmod.FingerprintError, AttributeError, TypeError):
        return "unclassified"


def build_leads(records, units=(), diff=None):
    """Pair each `needs_validation` record with its coverage unit and order them."""
    by_fingerprint = {}
    for unit in units or ():
        for value in getattr(unit, "result_fingerprints", ()) or ():
            by_fingerprint.setdefault(value, unit)
    leads = [Lead(record, by_fingerprint.get(record.get("fingerprint")), diff)
             for record in records or ()
             if isinstance(record, dict) and record.get("verdict") == "needs_validation"]
    leads.sort(key=lambda lead: lead.sort_key)
    return leads


# ------------------------------------------------------------------- run report

class RunReport:
    """Everything the publish job needs, assembled once and rendered many ways."""

    def __init__(self, repository="", pr_number=0, head_sha="", merge_base_sha="",
                 findings=(), units=(), diff=None, disclosure=None, omissions=(),
                 not_reviewed=(), deviations=(), coverage=None, usage=None,
                 run_status="complete", incomplete_reason="", quarantined=(),
                 unvalidated=(), suppressed=(), hardening=(), baseline="",
                 profile="quick", show_rejected=False, run_id=""):
        self.repository = repository
        self.pr_number = pr_number
        self.head_sha = head_sha
        self.merge_base_sha = merge_base_sha
        self.diff = diff
        self.disclosure = disclosure or Disclosure()
        self.units = tuple(units or ())
        self.findings = tuple(record for record in findings or ()
                              if isinstance(record, dict))
        self.leads = build_leads(self.findings, self.units, diff)
        self.rejected = tuple(record for record in self.findings
                              if record.get("verdict") == "rejected")
        self.omissions = tuple(_as_omission(item) for item in omissions or ())
        self.not_reviewed = tuple(item for item in not_reviewed or ()
                                  if isinstance(item, dict))
        self.deviations = tuple(deviations or ())
        self.coverage = dict(coverage or {})
        self.usage = dict(usage or {})
        self.run_status = run_status
        self.incomplete_reason = incomplete_reason
        self.quarantined = tuple(quarantined or ())
        self.unvalidated = tuple(unvalidated or ())
        self.suppressed = tuple(suppressed or ())
        self.hardening = tuple(hardening or ())
        self.baseline = baseline
        self.profile = profile
        self.show_rejected = bool(show_rejected)
        self.run_id = run_id or ("pr%s-%s" % (pr_number, (head_sha or "")[:12]))
        # Reserve handles over every fingerprint the run knows, so a published handle
        # is a position in the whole run and not a position in the published subset.
        self.disclosure.assign([lead.fingerprint for lead in self.leads]
                               + [record.get("fingerprint") for record in self.rejected]
                               + list(self.unvalidated))

    @property
    def published(self):
        return [lead for lead in self.leads if self.disclosure.allows(lead)]

    @property
    def withheld(self):
        return [lead for lead in self.leads if not self.disclosure.allows(lead)]

    def reference(self, lead):
        """A published lead's identity, on every surface and in its dedupe marker."""
        return self.disclosure.posted_reference(lead.fingerprint)

    def withheld_reference(self, fingerprint):
        """A fingerprint that gets no comment: withheld, never validated, quarantined."""
        return self.disclosure.withheld_reference(fingerprint)


class _Omission:
    """A normalised omission row; `tools.Omission` and plain dicts both arrive here."""

    def __init__(self, kind, path="", ref="", reason="", detail=""):
        self.kind = kind
        self.path = path
        self.ref = ref
        self.reason = reason
        self.detail = detail


def _as_omission(item):
    if isinstance(item, dict):
        return _Omission(item.get("kind", ""), item.get("path", ""), item.get("ref", ""),
                         item.get("reason", ""), item.get("detail", ""))
    return _Omission(getattr(item, "kind", ""), getattr(item, "path", ""),
                     getattr(item, "ref", ""), getattr(item, "reason", ""),
                     getattr(item, "detail", ""))


# ------------------------------------------------------------------ summary comment

def summary_markdown(report):
    """The one issue comment per run.

    Order is deliberate: the leads a reviewer can act on, then everything the run did
    not or could not do. The partial-coverage statement and the "Not reviewed" list are
    unconditional -- a gap that is not printed is a gap that closes silently, which
    HUNTING.md:247 forbids being read as coverage.
    """
    out = [MARKER % token(report.run_id, 64)]
    out.append(_heading(report))
    out.append("")
    out.append(PARTIAL_NOTICE)
    out.append("")
    if report.run_status != "complete":
        out.append("> [!WARNING]")
        out.append("> %s (%s). Coverage below is what was reached, not what was needed."
                   % (INCOMPLETE_HEADING,
                      sanitize_for_github(report.incomplete_reason
                                          or "reason not recorded", limit=200)))
        out.append("")
    out.append(_coverage_line(report))
    out.append("")
    out.extend(_leads_section(report))
    out.extend(_unrepresentable_section(report))
    out.extend(_not_reviewed_section(report))
    out.extend(_withheld_section(report))
    out.extend(_unvalidated_section(report))
    out.extend(_rejected_section(report))
    out.extend(_deviations_section(report))
    out.extend(_method_section(report))
    return _cut("\n".join(out).rstrip() + "\n", SUMMARY_LIMIT, _OVERFLOW)


_OVERFLOW = ("\n\n_This comment reached GitHub's length limit; the remaining sections "
             "are in the run artifact._")


def _heading(report):
    return "%s vs merge-base %s" % (_heading_for(report.head_sha),
                                    code(report.merge_base_sha[:7] or "unknown"))


def _heading_for(head_sha):
    """The one heading every summary surface uses, including the publish-side notices."""
    return "## AI security review (partial) - head %s" % code((head_sha or "")[:7]
                                                              or "unknown")


def _coverage_line(report):
    by_status = dict(report.coverage.get("by_status") or {})
    total = report.coverage.get("units", sum(by_status.values()))
    parts = []
    for status in ("covered", "candidate", "deferred", "out_of_scope", "blocked",
                   "planned", "in_progress", "not_applicable"):
        if by_status.get(status):
            parts.append("%d %s" % (by_status[status], status.replace("_", " ")))
    detail = (" (%s)" % ", ".join(parts)) if parts else ""
    return "**Coverage:** %d coverage unit%s%s - %d lead%s to check." % (
        total, "" if total == 1 else "s", detail,
        len(report.published), "" if len(report.published) == 1 else "s")


def _leads_section(report):
    leads = report.published
    out = ["### Leads that need validation (%d)" % len(leads), ""]
    if not leads:
        if report.withheld:
            # Saying "no lead" when leads exist but are withheld would be a lie the
            # disclosure policy does not need: the count below is enough.
            out.append("Nothing to show here under this disclosure mode; see the "
                       "withheld count below.")
        else:
            out.append("No lead survived verification in the part of this pull request "
                       "that was reviewed. That is not a statement that the rest is "
                       "clean; see *Not reviewed* below.")
        out.append("")
        return out
    for index, lead in enumerate(leads[:MAX_LEADS_IN_SUMMARY], start=1):
        out.extend(_lead_block(report, index, lead))
    if len(leads) > MAX_LEADS_IN_SUMMARY:
        out.append("_%d further lead(s) are in the run artifact._"
                   % (len(leads) - MAX_LEADS_IN_SUMMARY))
        out.append("")
    out.append(ORDER_FOOTNOTE)
    out.append("")
    return out


_INTRODUCED_TEXT = {
    "pr": "introduced or modified by this pull request",
    "pre_existing": "pre-existing: every cited line is unchanged since the merge base",
    "unknown": "could not be mapped to the diff",
}


def _lead_block(report, index, lead):
    path, line = lead.location
    where = sanitize_path(path) if path else "_no source location_"
    if path and line:
        where = link("%s line %d" % (sanitize_path(path), line),
                     blob_url(report.repository, report.head_sha, path, line))
    elif path:
        where = link(sanitize_path(path),
                     blob_url(report.repository, report.head_sha, path))
    out = ["#### %d. %s" % (index, sanitize_for_github(lead.title, limit=TITLE_LIMIT)),
           "",
           "- **Order\\*:** %s - %s" % (lead.priority,
                                        sanitize_for_github(lead.priority_rationale, 200)),
           "- **Where:** %s (%s)" % (where, _INTRODUCED_TEXT.get(lead.introduced,
                                                                lead.introduced)),
           "- **Boundary:** %s" % _boundary_story(lead),
           "- **Claimed root cause:** %s"
           % sanitize_for_github(lead.claimed_root_cause, limit=400)]
    if lead.blockers:
        out.append("- **Unresolved:**")
        for blocker in lead.blockers[:6]:
            out.append("  - %s" % sanitize_for_github(blocker, limit=300))
    out.append("- **Reference:** %s" % reference_markup(report.reference(lead)))
    out.append("")
    plan = render_validation_plan(lead.plan_local)
    if plan:
        out.append(plan)
        out.append("")
    if lead.plan_deployment:
        out.append("Owner check (model-written, unverified): %s"
                   % sanitize_for_github(lead.plan_deployment, limit=400))
        out.append("")
    return out


def _boundary_story(lead):
    """Who crosses what, told from the trace the record already had to supply."""
    entry, sink = lead.entrypoint, lead.sink
    if not entry or not sink:
        return sanitize_for_github(lead.description, limit=300)
    left = sanitize_for_github(entry.get("scope") or entry.get("file") or "entry", 120)
    right = sanitize_for_github(sink.get("scope") or sink.get("file") or "sink", 120)
    detail = sanitize_for_github(sink.get("description") or "", limit=240)
    story = "%s -> %s" % (left, right)
    return "%s - %s" % (story, detail) if detail else story


def _unrepresentable_section(report):
    """A named section, because a path the validator cannot represent is a suppression
    primitive: without this the file would vanish from a report that has no other
    category for it."""
    rows = [item for item in report.not_reviewed
            if item.get("status") == "unrepresentable" or item.get("kind") == "path"]
    if not rows:
        return []
    out = ["### Cannot be reported (unrepresentable path) (%d)" % len(rows), ""]
    out.append("The security-audit validator rejects these paths, so no lead about them "
               "can be recorded at all. Treat them as **not reviewed**, not as clean.")
    out.append("")
    for item in rows[:MAX_NOT_REVIEWED]:
        out.append("- %s - %s" % (sanitize_path(item.get("path", "")),
                                  sanitize_for_github(item.get("reason", ""), 200)))
    out.append("")
    return out


def _not_reviewed_section(report):
    rows = _not_reviewed_rows(report)
    out = ["<details><summary><strong>Not reviewed (%d)</strong></summary>" % len(rows),
           ""]
    if not rows:
        out.append("Every changed file in scope was opened, and no read, search or diff "
                   "was truncated. This still covers only `merge-base...head`.")
    else:
        out.append("Files and surfaces this run did not see, or did not see all of:")
        out.append("")
        for text in rows[:MAX_NOT_REVIEWED]:
            out.append("- %s" % text)
        if len(rows) > MAX_NOT_REVIEWED:
            out.append("- _...and %d more, listed in the run artifact._"
                       % (len(rows) - MAX_NOT_REVIEWED))
    out.append("")
    out.append("</details>")
    out.append("")
    return out


def _not_reviewed_rows(report):
    rows, seen = [], set()
    for omission in report.omissions:
        if omission.kind in ("long_lines_cut",):
            continue          # a cosmetic cut, not a surface the run failed to reach
        key = (omission.kind, omission.path)
        if key in seen:
            continue
        seen.add(key)
        reason = OMISSION_REASONS.get(omission.kind) or omission.reason or omission.kind
        where = sanitize_path(omission.path) if omission.path else "_run-wide_"
        detail = sanitize_for_github(omission.detail, limit=160)
        text = "%s - %s" % (where, sanitize_for_github(reason, limit=160))
        rows.append("%s (%s)" % (text, detail) if detail else text)
    for item in report.not_reviewed:
        if item.get("kind") == "path" or item.get("status") == "unrepresentable":
            continue          # rendered in its own named section above
        key = ("unit", item.get("coverage_id", ""))
        if key in seen:
            continue
        seen.add(key)
        status = item.get("status", "")
        reason = item.get("reason") or UNIT_REASONS.get(status, status)
        paths = ", ".join(sanitize_path(p, 80)
                          for p in (item.get("starting_paths") or ())[:4]) or "_no path_"
        rows.append("%s - coverage unit %s: %s"
                    % (paths, sanitize_for_github(status, 40),
                       sanitize_for_github(reason, limit=200)))
    return rows


def _withheld_section(report):
    withheld = report.withheld
    if not withheld:
        return []
    return ["> [!NOTE]",
            "> %d pre-existing or unmapped lead(s) were found and are **withheld from "
            "this public surface** under `disclosure: auto`, along with their "
            "fingerprints. Run the private baseline audit to see them." % len(withheld),
            ""]


def _unvalidated_section(report):
    if not report.unvalidated and not report.quarantined:
        return []
    out = ["<details><summary><strong>Claims with no final disposition (%d)</strong>"
           "</summary>" % (len(report.unvalidated) + len(report.quarantined)), ""]
    out.append("These are **not findings**. They were never validated, or their record "
               "was discarded, so the run is incomplete.")
    out.append("")
    # These never get a comment of their own, so on a public surface they are named by
    # handle: there is no file and line printed next to them to make the raw one moot.
    for value in report.unvalidated[:MAX_LIST_ITEMS]:
        out.append("- %s - never validated"
                   % reference_markup(report.withheld_reference(value)))
    for entry in report.quarantined[:MAX_LIST_ITEMS]:
        value = getattr(entry, "fingerprint", entry if isinstance(entry, str) else "")
        messages = getattr(entry, "messages", ())
        out.append("- %s - discarded: %s"
                   % (reference_markup(report.withheld_reference(value)),
                      sanitize_for_github("; ".join(messages) if messages
                                          else "record failed validation", limit=300)))
    out.append("")
    out.append("</details>")
    out.append("")
    return out


def _rejected_section(report):
    if not report.rejected:
        return []
    out = ["<details><summary><strong>Claims that did not survive verification (%d)"
           "</strong></summary>" % len(report.rejected), ""]
    out.append("A verifier read the source and disproved each of these. They are listed "
               "so a disagreement with an earlier run is visible; they are not findings.")
    out.append("")
    for record in report.rejected[:MAX_LIST_ITEMS]:
        line = "- %s" % sanitize_for_github(record.get("title") or "untitled claim",
                                            limit=TITLE_LIMIT)
        if report.show_rejected:
            line += " - %s" % sanitize_for_github(record.get("reason") or "", limit=300)
        out.append(line)
    out.append("")
    out.append("</details>")
    out.append("")
    return out


def _deviations_section(report):
    out = ["<details><summary><strong>Deviations from the security-audit skill (%d)"
           "</strong></summary>" % len(report.deviations), ""]
    if not report.deviations:
        out.append("None recorded for this run.")
    else:
        for item in report.deviations[:MAX_LIST_ITEMS]:
            text = item if isinstance(item, str) else (
                "%s - %s" % (item.get("ref", ""), item.get("reason", "")))
            out.append("- %s" % sanitize_for_github(text, limit=400))
    out.append("")
    out.append("</details>")
    out.append("")
    return out


def _method_section(report):
    usage = report.usage
    out = ["<details><summary><strong>Coverage and method</strong></summary>", ""]
    out.append("- Profile: %s, scoped to `merge-base...head`; execution policy "
               "`source-only-no-execution` (no pull-request code ran)."
               % sanitize_for_github(report.profile, 40))
    conversations = usage.get("conversations")
    if conversations is not None:
        out.append("- Conversations: %s of %s"
                   % (conversations, usage.get("max_conversations", "?")))
    if usage.get("usd") is not None:
        out.append("- Model spend: $%.2f of $%.2f ceiling"
                   % (float(usage.get("usd") or 0.0), float(usage.get("max_usd") or 0.0)))
    if usage.get("latency_s") is not None:
        out.append("- Wall time: %s" % _duration(usage.get("latency_s")))
    models = usage.get("models") or {}
    if models:
        out.append("- Models: %s" % ", ".join(
            "%s=%s" % (sanitize_for_github(role, 30), sanitize_for_github(name, 60))
            for role, name in sorted(models.items())))
    if report.baseline:
        out.append("- Baseline audit: %s" % sanitize_for_github(report.baseline, 200))
    if report.suppressed:
        out.append("- Suppressed by an unchanged prior rejection: %d claim(s)"
                   % len(report.suppressed))
    if report.hardening:
        out.append("- Hardening notes (not findings): %d" % len(report.hardening))
    out.append("- A green or neutral check is not a clean bill: prompt injection in the "
               "reviewed content can suppress a finding, and this pass is diff-scoped.")
    out.append("")
    out.append("</details>")
    out.append("")
    return out


def _duration(seconds):
    total = int(float(seconds or 0))
    return "%dm %02ds" % (total // 60, total % 60)


# ------------------------------------------------------------------ inline comments

def inline_comments(report, allow_deleted_control=False, diff=None):
    """Candidate anchors for a pull-request review, as data the publish job posts.

    `diff` overrides the report's own index. That is how the publish job re-anchors:
    it builds a `DiffIndex` from `GET /pulls/{n}/files` at the analysed head and hands
    it back here, so the data is GitHub's and the choice is still this module's.
    """
    if not report.disclosure.inline_allowed:
        return []
    index = report.diff if diff is None else diff
    return [_anchor(report, lead, index, allow_deleted_control)
            for lead in report.published]


def _anchor(report, lead, diff, allow_deleted_control):
    candidates = anchor_candidates(lead)
    entry = {"fingerprint": report.reference(lead), "record_hash": lead.record_hash,
             "priority": lead.priority, "body": lead_body(report, lead),
             # The publish job re-anchors against a live diff, so it needs the whole
             # ordered candidate list, not only the one this index happened to pick.
             "candidates": [[path, line] for path, line in candidates]}
    entry.update(select_anchor(candidates, diff, allow_deleted_control))
    return entry


def select_anchor(candidates, diff, allow_deleted_control=False):
    """Where one lead hangs: a RIGHT line, a LEFT line, the file, or the summary.

    An anchor is only emitted for a line the diff index actually contains, because that
    is the only line GitHub will accept; a record's claim about where its sink lives is
    not evidence that the line is in the diff. When no cited line is in the diff the
    lead falls back to a file-level comment, and then to the summary -- never to an
    anchor that would 422 the whole review.

    `allow_deleted_control` enables the design's LEFT-side fallback for a removed
    control (6.3). It is off by default because a caller that cannot post on the old
    side would produce an anchor it has to throw away; the publish job opts in.

    This is the only implementation of the choice. The analyze job calls it with the
    git-side index and the publish job with one built from the live files API.
    """
    pairs = [(path, line) for path, line in candidates or ()
             if isinstance(path, str) and path and _is_line(line)]
    if diff is not None:
        for path, line in pairs:
            if diff.right(path, line):
                return {"anchor": "line", "path": path, "line": line, "side": "RIGHT"}
        if allow_deleted_control:
            for path, line in pairs:
                old_line = diff.removal_near(path, line)
                if old_line is not None:
                    return {"anchor": "line", "path": path, "line": old_line,
                            "side": "LEFT"}
        for path, _line in pairs:
            if diff.has_path(path):
                return {"anchor": "file", "path": path, "line": None, "side": None}
    return {"anchor": "summary", "path": "", "line": None, "side": None}


def anchor_candidates(source, seeded=()):
    """Sink first -- that is where the harm lands -- then evidence, then back up the
    trace, then anything the caller seeded. Order is the design's; validity is the diff
    index's call.

    `source` is a `Lead` or a raw findings.json record, so the publish job can rebuild
    the same order from the bundle without assembling a report it has no units for.
    """
    if isinstance(source, Lead):
        sink, evidence, trace = source.sink, source.evidence, source.trace
    else:
        record = source if isinstance(source, dict) else {}
        trace = [e for e in record.get("trace") or () if isinstance(e, dict)]
        evidence = [e for e in record.get("evidence") or () if isinstance(e, dict)]
        sink = trace[-1] if trace else None
    ordered = ([sink] if sink else []) + list(evidence) + list(reversed(trace[:-1]))
    out, seen = [], set()
    for entry in ordered:
        if not isinstance(entry, dict):
            continue
        _remember((entry.get("file"), entry.get("line")), out, seen)
    for pair in seeded or ():
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            _remember((pair[0], pair[1]), out, seen)
    return out


def _remember(pair, out, seen):
    path, line = pair
    if not isinstance(path, str) or not path or not _is_line(line):
        return
    if (path, line) in seen:
        return
    seen.add((path, line))
    out.append((path, line))


def lead_body(report, lead):
    """The inline comment body: parent-built structure, inert record text inside it."""
    return _lead_body(report.repository, report.head_sha, report.reference(lead), lead)


def rebuild_lead_body(record, reference="", repository="", head_sha=""):
    """The same body from a raw record, for a bundle body that could not be posted.

    It lives here, not in the publish job, so that lead text has exactly one author and
    is escaped exactly once. The publish job has neither coverage units nor a diff, so
    the rebuilt body carries no priority ordering it cannot justify.
    """
    lead = Lead(record if isinstance(record, dict) else {})
    return _lead_body(repository, head_sha,
                      reference or lead.fingerprint, lead)


def _lead_body(repository, head_sha, reference, lead):
    # The marker carries the real fingerprint: this comment is being posted, so its own
    # body already prints the file and line the fingerprint is built from, and cross-push
    # dedupe needs a key that does not move when the set of leads does.
    out = [INLINE_MARKER % (token(reference, FINGERPRINT_LIMIT),
                            token(lead.record_hash, 32)),
           "**%s**" % sanitize_for_github(lead.title, limit=TITLE_LIMIT),
           "",
           "Order\\*: %s. No code was executed, so this is a lead, not a confirmed "
           "vulnerability, and it has no severity." % lead.priority,
           "",
           "%s" % sanitize_for_github(lead.claimed_root_cause, limit=400),
           ""]
    if lead.trace:
        out.append("Trace:")
        for entry in lead.trace[:MAX_TRACE_LINES]:
            path, line = entry.get("file") or "", entry.get("line")
            label = sanitize_path(path)
            if _is_line(line) and repository:
                target = link("%s:%d" % (label, line),
                              blob_url(repository, head_sha, path, line))
            else:
                target = label
            out.append("1. %s - %s (%s)"
                       % (target, sanitize_for_github(entry.get("description") or "", 200),
                          sanitize_for_github(entry.get("kind") or "", 20)))
        out.append("")
    if lead.blockers:
        out.append("Unresolved:")
        for blocker in lead.blockers[:6]:
            out.append("- %s" % sanitize_for_github(blocker, limit=300))
        out.append("")
    plan = render_validation_plan(lead.plan_local)
    if plan:
        out.append(plan)
        out.append("")
    if lead.plan_deployment:
        out.append("Owner check (model-written, unverified): %s"
                   % sanitize_for_github(lead.plan_deployment, limit=400))
        out.append("")
    out.append(ORDER_FOOTNOTE)
    out.append("")
    # An inline comment is read on its own, far from the summary that frames the run, so
    # the partial-pass framing travels with it rather than being appended downstream.
    out.append(INLINE_FOOTER)
    return _cut("\n".join(out), INLINE_LIMIT)


# ------------------------------------------------------- text for the publish job

def framed_summary(text, run_id="", head_sha="", run_status="complete",
                   incomplete_reason="", extra_sections=()):
    """The summary comment as the publish job posts it.

    `summary_markdown` already produced a complete, inert document, so it is posted
    whole when it still carries its marker and its framing. It is not re-escaped: that
    would turn every `&amp;` into `&amp;amp;` and every `\\*` into a literal backslash.
    When the document is missing, truncated or not inert, this frames what is left and
    says plainly that the body was dropped -- silence would read as "nothing found".
    """
    body = (text or "").strip()
    problems = inert_problems(body) if body else []
    usable = bool(body) and not problems and MARKER_PREFIX in body \
        and not framing_problems(body)
    warning = ""
    if run_status != "complete":
        warning = ("> [!WARNING]\n> %s (%s). Coverage below is what was reached, not "
                   "what was needed."
                   % (INCOMPLETE_HEADING,
                      sanitize_for_github(incomplete_reason or "reason not recorded",
                                          limit=200)))
    parts = []
    if usable:
        # The bundle is untrusted. `summary_markdown` says this itself when the analyze
        # job knew the run was incomplete, so the line is added only when the document
        # does not carry it: a gap that is not printed reads as coverage. It goes under
        # the marker rather than at the end, where nobody reads it.
        if warning and INCOMPLETE_HEADING not in body:
            marker_line, _, rest = body.partition("\n")
            parts.append("\n\n".join([marker_line, warning, rest.strip("\n")]))
        else:
            parts.append(body)
    else:
        parts.append(MARKER % token(run_id, 64))
        parts.append(_heading_for(head_sha))
        parts.append(PARTIAL_NOTICE)
        if warning:
            parts.append(warning)
        if body and not problems:
            parts.append(body)
        elif body:
            parts.append("_The bundle's summary did not pass the publish-side inertness "
                         "check (%s) and was not posted._"
                         % sanitize_for_github(", ".join(problems), limit=200))
        parts.append(ORDER_FOOTNOTE)
    parts.extend(section for section in extra_sections if section)
    return _cut("\n\n".join(parts), SUMMARY_LIMIT, _OVERFLOW)


def gate_notice(head_sha, reasons):
    """What is posted when the bundle cannot be trusted. Carries no lead text.

    The reasons are validator and gate strings: parent-shaped, but built around paths
    and fingerprints a model chose, so they are escaped like any other record text.
    """
    lines = [MARKER % "gate",
             "## AI security review - nothing published",
             "",
             "The analyze job's bundle did not pass the publish-side gate, so no lead "
             "text from it has been posted. This is not a clean result: it means the "
             "review's own output could not be verified.",
             "",
             "Analysed head: %s" % code((head_sha or "")[:7] or "unknown"),
             ""]
    for reason in list(reasons or ())[:20]:
        lines.append("- %s" % sanitize_for_github(reason, limit=300))
    lines.append("")
    lines.append("<sub>This partial pass reports no severity, and this check does not "
                 "block a merge by default.</sub>")
    return _cut("\n".join(lines), SUMMARY_LIMIT, _OVERFLOW)


def superseded_notice(analysed_head, live_head):
    """Parent-authored, so it interpolates nothing a bundle or a model wrote."""
    return "\n".join([
        MARKER % "superseded",
        "## AI security review - superseded",
        "",
        "This partial pass analysed %s, but the pull request head is now %s. Lead text "
        "from the older head would point at line numbers that have moved, so nothing "
        "has been posted and nothing here carries a severity."
        % (code(analysed_head or "unknown", 12), code(live_head or "unknown", 12)),
        "",
        "A review of the current head runs on the next push event.",
    ])


def collapsed(title, body):
    return "<details><summary>%s</summary>\n\n%s\n</details>" % (title, body)


def unanchored_section(references):
    """Leads no live line would carry, named so they are not silently absent."""
    if not references:
        return ""
    return collapsed("Leads that could not be anchored (%d)" % len(references),
                     "These are in the list above; GitHub would not take a comment on "
                     "the lines they cite.\n\n"
                     + "\n".join("- %s" % reference_markup(value)
                                 for value in references))


def suppression_section(references):
    """Leads an earlier push reported that this one did not, over unchanged source."""
    if not references:
        return ""
    return collapsed("Not re-reported, source unchanged (%d)" % len(references),
                     "These were reported on an earlier push and were not reported "
                     "again, while the code they cited did not change. That is not "
                     "evidence of a fix, so their threads stay open.\n\n"
                     + "\n".join("- %s" % reference_markup(value)
                                 for value in references))


def check_title(run_status, incomplete_reason, lead_count):
    """The check run's title. Plain text, so it is stripped and capped, not escaped."""
    if run_status != "complete":
        return "incomplete: %s" % (_plain(incomplete_reason, 180)
                                   or "reason not recorded")
    if lead_count == 1:
        return "1 lead needs validation"
    return "%d leads need validation" % lead_count


def check_summary(head_sha, lead_count, posted, unchanged):
    """The check run's output. A check is a surface too, so it carries the framing."""
    return ("Partial, diff-scoped, quick-profile pass at %s. No pull-request code was "
            "executed, so nothing is confirmed and nothing has a severity.\n\n"
            "%d lead(s) reported, %d inline comment(s) posted, %d unchanged since the "
            "last push.\n\nThis check is advisory: content in the pull request can "
            "suppress findings, so a green result is not a clean bill. Do not make it a "
            "required check."
            % (code((head_sha or "")[:7] or "unknown"), lead_count, posted, unchanged))


# --------------------------------------------------------------------------- SARIF

def sarif(report, enabled=False, tool_version="1"):
    """SARIF 2.1.0 for code scanning. Off by default; returns None when not enabled.

    There is no severity in this run, so no result carries `security-severity` and the
    level is derived from the P1/P2/P3 ordering, which the rule description says
    plainly. `partialFingerprints` is set here because GitHub computes
    `primaryLocationLineHash` from a checkout, and this action never checks out the
    pull request; alerts may therefore duplicate across pushes rather than merge.
    """
    if not enabled or not report.disclosure.sarif_allowed:
        return None
    leads = report.published
    rules, rule_index = [], {}
    results = []
    for lead in leads:
        rule_id = "security-audit/%s" % token(lead.class_token or "unclassified", 80)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": _rule_name(lead.class_token),
                "shortDescription": {"text": "Security-audit lead: %s"
                                             % _plain(lead.class_token)},
                "fullDescription": {"text": SARIF_RULE_DESCRIPTION},
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["security", "needs-validation", "no-severity"],
                               "precision": "medium"},
            })
        results.append(_sarif_result(report, lead, rule_id, rule_index[rule_id]))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ai-security-review",
                "informationUri": "https://github.com/%s" % token(report.repository, 140),
                "version": str(tool_version),
                "rules": rules,
            }},
            "automationDetails": {"id": "ai-security-review/%s"
                                        % token(report.run_id, 64)},
            "properties": {
                "partialCoverage": True,
                "executionPolicy": "source-only-no-execution",
                "note": PARTIAL_NOTICE,
            },
            "results": results,
        }],
    }


def _sarif_result(report, lead, rule_id, index):
    path, line = lead.location
    line = line or 1
    reference = report.reference(lead)
    message = "%s -- %s Order %s (an ordering from the skill's hunting order, not a " \
              "severity). Unresolved: %s" % (
                  _plain(lead.title, TITLE_LIMIT), _plain(lead.claimed_root_cause, 400),
                  lead.priority, _plain("; ".join(lead.blockers), 300) or "not recorded")
    result = {
        "ruleId": rule_id,
        "ruleIndex": index,
        "level": SARIF_LEVELS.get(lead.priority, "note"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": _plain(path, PATH_LIMIT) or "unknown",
                                 "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line, "endLine": line,
                       "startColumn": 1, "endColumn": 2},
        }}],
        # Our own key: GitHub cannot compute primaryLocationLineHash with no checkout.
        # A SARIF result exists only for a lead that is being published, so the key is
        # the real fingerprint -- stable across pushes, which is what merges alerts.
        "partialFingerprints": {"securityAuditFingerprint/v1":
                                token(reference, FINGERPRINT_LIMIT)},
        "properties": {"order": lead.priority, "introduced": lead.introduced,
                       "blockerKinds": lead.kinds, "severity": None},
    }
    related = []
    for entry in lead.evidence[:10]:
        entry_path, entry_line = entry.get("file"), entry.get("line")
        if not isinstance(entry_path, str) or not entry_path or not _is_line(entry_line):
            continue
        related.append({"physicalLocation": {
            "artifactLocation": {"uri": _plain(entry_path, PATH_LIMIT)},
            "region": {"startLine": entry_line, "endLine": entry_line,
                       "startColumn": 1, "endColumn": 2}},
            "message": {"text": _plain(entry.get("description") or "", 200)}})
    if related:
        result["relatedLocations"] = related
    return result


def _rule_name(class_token):
    parts = [part for part in re.split(r"[.\-_/]", class_token or "") if part]
    return "SecurityAudit" + "".join(part.capitalize() for part in parts)


def _plain(text, limit=BODY_LIMIT):
    """SARIF message text is JSON, not markdown, so it needs the character strip and the
    cap but not the markdown escaping."""
    out = re.sub(r"\s+", " ", strip_unsafe_characters(str(text or ""))).strip()
    return out[:limit] + "..." if limit and len(out) > limit else out


# ------------------------------------------------------------- annotations sidecar

def annotations_sidecar(report):
    """`pr-annotations.json` (design 5.3).

    It lives outside findings.json, whose schema is `additionalProperties: false` and
    which may not carry a severity or anything shaped like one. Everything here is
    re-derived by code from the record's own tagged blockers and the diff.
    """
    return {
        "version": 1,
        "run_id": report.run_id,
        "head_sha": report.head_sha,
        "merge_base_sha": report.merge_base_sha,
        "execution_policy": "source-only-no-execution",
        "severity": None,
        "note": ("`priority` orders leads by HUNTING.md:7. It is not a severity; "
                 "needs_validation has no severity because no code was executed."),
        "disclosure": {"mode": report.disclosure.mode, "public": report.disclosure.public,
                       "opaque_references": report.disclosure.opaque,
                       "withheld": len(report.withheld)},
        "leads": [{
            # Only published leads appear here, and a published lead is referenced by
            # its real fingerprint on every surface, so the two fields agree. The second
            # is kept because the bundle contract names it and a reader should not have
            # to know that `reference` happens to be the fingerprint.
            "reference": report.reference(lead),
            "fingerprint": lead.fingerprint,
            "coverage_id": lead.coverage_id,
            "priority": lead.priority,
            "priority_rationale": lead.priority_rationale,
            "blocker_kinds": lead.kinds,
            "introduced": lead.introduced,
            "record_hash": lead.record_hash,
            "validation_plan_flags": lead.plan_flags,
            "location": {"path": lead.location[0], "line": lead.location[1]},
        } for lead in report.published],
    }
