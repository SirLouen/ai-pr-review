"""Deterministic detectors that emit DRAFT CANDIDATES, never findings.

ATTACK-CLASSES.md:130 is explicit: "A flag is not a finding -- trace the impact before
reporting." Nothing here decides anything. Each detector produces a draft candidate that
enters the queue like any hunter's candidate and is validated by a fresh verifier, whose
job includes disproving it. The value is recall that survives a successful prompt
injection: a model that has been talked out of reporting cannot talk the parent out of
seeding, and this costs nothing.

Three detectors:

1. Committed secrets, scanned PER COMMIT rather than over `base...head`. A secret added
   in commit 1 and removed in commit 3 is invisible in the PR diff but is still in the
   pushed history and still leaked (ATTACK-CLASSES.md:103).
2. A privileged workflow trigger (`pull_request_target`, `workflow_run`) combined with a
   checkout of the pull request's head.
3. An untrusted `${{ github.event.* }}` expression interpolated straight into a `run:`
   or `script:` block.

Secret values never leave this module: a draft carries the rule, the location, the
length and a truncated SHA-256, and nothing that could reconstruct the credential.
"""
import hashlib
import math
import re
from collections import Counter

from . import fingerprint as fp
from .routing import ATTACK, SUPPLY, block_id, matches_any, sanitize

CRYPTO_SECRETS = block_id(ATTACK, "Cryptography and secrets")
CI_UNTRUSTED_CODE = block_id(SUPPLY, "Untrusted code in a privileged workflow")
CI_EXPRESSION = block_id(SUPPLY, "Workflow command and expression confusion")

NOT_A_FINDING = ("deterministic seeder flag; a flag is not a finding "
                 "(ATTACK-CLASSES.md:130) -- route to a verifier like any candidate")

MIN_ENTROPY = 3.5
MIN_GENERIC_LENGTH = 16
MAX_GENERIC_LENGTH = 200

# Generated files whose base64 integrity hashes and vendored blobs look exactly like
# high-entropy credentials. Only the generic entropy rule is suppressed here: a literal
# `-----BEGIN PRIVATE KEY-----` in a lockfile is still reported.
GENERIC_SKIP_GLOBS = (
    "*.lock", "**/*.lock", "package-lock.json", "**/package-lock.json", "yarn.lock",
    "**/yarn.lock", "pnpm-lock.yaml", "**/pnpm-lock.yaml", "go.sum", "**/go.sum",
    "*.min.js", "**/*.min.js", "*.map", "**/*.map", "**/*.snap", "**/*.svg",
    "**/*.woff*", "**/__snapshots__/**")

# Values that are shaped like a credential but are not one.
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:example|changeme|change_me|placeholder|your[-_ ]?(?:key|token|secret)|"
    r"dummy|fake|sample|redacted|notreal|xxxx|\bteststring\b|todo|foobar|"
    r"\$\{|\{\{|<[^>]*>|process\.env|os\.environ|getenv|System\.getenv|"
    r"^(?:none|null|nil|true|false|undefined)$|^\*+$|^0+$)")
URL_RE = re.compile(r"^(?:https?|ftp)://(?![^/@]*:[^/@]*@)")

SECRET_RULES = (
    {"id": "aws-access-key-id", "generic": False,
     "regex": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")},
    {"id": "private-key-block", "generic": False,
     "regex": re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----")},
    {"id": "github-token", "generic": False,
     "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|"
                         r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")},
    {"id": "slack-token", "generic": False,
     "regex": re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}\b|"
                         r"https://hooks\.slack\.com/services/T[A-Za-z0-9/_+-]{20,}")},
    {"id": "google-api-key", "generic": False,
     "regex": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")},
    {"id": "stripe-live-key", "generic": False,
     "regex": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b")},
    {"id": "anthropic-key", "generic": False,
     "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")},
    {"id": "openai-key", "generic": False,
     "regex": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")},
    {"id": "npm-token", "generic": False,
     "regex": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")},
    {"id": "jwt-literal", "generic": False,
     "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"
                         r"\.[A-Za-z0-9_-]{10,}\b")},
    # The only rule that needs an entropy gate: everything above is self-identifying.
    {"id": "credential-assignment", "generic": True,
     "regex": re.compile(
         r"(?i)(?P<ident>[A-Za-z0-9_.\-]*"
         r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|access[_-]?key|"
         r"private[_-]?key|credential|client[_-]?secret|auth[_-]?key)"
         r"[A-Za-z0-9_.\-]*)\s*(?:[:=]|=>|:=)\s*"
         r"[\"'](?P<value>[^\"'\\\s]{%d,%d})[\"']"
         % (MIN_GENERIC_LENGTH, MAX_GENERIC_LENGTH))},
)


def shannon_entropy(value):
    """Bits per character. Random base64 is about 4.0-5.0; English prose about 3.0-3.5."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_like_placeholder(value):
    if PLACEHOLDER_RE.search(value):
        return True
    if URL_RE.match(value):
        return True
    return len(set(value)) <= 3


def _secret_hits(path, text):
    """Yield (rule_id, line_no, matched_value) for every secret rule hit in one blob."""
    generic_ok = not matches_any(path, GENERIC_SKIP_GLOBS)
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in SECRET_RULES:
            if rule["generic"] and not generic_ok:
                continue
            for match in rule["regex"].finditer(line):
                value = match.groupdict().get("value") or match.group(0)
                if rule["generic"]:
                    if _looks_like_placeholder(value):
                        continue
                    if shannon_entropy(value) < MIN_ENTROPY:
                        continue
                # Inline allowlist markers (`gitleaks:allow`, `pragma: allowlist secret`)
                # are deliberately NOT honoured: the file is written by whoever opened
                # the PR, so obeying them would hand them a suppression primitive.
                yield rule["id"], line_no, value


def _digest(value):
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def merge_by_fingerprint(drafts):
    """Collapse drafts that share a fingerprint into one, preserving input order.

    Two credentials in one function, or one value that trips two rules, are one sink and
    therefore one fingerprint. Emitting both would put two records with the same
    fingerprint in findings.json, which validate-findings.cjs rejects for the whole
    document -- turning a seeder into a denial of the entire report.
    """
    merged = {}
    for draft in drafts:
        current = merged.get(draft["fingerprint"])
        if current is None:
            merged[draft["fingerprint"]] = dict(
                draft, rule_ids=(draft["rule_id"],), lines=(draft["line"],),
                merged_count=1)
            continue
        current["rule_ids"] = tuple(sorted(set(current["rule_ids"])
                                           | {draft["rule_id"]}))
        current["lines"] = tuple(sorted(set(current["lines"]) | {draft["line"]}))
        current["commits"] = tuple(dict.fromkeys(tuple(current.get("commits", ()))
                                                 + tuple(draft.get("commits", ()))))
        current["present_at_head"] = bool(current.get("present_at_head")
                                          or draft.get("present_at_head"))
        current["merged_count"] += 1
    return tuple(merged.values())


def scan_secrets(blobs):
    """Scan one blob per (commit, path) for committed credentials.

    `blobs` is an iterable of {"commit", "path", "text", "is_head"}. The caller walks
    the PR's own commits, so a credential added and later deleted is still seen.
    """
    drafts = {}
    for blob in blobs:
        path, text = blob.get("path") or "", blob.get("text") or ""
        commit = blob.get("commit") or ""
        is_head = bool(blob.get("is_head"))
        if not path:
            continue
        for rule_id, line_no, value in _secret_hits(path, text):
            key = (path, rule_id, _digest(value))
            draft = drafts.get(key)
            if draft is None:
                draft = drafts[key] = {
                    "rule_id": rule_id, "path": path, "commits": [],
                    "value_sha256": _digest(value), "value_length": len(value),
                    "first_line": line_no, "head_line": None,
                    "first_text": text, "head_text": None}
            if commit and commit not in draft["commits"]:
                draft["commits"].append(commit)
            if is_head:
                draft["head_line"] = line_no
                draft["head_text"] = text
    ordered = sorted(drafts.values(),
                     key=lambda d: (d["path"], d["rule_id"], d["value_sha256"]))
    return merge_by_fingerprint(_secret_draft(d) for d in ordered)


def _secret_draft(state):
    """Turn accumulated hits for one credential into a draft candidate.

    The symbol is resolved from the head revision when the credential is still there,
    so a hunter reading head lands on exactly the same fingerprint.
    """
    at_head = state["head_text"] is not None
    text = state["head_text"] if at_head else state["first_text"]
    line = state["head_line"] if at_head else state["first_line"]
    symbol = fp.enclosing_symbol(text, line, state["path"])
    return {
        "kind": "draft_candidate",
        "source": "seeder",
        "seeder": "secret-scan",
        "rule_id": state["rule_id"],
        "class_ref": CRYPTO_SECRETS,
        "fingerprint": fp.build(CRYPTO_SECRETS, state["path"], symbol),
        "path": state["path"],
        "line": line,
        "symbol": symbol,
        "commits": tuple(state["commits"]),
        "present_at_head": at_head,
        "value_sha256": state["value_sha256"],
        "value_length": state["value_length"],
        "summary": ("a value matching the %s pattern is committed in this pull request's "
                    "history%s" % (state["rule_id"],
                                   "" if at_head else " and was later removed, so it is "
                                                      "absent from the base..head diff")),
        "requires_verification": True,
        "note": NOT_A_FINDING,
    }


# ------------------------------------------------------------------ GitHub Actions

PRIVILEGED_TRIGGERS = frozenset(("pull_request_target", "workflow_run"))

# Checkout refs that resolve to contributor-controlled code.
HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|"
    r"github\.event\.pull_request\.merge_commit_sha|"
    r"github\.event\.workflow_run\.head_(?:sha|branch|commit)|"
    r"github\.head_ref|refs/pull/")

# Closed list of attacker-writable event fields. `github.event.number`,
# `github.event.action`, `github.sha` and friends are deliberately absent: they are not
# free text, and flagging them is the false positive that makes a seeder ignorable.
UNTRUSTED_EXPR_RE = re.compile(
    r"github\.head_ref|"
    r"github\.event\.(?:"
    r"issue\.(?:title|body)|"
    r"pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.[\w.]+)|"
    r"comment\.body|review\.body|review_comment\.body|"
    r"discussion\.(?:title|body)|"
    r"head_commit\.(?:message|author\.\w+)|"
    r"commits\[[^\]]*\]\.(?:message|author\.\w+)|"
    r"pages\[[^\]]*\]\.page_name|"
    r"workflow_run\.(?:head_branch|head_commit\.message|display_title)"
    r")")

EXPRESSION_RE = re.compile(r"\$\{\{(?P<body>[^}]*)\}\}")
_KEY_RE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[A-Za-z_][\w.-]*)\s*:(?P<rest>.*)$")
_STEP_RE = re.compile(r"^(?P<indent>\s*)-\s")


def _strip_comment(value):
    return value.split("#", 1)[0].strip() if "#" in value else value.strip()


def _triggers(lines):
    """Trigger names from an `on:` mapping, inline list or scalar. No YAML parser here."""
    found = set()
    for index, line in enumerate(lines):
        match = re.match(r"^(?:['\"]?on['\"]?)\s*:(?P<rest>.*)$", line)
        if not match:
            continue
        rest = _strip_comment(match.group("rest"))
        if rest:
            found.update(re.findall(r"[A-Za-z_][\w-]*", rest))
        # Trigger names sit at exactly one indent level under `on:`; anything deeper is
        # a trigger's own filter (`types:`, `branches:`) and is not a trigger.
        trigger_indent = None
        for follower in lines[index + 1:]:
            if not follower.strip() or follower.lstrip().startswith("#"):
                continue
            indent = len(follower) - len(follower.lstrip(" "))
            if indent == 0:
                break
            if trigger_indent is None:
                trigger_indent = indent
            if indent != trigger_indent:
                continue
            name = re.match(r"^\s*(?:-\s*)?([A-Za-z_][\w-]*)\s*:?", follower)
            if name:
                found.add(name.group(1))
        break
    return found


def _job_ranges(lines):
    """[(job_id, start_index, end_index)] using the indentation under `jobs:`."""
    jobs, start, job_indent, current, job_start = [], None, None, None, 0
    for index, line in enumerate(lines):
        if re.match(r"^jobs\s*:", line):
            start = index + 1
            continue
        if start is None or index < start:
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            if current:
                jobs.append((current, job_start, index))
                current = None
            start = None
            continue
        match = re.match(r"^\s*([A-Za-z_][\w.-]*)\s*:", line)
        if not match:
            continue
        if job_indent is None:
            job_indent = indent
        if indent == job_indent:
            if current:
                jobs.append((current, job_start, index))
            current, job_start = match.group(1), index
    if current:
        jobs.append((current, job_start, len(lines)))
    return jobs


def _job_of(jobs, index):
    for job_id, start, end in jobs:
        if start <= index < end:
            return job_id
    return ""


def _block_lines(lines, index):
    """The body of a block scalar (`run: |`) starting at `index`, plus its own line."""
    match = _KEY_RE.match(lines[index])
    if not match:
        return [(index, lines[index])]
    base = len(match.group("indent")) + (2 if _STEP_RE.match(lines[index]) else 0)
    # A `#` inside a shell command is not a YAML comment, so the body is never
    # comment-stripped; only the block-scalar indicator itself is dropped.
    rest = match.group("rest").strip()
    body = [(index, "" if rest[:1] in ("|", ">") else rest)]
    for offset in range(index + 1, len(lines)):
        line = lines[offset]
        if not line.strip():
            body.append((offset, line))
            continue
        if len(line) - len(line.lstrip(" ")) <= base:
            break
        body.append((offset, line))
    return body


def scan_workflows(workflows):
    """Draft candidates for the two high-value GitHub Actions patterns.

    `workflows` is an iterable of {"path", "text"} at head. Both detectors require a
    privileged trigger, which is what separates them from ordinary CI hygiene.
    """
    drafts = []
    for entry in workflows:
        path, text = entry.get("path") or "", entry.get("text") or ""
        if not path or not text:
            continue
        lines = text.splitlines()
        triggers = _triggers(lines)
        privileged = sorted(triggers & PRIVILEGED_TRIGGERS)
        if not privileged:
            continue
        jobs = _job_ranges(lines)
        drafts.extend(_checkout_drafts(path, text, lines, jobs, privileged))
        drafts.extend(_expression_drafts(path, text, lines, jobs, privileged))
    return merge_by_fingerprint(
        sorted(drafts, key=lambda d: (d["fingerprint"], d["line"])))


def _checkout_drafts(path, text, lines, jobs, privileged):
    """A privileged trigger plus an explicit checkout of the PR head."""
    out, seen = [], set()
    for index, line in enumerate(lines):
        if not re.search(r"uses\s*:\s*[\w.-]+/checkout@", line):
            continue
        step_indent = len(line) - len(line.lstrip(" "))
        for offset in range(index + 1, len(lines)):
            follower = lines[offset]
            if not follower.strip():
                continue
            indent = len(follower) - len(follower.lstrip(" "))
            if indent < step_indent or _STEP_RE.match(follower):
                break
            ref = re.match(r"^\s*ref\s*:(?P<value>.*)$", follower)
            if not ref or not HEAD_REF_RE.search(ref.group("value")):
                continue
            job = _job_of(jobs, offset)
            symbol = fp.enclosing_symbol(text, offset + 1, path)
            key = (path, symbol)
            if key in seen:
                break
            seen.add(key)
            out.append({
                "kind": "draft_candidate", "source": "seeder",
                "seeder": "actions-privileged-checkout",
                "rule_id": "privileged-trigger-head-checkout",
                "class_ref": CI_UNTRUSTED_CODE,
                "fingerprint": fp.build(CI_UNTRUSTED_CODE, path, symbol),
                "path": path, "line": offset + 1, "symbol": symbol,
                "job": job, "triggers": tuple(privileged),
                "evidence": sanitize(follower),
                "summary": ("workflow runs on %s and checks out a contributor-controlled "
                            "ref, so untrusted code may execute with this workflow's "
                            "secrets and token" % ", ".join(privileged)),
                "requires_verification": True, "note": NOT_A_FINDING})
            break
    return out


def _expression_drafts(path, text, lines, jobs, privileged):
    """An untrusted event field interpolated directly into a run:/script: block."""
    out, seen = [], set()
    index = 0
    while index < len(lines):
        match = _KEY_RE.match(lines[index])
        if not match or match.group("key") not in ("run", "script"):
            index += 1
            continue
        body = _block_lines(lines, index)
        for offset, content in body:
            for expression in EXPRESSION_RE.finditer(content):
                if not UNTRUSTED_EXPR_RE.search(expression.group("body")):
                    continue
                job = _job_of(jobs, offset)
                symbol = fp.enclosing_symbol(text, offset + 1, path)
                key = (path, symbol, expression.group("body").strip())
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": "draft_candidate", "source": "seeder",
                    "seeder": "actions-expression-injection",
                    "rule_id": "untrusted-expression-in-run",
                    "class_ref": CI_EXPRESSION,
                    "fingerprint": fp.build(CI_EXPRESSION, path, symbol),
                    "path": path, "line": offset + 1, "symbol": symbol,
                    "job": job, "triggers": tuple(privileged),
                    "evidence": sanitize("${{%s}}" % expression.group("body")),
                    "summary": ("an attacker-writable ${{ github.event... }} field is "
                                "interpolated into a %s: block before the shell parses "
                                "it" % match.group("key")),
                    "requires_verification": True, "note": NOT_A_FINDING})
        index = body[-1][0] + 1 if len(body) > 1 else index + 1
    return out


def run(commit_blobs=(), workflows=()):
    """All draft candidates for one run, ordered by fingerprint then location."""
    drafts = list(scan_secrets(commit_blobs)) + list(scan_workflows(workflows))
    drafts.sort(key=lambda d: (d["fingerprint"], d["path"], d["line"]))
    return merge_by_fingerprint(drafts)
