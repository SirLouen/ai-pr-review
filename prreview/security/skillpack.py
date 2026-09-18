"""Byte-exact extraction of security-audit skill text for agent prompts.

`HUNTING.md:18` forbids sending block or companion names alone; `HUNTING.md:13-23` and
`VALIDATION-AND-REPORTING.md:7` name the exact blocks a hunter and a verifier prompt must
carry verbatim. This module is the only place that turns one of those names into text, so
no prompt can quietly end up carrying a paraphrase.

Three guarantees, in order:

1. `MANIFEST` (upstream commit plus a sha256 per file) is checked before any slice is read.
   A modified vendored file stops the run, because a silently edited skill file means the
   prompts no longer say what the design says they say.
2. Every block is one contiguous slice of one vendored file, addressed by a stable anchor -
   a heading, a bold class name, or a unique line prefix - never by a line number, which an
   upstream edit shifts with no signal at all.
3. `blocks.lock` pins a sha256 per *named block*, so an upstream heading rename or a
   reordered paragraph fails CI instead of silently thinning a production prompt. `MANIFEST`
   cannot catch that on its own: it only says the file changed, not which prompt lost text.

Fence policy, decided deliberately (Design B sliced by line range and would have embedded
the delimiter lines): the skill wraps in a ``` fence exactly the text it tells the parent to
copy into an agent prompt - "include in every hunter prompt", "copy this promotion procedure
verbatim", "(include in every agent prompt for this domain)". Those blocks are extracted as
fence *content*; the ``` lines are markdown packaging and would put stray backticks into
every prompt, and their headings address the parent, not the agent. Prose sections that the
parent merely selects - attack classes, `Universal moves`, `Validation rules`, the structured
result contracts - are taken whole with their heading, because their own prose introduces the
JSON fences nested inside them.

Nothing here is ever "confirmed"-aware: the `confirmed` schema branch is extracted and shipped
like any other block, because `HUNTING.md:23` requires it in the prompt. Refusing a `confirmed`
verdict is the parent's job, not this module's.
"""
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass

# _default_vendor_dir is config's, so the vendor path is resolved in exactly one place.
from .config import ConfigError, _default_vendor_dir

MANIFEST_NAME = "MANIFEST"
LOCK_NAME = "blocks.lock"
SCHEMA_NAME = "report-schema.json"

# Files that live in the vendor directory but are not vendored upstream content, so they are
# not expected to appear in MANIFEST.
UNLISTED = (MANIFEST_NAME, LOCK_NAME)

COMPANIONS = (
    "AI-AND-LLM.md",
    "CLIENT-SIDE.md",
    "CLOUD-AND-DEPLOYMENT.md",
    "DATA-ISOLATION-AND-LIFECYCLE.md",
    "DESKTOP-MOBILE-AND-LOCAL-IPC.md",
    "MEMORY-SAFETY-AND-BINARY.md",
    "PROTOCOLS-RPC-AND-MESSAGING.md",
    "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
    "SUPPLY-CHAIN-AND-RELEASE.md",
    "WEB-PROTOCOL-AND-AUTH.md",
)

# The three sections HUNTING.md:18 requires from every selected companion, by the short name
# used in a canonical ref. `Core discipline` is fenced; the other two are prose.
COMPANION_CORE = "Core discipline"
COMPANION_UNIVERSAL = "Universal moves"
COMPANION_RULES = "Validation rules"

HEADING_RE = re.compile(r"^(#{1,6}) (.+?)\s*$")
# ATTACK-CLASSES.md names an ordinary class on a bold line carrying its subagent type.
CLASS_RE = re.compile(r"^\*\*(?P<name>[^*]+)\*\*\s+\(subagent_type:")
# A companion names an attack-class subsection with a bare bold line.
SUBCLASS_RE = re.compile(r"^\*\*(?P<name>[^*]+)\*\*\s*$")
FENCE_RE = re.compile(r"^```")
# A heading's trailing parenthetical addresses the parent ("include in every agent prompt
# for this domain"); the canonical ref uses the name without it.
PAREN_TAIL_RE = re.compile(r"\s*\([^()]*\)\s*$")


class SkillPackError(ConfigError):
    """The vendored skill is not what it was pinned to be, or a block no longer resolves.

    Deliberately a ConfigError: both mean the run must stop before the first model call.
    """


@dataclass(frozen=True)
class Spec:
    """Where a named block lives, in anchors rather than line numbers.

    kind:
      section  anchor is a heading line; the block runs to the next heading of the same or a
               higher level, or to `stop` when the file nests deeper headings inside it.
      fence    anchor is any unique line; the block is the content of the next ``` fence.
      klass    anchor is a bold class line; the block runs to the next peer or heading.
      span     anchor is the first line; the block ends at the end of the `stop` line.
      schema   report-schema.json branch whose `verdict.const` equals anchor.
    """
    file: str
    kind: str
    anchor: str
    stop: str = ""


@dataclass(frozen=True)
class Block:
    """One extracted block. `text` is exactly `file_text[start:end]`, never reassembled."""
    name: str
    file: str
    start: int
    end: int
    text: str

    @property
    def sha256(self):
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def nbytes(self):
        return len(self.text.encode("utf-8"))

    @property
    def tokens(self):
        return estimate_tokens(self.text)


# Blocks the design names explicitly. Everything else (ordinary attack classes, every
# companion section and subsection) is discovered from the files themselves, so a new
# upstream subsection appears in blocks.lock instead of going unnoticed.
SPECS = {
    # --- SKILL.md: every agent system prompt (design 4.3, 4.4) ---
    "SKILL.md#Core principles": Spec("SKILL.md", "section", "## Core principles"),
    "SKILL.md#Separate priority from certainty":
        Spec("SKILL.md", "section", "### Separate priority from certainty"),
    "SKILL.md#Anti-patterns": Spec("SKILL.md", "section", "## Anti-patterns"),

    # --- HUNTING.md: the nine required hunter-prompt parts ---
    "HUNTING.md#Required hunter prompt":
        Spec("HUNTING.md", "section", "## Required hunter prompt",
             stop="#### Core hunting method"),
    "HUNTING.md#Core hunting method":
        Spec("HUNTING.md", "fence", "#### Core hunting method"),
    "HUNTING.md#Promotion procedure":
        Spec("HUNTING.md", "fence", "#### Promotion procedure"),
    "HUNTING.md#Candidate gate":
        Spec("HUNTING.md", "fence", "#### Core validation rules"),
    "HUNTING.md#Local validation boundaries":
        Spec("HUNTING.md", "section", "## Local validation boundaries"),
    "HUNTING.md#Structured hunter result":
        Spec("HUNTING.md", "section", "## Structured hunter result"),
    "HUNTING.md#Coverage-critic waves":
        Spec("HUNTING.md", "section", "## Coverage-critic waves"),
    "HUNTING.md#Critic contract":
        Spec("HUNTING.md", "span", "Immediately after each hunter wave,",
             stop="The critic checks for unmapped entry points,"),
    "HUNTING.md#Quick-profile critic handling":
        Spec("HUNTING.md", "span", "The run profile bounds this loop."),
    "HUNTING.md#Hunter priority order":
        Spec("HUNTING.md", "span", "When a budget or profile caps hunter count,"),

    # --- VALIDATION-AND-REPORTING.md: the verifier prompt (VAL:7) ---
    "VALIDATION-AND-REPORTING.md#Verifier input whitelist":
        Spec("VALIDATION-AND-REPORTING.md", "span",
             "Assign each verifier a canonical lowercase unique ID"),
    "VALIDATION-AND-REPORTING.md#Candidate-verifier prompt":
        Spec("VALIDATION-AND-REPORTING.md", "fence", "#### Candidate-verifier prompt"),
    "VALIDATION-AND-REPORTING.md#Verifier promotion procedure":
        Spec("VALIDATION-AND-REPORTING.md", "fence",
             "Copy this promotion procedure verbatim into every candidate-verifier prompt:"),
    "VALIDATION-AND-REPORTING.md#Verifier decision rules":
        Spec("VALIDATION-AND-REPORTING.md", "span",
             "A verifier can promote `needs_validation` to `confirmed`"),
    "VALIDATION-AND-REPORTING.md#Quick merge":
        Spec("VALIDATION-AND-REPORTING.md", "span", "In a `quick` run, Phase 3 and Phase 5 merge:"),
    "VALIDATION-AND-REPORTING.md#Final record checks":
        Spec("VALIDATION-AND-REPORTING.md", "span", "For `confirmed`, require it to check:",
             stop="5. The fingerprint matches prior/current records for the same root cause."),

    # --- RECONNAISSANCE.md: the four fenced recon prompts and the selection discipline ---
    "RECONNAISSANCE.md#Agent 1a":
        Spec("RECONNAISSANCE.md", "fence", "**Agent 1a:"),
    "RECONNAISSANCE.md#Agent 1b":
        Spec("RECONNAISSANCE.md", "fence", "**Agent 1b:"),
    "RECONNAISSANCE.md#Agent 1c":
        Spec("RECONNAISSANCE.md", "fence", "**Agent 1c:"),
    "RECONNAISSANCE.md#Agent 1d":
        Spec("RECONNAISSANCE.md", "fence", "**Agent 1d:"),
    "RECONNAISSANCE.md#Prior-run input":
        Spec("RECONNAISSANCE.md", "section", "## Prior-run input"),
    "RECONNAISSANCE.md#Architecture summary and companion selection":
        Spec("RECONNAISSANCE.md", "section", "## Architecture summary and companion selection"),
    "RECONNAISSANCE.md#Companion selection discipline":
        Spec("RECONNAISSANCE.md", "span", "Do not select a companion file merely because"),
    "RECONNAISSANCE.md#Exclusion reasons":
        Spec("RECONNAISSANCE.md", "span", "When `lifecycle` is material,"),

    # --- report-schema.json: all three branches, sliced from the vendored bytes ---
    "report-schema.json#confirmed": Spec(SCHEMA_NAME, "schema", "confirmed"),
    "report-schema.json#needs_validation": Spec(SCHEMA_NAME, "schema", "needs_validation"),
    "report-schema.json#rejected": Spec(SCHEMA_NAME, "schema", "rejected"),
}

# The hunter's Part 6, in HUNTING.md:20 order. SkillPack.method_section() appends the action's
# no-execution policy after these two; it never replaces either of them.
HUNTER_METHOD = ("HUNTING.md#Core hunting method", "HUNTING.md#Promotion procedure")

# Part 9 of the hunter prompt (HUNTING.md:23). The `confirmed` branch stays even though the
# parent refuses a confirmed verdict: the skill requires it, and omitting it costs fidelity
# for nothing, since the refusal happens in code.
HUNTER_SCHEMA_BRANCHES = ("report-schema.json#confirmed",
                          "report-schema.json#needs_validation")
VERIFIER_SCHEMA_BRANCHES = HUNTER_SCHEMA_BRANCHES + ("report-schema.json#rejected",)

# Every agent system prompt (design 4.3).
SYSTEM_BLOCKS = ("SKILL.md#Core principles", "SKILL.md#Anti-patterns")

ACTION_BLOCK_OPEN = "----- BEGIN ACTION-OWNED BLOCK (not security-audit skill text) -----"
ACTION_BLOCK_CLOSE = "----- END ACTION-OWNED BLOCK -----"


_TOKENISH = re.compile(r"\w+|[^\w\s]")


def estimate_tokens(text):
    """Rough token count for prompt budgeting.

    Deliberately biased high: a budget that under-counts overflows the context window mid-run,
    which costs a whole conversation, while over-counting only leaves headroom unused. Words
    are charged one token per four characters and every punctuation mark one token.
    """
    return sum(max(1, (len(piece) + 3) // 4) for piece in _TOKENISH.findall(text))


class SkillPack:
    """Verified access to one vendored skill directory. Build it through pack()."""

    def __init__(self, vendor_dir):
        self.vendor_dir = os.path.abspath(vendor_dir)
        self.commit = ""
        self._files = {}
        self._starts = {}
        self._blocks = {}
        self._specs = {}
        self._verify_manifest()
        self._build_registry()

    # -- vendored bytes ----------------------------------------------------------------

    def _read(self, name):
        if name not in self._files:
            path = os.path.join(self.vendor_dir, name)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
            except OSError as e:
                raise SkillPackError("cannot read vendored %s: %s" % (name, e))
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise SkillPackError("vendored %s is not utf-8: %s" % (name, e))
            self._files[name] = text
            self._starts[name] = _line_starts(text)
        return self._files[name]

    def _verify_manifest(self):
        """Fail loudly on any drift from the pinned upstream tree, in either direction."""
        path = os.path.join(self.vendor_dir, MANIFEST_NAME)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                manifest = fh.read()
        except OSError as e:
            raise SkillPackError("cannot read %s: %s" % (path, e))
        expected = {}
        for line in manifest.splitlines():
            line = line.strip()
            if line.startswith("# commit "):
                self.commit = line[len("# commit "):].strip()
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition("  ")
            if len(digest) != 64 or not name:
                raise SkillPackError("malformed %s line: %r" % (MANIFEST_NAME, line[:80]))
            expected[name.strip()] = digest
        if not expected:
            raise SkillPackError("%s lists no files" % MANIFEST_NAME)

        try:
            present = set(os.listdir(self.vendor_dir))
        except OSError as e:
            raise SkillPackError("cannot list %s: %s" % (self.vendor_dir, e))
        extra = sorted(present - set(expected) - set(UNLISTED))
        if extra:
            raise SkillPackError(
                "%s does not list vendored file(s): %s" % (MANIFEST_NAME, ", ".join(extra)))
        for name in sorted(expected):
            file_path = os.path.join(self.vendor_dir, name)
            try:
                with open(file_path, "rb") as fh:
                    got = hashlib.sha256(fh.read()).hexdigest()
            except OSError as e:
                raise SkillPackError("vendored %s is missing or unreadable: %s" % (name, e))
            if got != expected[name]:
                raise SkillPackError(
                    "vendored %s does not match %s (expected %s, got %s); the skill text was "
                    "edited, so the prompts no longer carry the pinned contract"
                    % (name, MANIFEST_NAME, expected[name][:12], got[:12]))

    # -- registry ----------------------------------------------------------------------

    def _build_registry(self):
        self._specs = dict(SPECS)
        self._specs.update(self._discover_attack_classes())
        for companion in COMPANIONS:
            self._specs.update(self._discover_companion(companion))

    def _discover_attack_classes(self):
        """Every ordinary class in ATTACK-CLASSES.md, by its bold name."""
        found = {}
        for line in self._read("ATTACK-CLASSES.md").splitlines():
            m = CLASS_RE.match(line)
            if m:
                name = m.group("name")
                found["ATTACK-CLASSES.md#" + name] = Spec(
                    "ATTACK-CLASSES.md", "klass", "**%s**" % name)
        if not found:
            raise SkillPackError("ATTACK-CLASSES.md has no ordinary attack-class blocks")
        return found

    def _discover_companion(self, companion):
        """Every `##` section and every bold attack-class subsection of one companion file."""
        found, sections = {}, []
        for line in self._read(companion).splitlines():
            m = HEADING_RE.match(line)
            if m and len(m.group(1)) == 2:
                short = PAREN_TAIL_RE.sub("", m.group(2))
                sections.append(short)
                kind = "fence" if short == COMPANION_CORE else "section"
                found["%s#%s" % (companion, short)] = Spec(companion, kind, line)
                continue
            m = SUBCLASS_RE.match(line)
            if m:
                name = m.group("name")
                found["%s#%s" % (companion, name)] = Spec(companion, "klass", line)
        for required in (COMPANION_CORE, COMPANION_UNIVERSAL, COMPANION_RULES):
            if required not in sections:
                raise SkillPackError(
                    "%s has no `%s` section; HUNTING.md:18 requires one in every companion"
                    % (companion, required))
        return found

    # -- extraction --------------------------------------------------------------------

    def names(self):
        return sorted(self._specs)

    def has(self, name):
        return name in self._specs

    def block(self, name):
        if name in self._blocks:
            return self._blocks[name]
        spec = self._specs.get(name)
        if spec is None:
            raise SkillPackError("no such skill block: %r" % (name,))
        text = self._read(spec.file)
        starts = self._starts[spec.file]
        if spec.kind == "schema":
            start, end = _schema_branch(text, spec.anchor, spec.file)
        elif spec.kind == "section":
            start, end = _section(text, starts, spec)
        elif spec.kind == "fence":
            start, end = _fence(text, starts, spec)
        elif spec.kind == "klass":
            start, end = _klass(text, starts, spec)
        elif spec.kind == "span":
            start, end = _span(text, starts, spec)
        else:
            raise SkillPackError("unknown block kind %r for %r" % (spec.kind, name))
        if end <= start:
            raise SkillPackError("block %r resolved to nothing in %s" % (name, spec.file))
        block = Block(name=name, file=spec.file, start=start, end=end, text=text[start:end])
        self._blocks[name] = block
        return block

    def text(self, name):
        return self.block(name).text

    def file_text(self, name):
        """The whole vendored file, for a test that re-derives a slice independently."""
        return self._read(name)

    # -- accounting --------------------------------------------------------------------

    def account(self, names):
        """Bytes and an estimated token count per block plus totals, for the budget gate."""
        blocks = [self.block(n) for n in names]
        per = [{"name": b.name, "bytes": b.nbytes, "tokens": b.tokens} for b in blocks]
        return {"blocks": per,
                "bytes": sum(p["bytes"] for p in per),
                "tokens": sum(p["tokens"] for p in per)}

    def fits(self, names, token_budget):
        """True when the named blocks alone leave room in `token_budget`."""
        return self.account(names)["tokens"] <= token_budget

    # -- composed sections -------------------------------------------------------------

    def method_section(self, policy_text):
        """Hunter/verifier Part 6: core method, then promotion procedure, then our policy.

        HUNTING.md:20 requires "the core hunting method below, followed by the promotion
        procedure block". Both go in unedited; the run's no-execution policy is appended as a
        clearly delimited action-owned block, never as a substitution for skill text, because
        an agent that cannot see the skill's own no-sandbox rule (HUNTING.md:77) loses the
        contract this whole module exists to preserve.
        """
        parts = [self.text(name) for name in HUNTER_METHOD]
        parts.append("\n".join([ACTION_BLOCK_OPEN, policy_text.strip(), ACTION_BLOCK_CLOSE]))
        return "\n\n".join(parts)

    def companion_blocks(self, companion, subclasses):
        """The block names HUNTING.md:18 requires for one selected companion, in its order."""
        names = ["%s#%s" % (companion, COMPANION_CORE)]
        for sub in subclasses:
            name = "%s#%s" % (companion, sub)
            if not self.has(name):
                raise SkillPackError("%s has no attack-class subsection %r" % (companion, sub))
            names.append(name)
        names.append("%s#%s" % (companion, COMPANION_UNIVERSAL))
        names.append("%s#%s" % (companion, COMPANION_RULES))
        return names

    # -- blocks.lock -------------------------------------------------------------------

    def lock_text(self):
        lines = [
            "# blocks.lock - sha256 of every named block prreview/security/skillpack.py extracts",
            "# from the vendored security-audit skill. A heading rename or a reordered paragraph",
            "# changes a block digest here even when MANIFEST still matches, which is the point.",
            "# skill commit %s" % (self.commit or "unknown"),
            "# regenerate: python3 -m prreview.security.skillpack lock",
            "# <sha256>  <bytes>  <block name>",
        ]
        for name in self.names():
            block = self.block(name)
            lines.append("%s  %6d  %s" % (block.sha256, block.nbytes, name))
        return "\n".join(lines) + "\n"

    def lock_path(self):
        return os.path.join(self.vendor_dir, LOCK_NAME)

    def verify_lock(self):
        """Return a list of human-readable problems; empty means the lock is current."""
        path = self.lock_path()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                recorded = _parse_lock(fh.read())
        except OSError as e:
            return ["cannot read %s: %s" % (path, e)]
        problems = []
        current = self.names()
        for name in current:
            block = self.block(name)
            want = recorded.get(name)
            if want is None:
                problems.append("block not in %s: %s" % (LOCK_NAME, name))
            elif want != block.sha256:
                problems.append("block changed since %s: %s (%s -> %s)"
                                % (LOCK_NAME, name, want[:12], block.sha256[:12]))
        for name in sorted(set(recorded) - set(current)):
            problems.append("block no longer resolves: %s" % name)
        return problems


def _parse_lock(text):
    recorded = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(None, 2)          # a block name may contain spaces; the rest is it
        if len(fields) != 3 or len(fields[0]) != 64:
            raise SkillPackError("malformed %s line: %r" % (LOCK_NAME, line[:80]))
        recorded[fields[2].strip()] = fields[0]
    return recorded


# -- anchor resolution -----------------------------------------------------------------

def _line_starts(text):
    starts, pos = [0], text.find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return starts


def _line(text, starts, i):
    end = starts[i + 1] - 1 if i + 1 < len(starts) else len(text)
    return text[starts[i]:end]


def _find_line(text, starts, prefix, where):
    """Index of the one line starting with `prefix`. Ambiguity is an error, not a guess."""
    hits = [i for i in range(len(starts)) if _line(text, starts, i).startswith(prefix)]
    if not hits:
        raise SkillPackError("anchor %r not found in %s" % (prefix, where))
    if len(hits) > 1:
        raise SkillPackError("anchor %r is ambiguous in %s (%d lines)"
                             % (prefix, where, len(hits)))
    return hits[0]


def _line_end(text, starts, i):
    return starts[i + 1] - 1 if i + 1 < len(starts) else len(text)


def _trim(text, start, end):
    while end > start and text[end - 1] in " \t\r\n":
        end -= 1
    return start, end


def _section(text, starts, spec):
    i = _find_line(text, starts, spec.anchor, spec.file)
    m = HEADING_RE.match(_line(text, starts, i))
    if not m:
        raise SkillPackError("section anchor %r is not a heading in %s"
                             % (spec.anchor, spec.file))
    level = len(m.group(1))
    end = len(text)
    for j in range(i + 1, len(starts)):
        line = _line(text, starts, j)
        if spec.stop and line.startswith(spec.stop):
            end = starts[j]
            break
        h = HEADING_RE.match(line)
        if h and len(h.group(1)) <= level:
            end = starts[j]
            break
    return _trim(text, starts[i], end)


def _fence(text, starts, spec):
    """Content of the next ``` fence after the anchor, delimiter lines excluded."""
    i = _find_line(text, starts, spec.anchor, spec.file)
    open_at = None
    for j in range(i + 1, len(starts)):
        if FENCE_RE.match(_line(text, starts, j)):
            open_at = j
            break
    if open_at is None:
        raise SkillPackError("no fence after %r in %s" % (spec.anchor, spec.file))
    for j in range(open_at + 1, len(starts)):
        if FENCE_RE.match(_line(text, starts, j)):
            # Stop before the newline that ends the last content line.
            return _trim(text, starts[open_at + 1], starts[j])
    raise SkillPackError("unterminated fence after %r in %s" % (spec.anchor, spec.file))


def _klass(text, starts, spec):
    """A bold-named class block, ending at the next peer bold name or the next heading."""
    i = _find_line(text, starts, spec.anchor, spec.file)
    peer = CLASS_RE if CLASS_RE.match(_line(text, starts, i)) else SUBCLASS_RE
    end = len(text)
    for j in range(i + 1, len(starts)):
        line = _line(text, starts, j)
        if peer.match(line) or HEADING_RE.match(line):
            end = starts[j]
            break
    return _trim(text, starts[i], end)


def _span(text, starts, spec):
    i = _find_line(text, starts, spec.anchor, spec.file)
    j = _find_line(text, starts, spec.stop, spec.file) if spec.stop else i
    if j < i:
        raise SkillPackError("span %r ends before it starts in %s" % (spec.anchor, spec.file))
    return _trim(text, starts[i], _line_end(text, starts, j))


def _schema_branch(text, verdict, where):
    """Byte-exact slice of one `items.oneOf` branch of report-schema.json.

    Sliced rather than re-serialised: the vendored file is already pretty-printed, and
    HUNTING.md:23 says "copied verbatim", which a json.dumps() round-trip would not be.
    """
    key = text.find('"oneOf"')
    if key < 0:
        raise SkillPackError("%s has no items.oneOf" % where)
    bracket = text.find("[", key)
    if bracket < 0:
        raise SkillPackError("%s has a malformed items.oneOf" % where)
    decoder = json.JSONDecoder()
    pos = bracket + 1
    while True:
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text) or text[pos] != "{":
            raise SkillPackError("%s has no %r branch in items.oneOf" % (where, verdict))
        try:
            obj, end = decoder.raw_decode(text, pos)
        except ValueError as e:
            raise SkillPackError("%s items.oneOf is not valid JSON: %s" % (where, e))
        const = ((obj.get("properties") or {}).get("verdict") or {}).get("const")
        if const == verdict:
            return pos, end
        pos = end


# -- module-level access ----------------------------------------------------------------

_CACHE = {}


def pack(vendor_dir=None):
    """The verified SkillPack for a vendor directory, built once per process."""
    path = os.path.abspath(vendor_dir or _default_vendor_dir())
    if path not in _CACHE:
        _CACHE[path] = SkillPack(path)
    return _CACHE[path]


def text(name, vendor_dir=None):
    return pack(vendor_dir).text(name)


def account(names, vendor_dir=None):
    return pack(vendor_dir).account(names)


def main(argv=None):
    """lock | verify | list | show <name> | account <name>..."""
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv.pop(0) if argv else "verify"
    vendor_dir = os.environ.get("SA_VENDOR_DIR") or None
    try:
        sp = pack(vendor_dir)
    except SkillPackError as e:
        print("ERROR: %s" % e)
        return 2
    if command == "lock":
        with open(sp.lock_path(), "w", encoding="utf-8") as fh:
            fh.write(sp.lock_text())
        print("wrote %s (%d blocks)" % (sp.lock_path(), len(sp.names())))
        return 0
    if command == "verify":
        problems = sp.verify_lock()
        for problem in problems:
            print("ERROR: %s" % problem)
        print("%d blocks, %s" % (len(sp.names()), "stale" if problems else "lock is current"))
        return 1 if problems else 0
    if command == "list":
        for name in sp.names():
            block = sp.block(name)
            print("%-72s %6d B  ~%5d tok" % (name, block.nbytes, block.tokens))
        return 0
    if command == "show" and argv:
        print(sp.text(argv[0]))
        return 0
    if command == "account" and argv:
        totals = sp.account(argv)
        for row in totals["blocks"]:
            print("%-72s %6d B  ~%5d tok" % (row["name"], row["bytes"], row["tokens"]))
        print("%-72s %6d B  ~%5d tok" % ("TOTAL", totals["bytes"], totals["tokens"]))
        return 0
    print(main.__doc__)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:   # `... list | head` closes the pipe; not an error worth a trace
        sys.stderr.close()
        raise SystemExit(0)
