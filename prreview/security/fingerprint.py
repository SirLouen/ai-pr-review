"""Parent-computed finding fingerprints: sa1:<class>:<sink path>@<sink symbol>.

HUNTING.md:153-155 requires one source-derived fingerprint per root cause, matching
`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` and containing no line, wave, agent, severity or
verdict. The skill gives the constraints but no derivation, so the parent supplies one
and no model ever chooses a component of it:

    sa1:<class token>:<esc(sink path)>@<esc(sink symbol)>[:r<N>]

The class token comes from a closed table keyed by the unit's attack-class block
reference. The sink path is `trace[-1].file` at head with the prior-run rename map
applied. The sink symbol is resolved here, by regex, from the file text at
`trace[-1].line` -- never the model's own scope string, which would let an injected
agent vary the key per push to defeat dedupe.

No line number appears anywhere in it, so a fingerprint survives line shifts and
reformatting; the rename map carries it across a file rename.

There is exactly ONE producer of fingerprints. The seeders in `seeders.py` call
`for_sink()` like everything else, so a secret a seeder drafts and the same secret a
hunter proposes collapse to one record instead of two.
"""
import hashlib
import re

from .routing import ATTACK, COMPANION_GROUPS, ORDINARY_CLASSES, block_id

SCHEME = "sa1"
PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")

# esc() keeps only these bytes; everything else becomes +HH. ':' and '@' are NOT in the
# set, so an escaped component can never collide with the field separators.
_SAFE_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-")
MAX_COMPONENT = 180
TOP_LEVEL = "_top"
_HASHED_RE = re.compile(r"^h-[0-9a-f]{12}$")


class FingerprintError(Exception):
    """Raised when a fingerprint cannot be built or does not match the skill's pattern."""


def _build_class_tokens():
    """Closed table: attack-class block reference -> fingerprint class token."""
    table = {}
    for name, token in ORDINARY_CLASSES:
        table[block_id(ATTACK, name)] = token
    for group, (companion, _heading, classes) in COMPANION_GROUPS.items():
        for name, token in classes:
            table[block_id(companion, name)] = "%s-%s" % (group, token)
    return table


CLASS_TOKENS = _build_class_tokens()
BLOCK_BY_TOKEN = {token: block for block, token in CLASS_TOKENS.items()}


def class_token(class_ref):
    """Map `FILE.md#Exact class name` to its token, or fail closed."""
    token = CLASS_TOKENS.get(class_ref)
    if token is None:
        raise FingerprintError("unknown attack-class reference: %r" % (class_ref,))
    return token


def esc(value):
    """Escape one fingerprint component: non-allowlisted bytes become +HH.

    A component that is still over MAX_COMPONENT characters is replaced by
    `h-<sha1[:12]>` of its original bytes, which keeps the fingerprint bounded without
    losing identity -- the same path always hashes to the same token.
    """
    raw = value.encode("utf-8")
    escaped = "".join(chr(b) if b in _SAFE_BYTES else "+%02X" % b for b in raw)
    if len(escaped) > MAX_COMPONENT:
        return "h-" + hashlib.sha1(raw).hexdigest()[:12]
    return escaped


def unesc(component):
    """Reverse esc(). Returns None for a hashed component, which is not reversible."""
    if _HASHED_RE.match(component):
        return None
    out, i = bytearray(), 0
    while i < len(component):
        if component[i] == "+" and i + 2 < len(component):
            try:
                out.append(int(component[i + 1:i + 3], 16))
            except ValueError:
                raise FingerprintError("malformed escape in %r" % component)
            i += 3
        else:
            out.append(ord(component[i]))
            i += 1
    return out.decode("utf-8", "replace")


def build(class_ref, sink_path, sink_symbol, variant=1):
    """Assemble a fingerprint. `variant` > 1 appends the :rN suffix (design 8.3)."""
    if not sink_path:
        raise FingerprintError("sink path is required")
    if not isinstance(variant, int) or variant < 1:
        raise FingerprintError("variant must be an integer >= 1, got %r" % (variant,))
    fp = "%s:%s:%s@%s" % (SCHEME, class_token(class_ref), esc(sink_path),
                          esc(sink_symbol or TOP_LEVEL))
    if variant > 1:
        fp += ":r%d" % variant
    if not PATTERN.match(fp):
        raise FingerprintError("assembled fingerprint violates HUNTING.md:153: %r" % fp)
    return fp


def parse(fingerprint):
    """Split a fingerprint back into its parts. Raises on anything not in this scheme."""
    if not fingerprint.startswith(SCHEME + ":"):
        raise FingerprintError("not an %s fingerprint: %r" % (SCHEME, fingerprint))
    token, _, tail = fingerprint[len(SCHEME) + 1:].partition(":")
    path, sep, rest = tail.partition("@")
    if not sep or not token or not path:
        raise FingerprintError("malformed fingerprint: %r" % fingerprint)
    variant = 1
    symbol = rest
    if ":" in rest:
        symbol, _, suffix = rest.rpartition(":")
        match = re.match(r"^r([2-9]\d*)$", suffix)
        if not match:
            raise FingerprintError("malformed variant suffix in %r" % fingerprint)
        variant = int(match.group(1))
    return {"token": token, "class_ref": BLOCK_BY_TOKEN.get(token),
            "path": unesc(path), "escaped_path": path,
            "symbol": unesc(symbol), "escaped_symbol": symbol,
            "variant": variant, "path_hashed": _HASHED_RE.match(path) is not None}


def sink_key(fingerprint):
    """`class:path@symbol` with no variant suffix.

    This is the key the parent groups prior records by when it offers a verifier the
    `same_root_cause_as` candidates for one sink (design 8.3).
    """
    parts = parse(fingerprint)
    return "%s:%s@%s" % (parts["token"], parts["escaped_path"], parts["escaped_symbol"])


# --------------------------------------------------------------------------- symbols

_KEYWORDS = frozenset((
    "if", "for", "while", "switch", "catch", "return", "do", "else", "try", "with",
    "match", "case", "when", "using", "lock", "foreach", "elif", "except", "finally",
    "function", "def", "new", "await", "yield", "throw", "typeof", "sizeof", "assert"))

_PY_RULES = (
    re.compile(r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"^(?P<indent>\s*)class\s+(?P<name>[A-Za-z_]\w*)"),
)

_JS_RULES = (
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
               r"(?P<name>[A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*="
               r"\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+"
               r"(?P<name>[A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:public|private|protected|static|readonly|async|get|set|\*)?"
               r"\s*(?P<name>[A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?::[^{]+)?\{\s*$"),
)

_GO_RULES = (
    re.compile(r"^func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"^type\s+(?P<name>[A-Za-z_]\w*)\s"),
)

_RUST_RULES = (
    re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?"
               r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+"
               r"(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"^\s*impl(?:<[^>]*>)?\s+(?P<name>[A-Za-z_][\w:]*)"),
    re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|mod)\s+"
               r"(?P<name>[A-Za-z_]\w*)"),
)

_RUBY_RULES = (
    re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][\w?!]*)"),
    re.compile(r"^\s*(?:class|module)\s+(?P<name>[A-Za-z_][\w:]*)"),
)

_PHP_RULES = (
    re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*"
               r"function\s+&?(?P<name>[A-Za-z_]\w*)"),
    re.compile(r"^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+"
               r"(?P<name>[A-Za-z_]\w*)"),
)

# Braced C-family languages: a declaration line ending in ( ... ) { , plus type decls.
_BRACE_RULES = (
    re.compile(r"^\s*(?:@\w+[^\n]*\s+)?(?:(?:public|private|protected|internal|static|"
               r"final|abstract|override|open|suspend|virtual|async|inline|extern|"
               r"unsafe|partial|sealed|const|explicit|inline)\s+)*"
               r"(?:fun|func|sub)?\s*[\w<>\[\]:,.?*&\s]*?"
               r"(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?"
               r"(?:->\s*[\w<>\[\]:,.?*& ]+)?(?:throws [\w.,\s]+)?\{?\s*$"),
    re.compile(r"^\s*(?:(?:public|private|protected|internal|static|final|abstract|"
               r"open|sealed|partial)\s+)*(?:class|interface|struct|enum|union|"
               r"protocol|object|record)\s+(?P<name>[A-Za-z_]\w*)"),
)

_LANG_RULES = {
    "py": _PY_RULES, "pyi": _PY_RULES, "pyx": _PY_RULES, "pxd": _PY_RULES,
    "js": _JS_RULES, "jsx": _JS_RULES, "mjs": _JS_RULES, "cjs": _JS_RULES,
    "ts": _JS_RULES, "tsx": _JS_RULES, "mts": _JS_RULES, "cts": _JS_RULES,
    "vue": _JS_RULES, "svelte": _JS_RULES, "astro": _JS_RULES,
    "go": _GO_RULES, "rs": _RUST_RULES, "rb": _RUBY_RULES, "rake": _RUBY_RULES,
    "php": _PHP_RULES,
}
for _ext in ("c", "h", "cc", "cpp", "cxx", "hpp", "hh", "m", "mm", "java", "kt",
             "kts", "cs", "swift", "scala", "groovy", "dart", "zig"):
    _LANG_RULES[_ext] = _BRACE_RULES

_INDENT_LANGS = frozenset(("py", "pyi", "pyx", "pxd", "rb", "rake"))
_YAML_EXTS = frozenset(("yml", "yaml"))
_YAML_KEY = re.compile(r"^(?P<indent>[ ]*)(?P<name>[A-Za-z_][\w.-]*):\s*(?:#.*)?$|"
                       r"^(?P<indent2>[ ]*)(?P<name2>[A-Za-z_][\w.-]*):\s+\S")
_DECORATOR = re.compile(r"^\s*@")


def _extension(path):
    base = path.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    return base[dot + 1:].lower() if dot > 0 else ""


def _indent_of(line):
    return len(line) - len(line.lstrip(" \t"))


def _yaml_symbol(lines, line):
    """YAML/workflow symbol: `jobs.<id>` inside a job, otherwise the top-level key."""
    top, job, job_indent = "", "", None
    for raw in lines[:line]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = _YAML_KEY.match(raw)
        if not match:
            continue
        name = match.group("name") or match.group("name2")
        indent = len(match.group("indent") if match.group("indent") is not None
                     else match.group("indent2"))
        if indent == 0:
            top, job, job_indent = name, "", None
        elif top == "jobs":
            if job_indent is None:
                job_indent = indent
            if indent == job_indent:
                job = name
    if top == "jobs":
        return "jobs.%s" % job if job else "jobs"
    return top or TOP_LEVEL


def enclosing_symbol(text, line, path=""):
    """Resolve the symbol enclosing `line` (1-based) in `text`.

    Deliberately regex-only and per-language, in the spirit of git's funcname patterns:
    the nearest matching declaration above the line wins. For indentation-significant
    languages the match must also be less indented than the cited line, so a line in a
    method body resolves to the method and not to a later sibling.
    """
    lines = text.splitlines()
    if not lines:
        return TOP_LEVEL
    line = max(1, min(int(line or 1), len(lines)))
    ext = _extension(path)
    if ext in _YAML_EXTS:
        return _yaml_symbol(lines, line)
    rules = _LANG_RULES.get(ext)
    if rules is None:
        return TOP_LEVEL

    target = lines[line - 1]
    # A citation that lands on a decorator belongs to the function it decorates.
    if _DECORATOR.match(target):
        for ahead in lines[line - 1:line + 9]:
            for rule in rules:
                match = rule.match(ahead)
                if match and match.group("name") not in _KEYWORDS:
                    return match.group("name")

    indent_sensitive = ext in _INDENT_LANGS
    target_indent = _indent_of(target) if target.strip() else None
    for index in range(line - 1, -1, -1):
        candidate = lines[index]
        if not candidate.strip():
            continue
        for rule in rules:
            match = rule.match(candidate)
            if not match or match.group("name") in _KEYWORDS:
                continue
            if indent_sensitive and index != line - 1:
                if target_indent is not None and _indent_of(candidate) >= target_indent:
                    continue
            return match.group("name")
    return TOP_LEVEL


def for_sink(class_ref, sink_path, text, line, variant=1):
    """The single fingerprint entry point: resolve the symbol, then assemble.

    Hunters, seeders and the ledger all go through here so that two proposals about the
    same sink produce the same bytes.
    """
    return build(class_ref, sink_path, enclosing_symbol(text or "", line, sink_path),
                 variant=variant)


# ---------------------------------------------------------------------- rename map

class RenameMap:
    """old path -> new path, followed transitively, so a fingerprint survives a rename.

    Prior-run records were fingerprinted against the paths of that push. Before matching
    a prior fingerprint against this run's candidates, the parent rewrites its sink path
    through this map (design 8.3: "prior-run rename map applied before matching").
    """

    def __init__(self, pairs=()):
        self.forward = {}
        for old, new in pairs:
            if old and new and old != new:
                self.forward[old] = new
        self.backward = {new: old for old, new in self.forward.items()}

    def current(self, path):
        """Follow the rename chain forward. A cycle stops at the first repeat."""
        return self._follow(path, self.forward)

    def original(self, path):
        return self._follow(path, self.backward)

    @staticmethod
    def _follow(path, table):
        seen = {path}
        while path in table:
            path = table[path]
            if path in seen:
                break
            seen.add(path)
        return path

    def translate(self, fingerprint):
        """Rewrite a prior fingerprint's sink path into this run's path.

        Returns the fingerprint unchanged when the path did not move, or when it was
        hashed by esc() and therefore cannot be reversed.
        """
        parts = parse(fingerprint)
        if parts["path_hashed"] or parts["path"] is None:
            return fingerprint
        moved = self.current(parts["path"])
        if moved == parts["path"]:
            return fingerprint
        fp = "%s:%s:%s@%s" % (SCHEME, parts["token"], esc(moved),
                              parts["escaped_symbol"])
        if parts["variant"] > 1:
            fp += ":r%d" % parts["variant"]
        return fp


def rename_map(changed_files):
    """Build a RenameMap from changed-file records carrying `previous_path`."""
    pairs = []
    for entry in changed_files:
        old = entry.get("previous_path") or entry.get("previous_filename") or ""
        new = entry.get("path") or entry.get("filename") or ""
        if old and new:
            pairs.append((old, new))
    return RenameMap(pairs)
