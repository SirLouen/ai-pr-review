"""Hardened, read-only access to the git objects the review reasons about.

The PR tree is never checked out and never executed. Everything the agents can see
comes from a bare repository that this module fetches by SHA and then reads with a
fixed argv, an explicit environment and a per-call timeout and byte cap.

Two suppression channels shaped this file, both verified on git 2.43.0:

* `.gitattributes` in the PR tree. A single added line `*.ts -diff` makes `git grep -I`
  return *nothing* for matching files and makes `git diff` report them as binary, so the
  vulnerable hunk disappears from the reviewer's only search tool. `GIT_ATTR_NOSYSTEM`
  and `core.attributesFile=/dev/null` do not help; only `-c attr.tree=<empty tree>` does,
  and git ignores unknown `-c` keys in silence, so on git < 2.40 that flag is a no-op.
  Hence `assert_git_version()`: refuse to run rather than degrade. `diff_index()` carries
  an independent tripwire for the same channel that does not depend on any config key.
* Pathspec magic. `:(top,exclude)app.ts` from a model removes the interesting file from
  its own grep. `GIT_LITERAL_PATHSPECS=1` neutralises it -- but it also neutralises our
  own `:(glob)` prefix, so the two modes are mutually exclusive. Lookups are structural
  (in-memory tree index, then content by OID) and run under literal pathspecs; grep gets
  a charset-allowlisted glob and a parent-built pathspec instead. See `grep()`.

No model-supplied string ever reaches `open()`, a shell, or a pathspec unfiltered.
"""
import base64
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import Caps, EMPTY_TREE, MIN_GIT_VERSION

CALL_TIMEOUT_S = 20
CALL_MAX_BYTES = 4 * 1024 * 1024
INDEX_TIMEOUT_S = 120
INDEX_MAX_BYTES = 64 * 1024 * 1024
FETCH_TIMEOUT_S = 900
MAX_INDEX_ENTRIES = 200_000
MAX_PATH_BYTES = 4096
MAX_PATTERN_CHARS = 200
MAX_GLOB_CHARS = 200
SNIFF_BYTES = 8000                  # git's own binary heuristic looks this far for a NUL
SYMLINK_TARGET_BYTES = 4096
LFS_POINTER_MAGIC = b"version https://git-lfs.github.com/spec/v1"
MODE_SYMLINK = "120000"
MODE_SUBMODULE = "160000"
GIT_VERSION_RE = re.compile(r"^git version (\d+)\.(\d+)")
GLOB_RE = re.compile(r"^[A-Za-z0-9._/*?\[\]{}!-]+$")
HUNK_RE = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Applied to every single invocation, including `init`. attr.tree is the one that matters;
# the rest close hook, filter, protocol and fsmonitor execution paths in the PR's tree.
HARDENED_CONFIG = (
    "-c", "attr.tree=" + EMPTY_TREE,
    "-c", "core.attributesFile=/dev/null",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.allow=never",
    "-c", "credential.helper=",     # empty value resets the helper list, it does not add one
    "-c", "gc.auto=0",              # no background repack racing the run's reads
)
DIFF_FLAGS = ("--no-ext-diff", "--no-textconv", "--no-color")
# Downgraded because they are common in old history and are not a parser-safety signal;
# everything else stays fatal, which is the point of fsck-ing a fetched pack at all.
FSCK_LENIENT = ("badTimezone", "missingEmail", "badEmail", "zeroPaddedFilemode", "badTagName")


class GitError(Exception):
    """A git invocation failed, timed out, or blew a byte cap."""


class PathError(Exception):
    """A model-supplied path, glob or pattern was rejected before it reached git."""


class SizeGateError(Exception):
    """The PR, or the fetch it would require, exceeds a hard resource cap."""


@dataclass(frozen=True)
class GitRepo:
    """Handle for one bare repository under the run's scratch directory."""
    git_dir: str
    home: str
    git_binary: str
    caps: Caps


@dataclass(frozen=True)
class Result:
    code: int
    out: bytes
    err: bytes


# ---------------------------------------------------------------- process plumbing

def git_env(git_dir, home, literal_pathspecs=False, extra=None):
    """The complete environment of a git child process. Nothing is inherited.

    Building it from scratch (rather than copying os.environ) is what keeps model
    credentials and any other ambient secret out of every subprocess by construction.
    """
    path = "/usr/bin:/bin"
    env = {
        "PATH": path,
        "HOME": home,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    if git_dir:
        env["GIT_DIR"] = git_dir
    if literal_pathspecs:
        env["GIT_LITERAL_PATHSPECS"] = "1"
    if extra:
        env.update(extra)
    return env


def _redact(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def _kill(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _pump(stream, cap, sink, overflow):
    total = 0
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            total += len(chunk)
            if total > cap:
                overflow.append(True)
                return
            sink.append(chunk)
    except (ValueError, OSError):
        return
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _dir_bytes(path):
    total = 0
    stack = [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def _run(argv, env, timeout, max_bytes, watch=None, redact=()):
    """Run one process with no shell, a hard deadline, an output cap and an optional
    watchdog on the size of a directory it is filling (the fetch)."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, start_new_session=True)
    out, err, overflow, too_big = [], [], [], []
    threads = [threading.Thread(target=_pump, args=(proc.stdout, max_bytes, out, overflow)),
               threading.Thread(target=_pump, args=(proc.stderr, 256 * 1024, err, []))]
    stop = threading.Event()
    if watch:
        threads.append(threading.Thread(target=_watchdog, args=(watch, too_big, stop)))
    for thread in threads:
        thread.daemon = True
        thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while True:
            if overflow or too_big:
                _kill(proc)
                break
            if proc.poll() is not None and not any(t.is_alive() for t in threads[:2]):
                break
            if time.monotonic() > deadline:
                timed_out = True
                _kill(proc)
                break
            for thread in threads[:2]:
                thread.join(0.05)
    finally:
        stop.set()
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill(proc)
            code = -1
    where = _redact(" ".join(argv[-4:]), redact)
    if too_big:
        raise SizeGateError("git fetch exceeded %d bytes on disk and was killed" % watch[1])
    if timed_out:
        raise GitError("git timed out after %ds: %s" % (timeout, where))
    if overflow:
        raise GitError("git output exceeded %d bytes: %s" % (max_bytes, where))
    return Result(code, b"".join(out), b"".join(err))


def _watchdog(watch, too_big, stop):
    path, cap = watch
    while not stop.wait(0.25):
        if _dir_bytes(path) > cap:
            too_big.append(True)
            return


def run_git(repo, args, timeout=CALL_TIMEOUT_S, max_bytes=CALL_MAX_BYTES, literal=False,
            config=(), env_extra=None, allow_fail=False, redact=()):
    """Run git in `repo` with the hardened config and environment. Fixed argv, never a shell."""
    argv = [repo.git_binary] + list(HARDENED_CONFIG) + list(config) + list(args)
    env = git_env(repo.git_dir, repo.home, literal_pathspecs=literal, extra=env_extra)
    result = _run(argv, env, timeout, max_bytes, redact=redact)
    if result.code != 0 and not allow_fail:
        raise GitError("git %s failed (%d): %s"
                       % (_redact(" ".join(str(a) for a in args[:3]), redact), result.code,
                          _redact(result.err.decode("utf-8", "replace").strip()[:400], redact)))
    return result


# ---------------------------------------------------------------- version + repo setup

def git_version(git_binary=None):
    binary = git_binary or shutil.which("git") or "git"
    result = _run([binary, "--version"], git_env(None, "/nonexistent"), CALL_TIMEOUT_S, 64 * 1024)
    match = GIT_VERSION_RE.match(result.out.decode("utf-8", "replace").strip())
    if result.code != 0 or not match:
        raise GitError("cannot determine git version from %r" % result.out[:120])
    return (int(match.group(1)), int(match.group(2)))


def assert_git_version(git_binary=None):
    """Refuse to run on a git too old for `attr.tree`.

    Unknown `-c` keys are accepted silently, so on git < 2.40 our single control against
    `.gitattributes`-driven suppression would be a no-op and every later check would pass
    while the reviewer was reading an attacker-filtered view of the tree.
    """
    version = git_version(git_binary)
    if version < MIN_GIT_VERSION:
        raise GitError(
            "git %d.%d is too old: attr.tree needs >= %d.%d and git ignores unknown -c keys "
            "silently, so .gitattributes could suppress files from the review"
            % (version[0], version[1], MIN_GIT_VERSION[0], MIN_GIT_VERSION[1]))
    return version


def open_repo(scratch_dir, caps=None, git_binary=None):
    """Create (or reopen) the bare repo and the private HOME under the run's scratch dir."""
    scratch = os.path.abspath(scratch_dir)
    git_dir = os.path.join(scratch, "repo.git")
    home = os.path.join(scratch, "home")
    os.makedirs(home, mode=0o700, exist_ok=True)
    binary = git_binary or shutil.which("git") or "git"
    assert_git_version(binary)
    repo = GitRepo(git_dir=git_dir, home=home, git_binary=binary, caps=caps or Caps())
    if not os.path.isdir(os.path.join(git_dir, "objects")):
        argv = ([binary] + list(HARDENED_CONFIG) + ["-c", "init.defaultBranch=main",
                                                    "init", "--bare", "--quiet", git_dir])
        # GIT_DIR must be absent here or it, not the argument, decides where the repo lands.
        result = _run(argv, git_env(None, home), CALL_TIMEOUT_S, CALL_MAX_BYTES)
        if result.code != 0:
            raise GitError("git init --bare failed: %s"
                           % result.err.decode("utf-8", "replace").strip()[:400])
    return repo


# ---------------------------------------------------------------- size gate + fetch

def check_pr_size(caps, changed_files, additions, deletions, changed_bytes=0):
    """Refuse an oversized PR *before* anything is fetched.

    The numbers come from the compare API, so the runner never downloads the pack it is
    about to refuse; a fork can otherwise burn the whole job on every push for free.
    """
    lines = int(additions) + int(deletions)
    if int(changed_files) > caps.max_changed_files:
        raise SizeGateError("PR changes %d files, over the %d-file cap"
                            % (int(changed_files), caps.max_changed_files))
    if lines > caps.max_diff_lines:
        raise SizeGateError("PR changes %d diff lines, over the %d-line cap"
                            % (lines, caps.max_diff_lines))
    if changed_bytes and int(changed_bytes) > caps.max_fetch_bytes:
        raise SizeGateError("PR changes %d bytes, over the %d-byte cap"
                            % (int(changed_bytes), caps.max_fetch_bytes))
    return {"changed_files": int(changed_files), "diff_lines": lines}


def _auth_env(remote_url, token):
    """Pass the token to exactly one subprocess, as config in its environment.

    Never argv (visible in /proc), never `git config` (persisted in .git/config where a
    later tool call could read it back).
    """
    if not token:
        return {}
    parts = urlsplit(remote_url)
    if parts.scheme != "https" or not parts.netloc:
        raise GitError("refusing to send a token to a non-https remote")
    header = base64.b64encode(("x-access-token:%s" % token).encode("utf-8")).decode("ascii")
    return {"GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://%s/.extraheader" % parts.netloc,
            "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic %s" % header}


def fetch_commits(repo, remote_url, wants, token="", protocols=("https",), caps=None,
                  timeout=FETCH_TIMEOUT_S):
    """Fetch (sha, depth) pairs by SHA. No refspec, no tags, no submodules, no fetch head.

    The transfer itself is bounded: a watchdog kills the fetch if the object store grows
    past caps.max_fetch_bytes, because the size gate can only see the diff, not the pack.
    """
    caps = caps or repo.caps
    auth = _auth_env(remote_url, token)
    config = ["-c", "transfer.fsckObjects=true"]
    for msg_id in FSCK_LENIENT:
        config += ["-c", "fetch.fsck.%s=warn" % msg_id]
    for protocol in protocols:
        config += ["-c", "protocol.%s.allow=always" % protocol]
    if _dir_bytes(repo.git_dir) > caps.max_fetch_bytes:
        raise SizeGateError("object store already over the %d-byte cap" % caps.max_fetch_bytes)
    for sha, depth in wants:
        require_sha(sha)
        args = ["fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
                "--no-write-fetch-head", "--depth=%d" % int(depth), remote_url, sha]
        argv = [repo.git_binary] + list(HARDENED_CONFIG) + config + args
        env = git_env(repo.git_dir, repo.home, extra=auth)
        result = _run(argv, env, timeout, CALL_MAX_BYTES,
                      watch=(repo.git_dir, caps.max_fetch_bytes), redact=(token,))
        if result.code != 0:
            raise GitError("git fetch %s failed (%d): %s"
                           % (sha[:12], result.code,
                              _redact(result.err.decode("utf-8", "replace").strip()[:400],
                                      (token,))))
        # The watchdog only samples every 250ms, so a fast fetch is checked here as well.
        size = _dir_bytes(repo.git_dir)
        if size > caps.max_fetch_bytes:
            raise SizeGateError("fetched objects reached %d bytes, over the %d-byte cap"
                                % (size, caps.max_fetch_bytes))
    return {"bytes": _dir_bytes(repo.git_dir), "shas": [sha for sha, _ in wants]}


def fetch_pr(repo, remote_url, head_sha, merge_base_sha, commit_count, token="",
             extra=(), protocols=("https",), caps=None):
    """Fetch head and merge-base by SHA, deep enough for the PR's own commits."""
    depth = max(2, min(int(commit_count) + 1, 251))
    wants = {head_sha: depth, merge_base_sha: 1}
    for sha, sha_depth in extra:
        wants[sha] = max(wants.get(sha, 0), int(sha_depth))
    stats = fetch_commits(repo, remote_url, sorted(wants.items()), token=token,
                          protocols=protocols, caps=caps)
    for sha in (head_sha, merge_base_sha):
        if not object_exists(repo, sha):
            # A force-push between the event and the fetch must fail the run loudly,
            # never silently review a different tree.
            raise GitError("commit %s is missing after fetch (force-push during the run?)"
                           % sha[:12])
    stats["depth"] = depth
    return stats


# ---------------------------------------------------------------- object helpers

def require_sha(sha):
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GitError("not a full object name: %r" % (sha if isinstance(sha, str) else type(sha)))
    return sha


def object_exists(repo, sha, kind="commit"):
    require_sha(sha)
    result = run_git(repo, ["cat-file", "-e", "%s^{%s}" % (sha, kind)], allow_fail=True)
    return result.code == 0


def commit_parents(repo, sha):
    """Parents recorded in the commit object, present in the repo or not.

    A shallow boundary commit still names its parent here while the parent object is
    absent; `git diff-tree -p` on such a commit prints nothing and exits 0, which would
    read as "this commit changed nothing".
    """
    require_sha(sha)
    body = run_git(repo, ["cat-file", "commit", sha]).out.decode("utf-8", "replace")
    parents = []
    for line in body.split("\n"):
        if line.startswith("parent "):
            parents.append(line[7:].strip())
        elif not line.strip():
            break
    return parents


def commits_between(repo, merge_base, head, limit=250):
    """The PR's own commits, oldest first."""
    require_sha(merge_base)
    require_sha(head)
    args = ["rev-list", "--reverse", "--max-count=%d" % (int(limit) + 1),
            "%s..%s" % (merge_base, head)]
    out = run_git(repo, args).out.decode("ascii", "replace").split()
    return {"commits": out[:limit], "truncated": len(out) > limit}


# ---------------------------------------------------------------- path confinement

def normalize_path(raw):
    """Validate a model-supplied path. Structural checks only; no filesystem is touched."""
    if not isinstance(raw, str) or not raw:
        raise PathError("path must be a non-empty string")
    path = unicodedata.normalize("NFC", raw)
    if len(path.encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES:
        raise PathError("path is longer than %d bytes" % MAX_PATH_BYTES)
    if path[0] in (":", "-"):
        raise PathError("path may not start with %r (pathspec magic or an option)" % path[0])
    if path.startswith("/") or path.startswith("~"):
        raise PathError("path must be relative to the repository root")
    if "\\" in path:
        raise PathError("path may not contain a backslash")
    for char in path:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise PathError("path may not contain control characters")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PathError("path may not contain empty, '.' or '..' components")
    return path


def normalize_glob(raw):
    """Validate a model-supplied glob. The charset is the control: it excludes ':' and '(',
    so pathspec magic such as ':(top,exclude)x' cannot be expressed at all."""
    if not isinstance(raw, str) or not raw:
        raise PathError("path_glob must be a non-empty string")
    glob = unicodedata.normalize("NFC", raw)
    if len(glob) > MAX_GLOB_CHARS:
        raise PathError("path_glob is longer than %d characters" % MAX_GLOB_CHARS)
    if not GLOB_RE.match(glob):
        raise PathError("path_glob may only contain [A-Za-z0-9._/*?[]{}!-]; "
                        "pathspec magic is not accepted")
    if glob.startswith("/") or ".." in glob.split("/"):
        raise PathError("path_glob must be relative and may not contain '..'")
    return glob


def _glob_regex(glob):
    """Compile a glob with git's `:(glob)` semantics: '*' and '?' do not cross '/'."""
    out, i = [], 0
    while i < len(glob):
        char = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            end = glob.find("]", i + 1)
            if end == -1:
                out.append(re.escape(char))
                i += 1
            else:
                body = glob[i + 1:end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end + 1
        else:
            out.append(re.escape(char))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_paths(index, glob, limit=None):
    """Paths in the tree index matching an already-validated glob."""
    pattern = _glob_regex(glob)
    hits = [path for path in index if pattern.match(path)]
    hits.sort()
    return hits if limit is None else hits[:limit]


# ---------------------------------------------------------------- tree index + reads

def tree_index(repo, ref_sha):
    """path -> {mode, type, oid, size} for every blob, symlink and gitlink in a commit."""
    require_sha(ref_sha)
    out = run_git(repo, ["ls-tree", "-r", "-z", "-l", ref_sha],
                  timeout=INDEX_TIMEOUT_S, max_bytes=INDEX_MAX_BYTES).out
    index = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        fields = meta.split()
        if len(fields) != 4:
            raise GitError("unparsable ls-tree record: %r" % record[:120])
        mode, obj_type, oid, size = (f.decode("ascii", "replace") for f in fields)
        index[os.fsdecode(raw_path)] = {
            "path": os.fsdecode(raw_path),
            "mode": mode,
            "type": "submodule" if mode == MODE_SUBMODULE else
                    ("symlink" if mode == MODE_SYMLINK else "file"),
            "oid": oid,
            "size": -1 if size == "-" else int(size),
        }
        if len(index) > MAX_INDEX_ENTRIES:
            raise GitError("tree has more than %d entries" % MAX_INDEX_ENTRIES)
    return index


def resolve_path(index, raw_path):
    """Look a model-supplied path up in the tree index. This is the only path resolution
    there is: the result is an OID, and content is fetched by OID."""
    path = normalize_path(raw_path)
    entry = index.get(path)
    if entry is None:
        raise PathError("no such path in this ref: %s" % path)
    return entry


def list_dir(index, raw_path="", recursive=False, caps=None):
    """Directory listing computed from the tree index, not from a pathspec."""
    caps = caps or Caps()
    if raw_path in ("", ".", "/"):
        prefix = ""
    else:
        prefix = normalize_path(raw_path).rstrip("/") + "/"
    seen, entries = set(), []
    for path, entry in index.items():
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):]
        if not rest:
            continue
        if recursive or "/" not in rest:
            if rest in seen:
                continue
            seen.add(rest)
            entries.append({"name": rest, "path": path, "type": entry["type"],
                            "size": entry["size"], "oid": entry["oid"]})
        else:
            name = rest.split("/", 1)[0]
            if name in seen:
                continue
            seen.add(name)
            entries.append({"name": name, "path": prefix + name, "type": "dir",
                            "size": -1, "oid": ""})
    if prefix and not entries:
        raise PathError("no such directory in this ref: %s" % prefix.rstrip("/"))
    entries.sort(key=lambda e: e["name"])
    limit = caps.tree_entries
    return {"entries": entries[:limit], "truncated": len(entries) > limit,
            "total": len(entries)}


def read_blob(repo, oid, max_bytes):
    """Read a blob by OID. `max_bytes` is a hard cap; overrunning it is an error, never
    a silent truncation."""
    require_sha(oid)
    return run_git(repo, ["cat-file", "blob", oid], max_bytes=max_bytes).out


def read_entry(repo, entry, caps=None):
    """Classify and read one tree entry. Symlinks yield their target text and are never
    dereferenced; submodules and LFS pointers are reported, not followed."""
    caps = caps or repo.caps
    path = entry["path"]
    if entry["mode"] == MODE_SUBMODULE:
        return {"kind": "submodule", "path": path, "commit": entry["oid"],
                "note": "submodule not fetched"}
    if entry["mode"] == MODE_SYMLINK:
        target = read_blob(repo, entry["oid"], SYMLINK_TARGET_BYTES + 1)
        return {"kind": "symlink", "path": path, "oid": entry["oid"],
                "size": entry["size"],
                "target": target[:SYMLINK_TARGET_BYTES].decode("utf-8", "replace"),
                "note": "symlink target is reported as text and never followed"}
    if entry["size"] > caps.blob_bytes:
        return {"kind": "oversize", "path": path, "oid": entry["oid"],
                "size": entry["size"], "limit": caps.blob_bytes}
    data = read_blob(repo, entry["oid"], caps.blob_bytes + 1)
    if data.startswith(LFS_POINTER_MAGIC):
        return {"kind": "lfs", "path": path, "oid": entry["oid"], "size": entry["size"],
                "pointer": data[:1024].decode("utf-8", "replace"),
                "note": "git-lfs object not fetched"}
    if is_binary(data):
        return {"kind": "binary", "path": path, "oid": entry["oid"], "size": entry["size"]}
    return {"kind": "text", "path": path, "oid": entry["oid"], "size": entry["size"],
            "data": data, "text": data.decode("utf-8", "replace")}


def read_path(repo, index, raw_path, caps=None):
    return read_entry(repo, resolve_path(index, raw_path), caps=caps)


def is_binary(data):
    return b"\x00" in data[:SNIFF_BYTES]


# ---------------------------------------------------------------- grep

def grep(repo, ref_sha, pattern, index, path_glob=None, fixed_string=True,
         ignore_case=False, caps=None):
    """Search a tree with `git grep`. `index` must be the tree index of `ref_sha`.

    Unlike ripgrep, `git grep <tree-ish>` searches dot-directories, so `.github/workflows/**`
    is reachable, and it ignores `.ignore`/`.rgignore` files in the PR tree.

    NOTE, do not "fix" this: GIT_LITERAL_PATHSPECS=1 and our own `:(glob)` prefix are
    mutually exclusive -- under literal pathspecs the prefix is taken literally and the
    grep matches nothing at all, which reads to a model as "clean". Grep therefore runs
    without literal pathspecs and the control is the charset allowlist in normalize_glob()
    plus the index pre-check below, which turns "your glob matches nothing" into an
    explicit error instead of an empty result set.
    """
    caps = caps or repo.caps
    require_sha(ref_sha)
    if not isinstance(pattern, str) or not pattern:
        raise PathError("pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise PathError("pattern is longer than %d characters" % MAX_PATTERN_CHARS)
    if "\x00" in pattern or "\n" in pattern:
        raise PathError("pattern may not contain NUL or newline")
    # --no-recurse-submodules is valid here but not on diff/ls-tree, so it is not part of
    # the global flag set; nothing is fetched for a submodule anyway.
    args = ["grep", "-n", "-I", "--no-color", "--no-textconv", "--no-recurse-submodules",
            "-z", "-F" if fixed_string else "-E"]
    if ignore_case:
        args.append("-i")
    args += ["-e", pattern, ref_sha]
    if path_glob is not None:
        glob = normalize_glob(path_glob)
        if not glob_paths(index, glob, limit=1):
            raise PathError("path_glob %s matches no file in this ref" % glob)
        args += ["--", ":(glob)" + glob]
    result = run_git(repo, args, allow_fail=True)
    if result.code == 1:
        return {"hits": [], "truncated": False, "matched_files": 0}
    if result.code != 0:
        raise GitError("git grep failed (%d): %s"
                       % (result.code, result.err.decode("utf-8", "replace").strip()[:300]))
    return _parse_grep(result.out, ref_sha + ":", caps)


def _parse_grep(out, prefix, caps):
    """`git grep -z -n` emits <name>NUL<lineno>NUL<text>LF per hit."""
    hits, pos, used, truncated = [], 0, 0, False
    prefix_bytes = prefix.encode("ascii")
    files = set()
    while pos < len(out):
        end = out.find(b"\0", pos)
        if end == -1:
            break
        name = out[pos:end]
        pos = end + 1
        end = out.find(b"\0", pos)
        if end == -1:
            break
        lineno = out[pos:end]
        pos = end + 1
        end = out.find(b"\n", pos)
        if end == -1:
            end = len(out)
        text = out[pos:end]
        pos = end + 1
        if name.startswith(prefix_bytes):
            name = name[len(prefix_bytes):]
        path = os.fsdecode(name)
        files.add(path)
        if len(hits) >= caps.grep_hits or used >= caps.grep_bytes:
            truncated = True
            break
        line = text[:500].decode("utf-8", "replace")
        used += len(line)
        hits.append({"path": path, "line": int(lineno or 0), "text": line})
    return {"hits": hits, "truncated": truncated, "matched_files": len(files)}


# ---------------------------------------------------------------- diff index

def diff_index(repo, merge_base, head, caps=None, with_hunks=True):
    """Status, counts, binary flag and hunk ranges for merge_base..head.

    Hunks carry both old and new line numbers: the publish job anchors inline comments by
    new-side line, and deciding whether a cited line was introduced by this PR needs the
    old side too.
    """
    caps = caps or repo.caps
    require_sha(merge_base)
    require_sha(head)
    raw = run_git(repo, ["diff"] + list(DIFF_FLAGS) + ["-M", "--raw", "-z", "--abbrev=40",
                                                       merge_base, head],
                  timeout=INDEX_TIMEOUT_S, max_bytes=INDEX_MAX_BYTES).out
    counts = _numstat(run_git(repo, ["diff"] + list(DIFF_FLAGS) + ["-M", "--numstat", "-z",
                                                                  merge_base, head],
                              timeout=INDEX_TIMEOUT_S, max_bytes=INDEX_MAX_BYTES).out)
    files = []
    tokens = raw.split(b"\0")
    i = 0
    while i < len(tokens):
        meta = tokens[i]
        if not meta:
            i += 1
            continue
        fields = meta.lstrip(b":").split()
        if len(fields) < 5 or i + 1 >= len(tokens):
            raise GitError("unparsable diff --raw record: %r" % meta[:120])
        status = fields[4].decode("ascii", "replace")
        path = os.fsdecode(tokens[i + 1])
        i += 2
        old_path = None
        if status[0] in ("R", "C"):
            if i >= len(tokens):
                raise GitError("truncated rename record in diff --raw")
            old_path, path = path, os.fsdecode(tokens[i])
            i += 1
        count = counts.get(path, {"added": 0, "removed": 0, "binary": False})
        files.append({
            "path": path,
            "old_path": old_path,
            "status": status[0],
            "similarity": int(status[1:]) if status[1:].isdigit() else None,
            "old_mode": fields[0].decode("ascii", "replace"),
            "new_mode": fields[1].decode("ascii", "replace"),
            "old_oid": fields[2].decode("ascii", "replace"),
            "new_oid": fields[3].decode("ascii", "replace"),
            "added": count["added"],
            "removed": count["removed"],
            "binary": count["binary"],
            "suspected_suppression": False,
            "hunks": [],
            "hunks_omitted": False,
        })
    for entry in files:
        if entry["binary"]:
            entry["suspected_suppression"] = _looks_suppressed(repo, entry, caps)
    if with_hunks:
        for entry in files[:caps.max_changed_files]:
            if not entry["binary"]:
                entry["hunks"] = file_hunks(repo, merge_base, head, entry["path"],
                                            entry["old_path"])
        for entry in files[caps.max_changed_files:]:
            entry["hunks_omitted"] = True
    totals = {"files": len(files),
              "added": sum(f["added"] for f in files),
              "removed": sum(f["removed"] for f in files),
              "binary": sum(1 for f in files if f["binary"])}
    return {"files": files, "totals": totals,
            "suspected_suppression": [f["path"] for f in files if f["suspected_suppression"]]}


def _numstat(out):
    """`--numstat -z` emits <add>TAB<del>TAB<path>NUL, or <add>TAB<del>TAB NUL<old>NUL<new>NUL
    for a rename. '-' for the counts means git treated the file as binary."""
    counts = {}
    tokens = out.split(b"\0")
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if not token:
            i += 1
            continue
        parts = token.split(b"\t", 2)
        if len(parts) != 3:
            raise GitError("unparsable numstat record: %r" % token[:120])
        added, removed, path = parts
        i += 1
        if path == b"":
            if i + 1 >= len(tokens):
                raise GitError("truncated rename record in numstat")
            path = tokens[i + 1]
            i += 2
        binary = added == b"-" or removed == b"-"
        counts[os.fsdecode(path)] = {
            "added": 0 if binary else int(added),
            "removed": 0 if binary else int(removed),
            "binary": binary,
        }
    return counts


def _looks_suppressed(repo, entry, caps):
    """Tripwire independent of attr.tree: git calls this file binary, but its bytes are
    text. The remaining explanation is a `-diff` attribute from the PR's own tree."""
    oid = entry["new_oid"] if set(entry["new_oid"]) != {"0"} else entry["old_oid"]
    if set(oid) == {"0"}:
        return False
    try:
        head = read_blob(repo, oid, SNIFF_BYTES + 1)
    except GitError:
        return False
    return len(head) > 0 and not is_binary(head)


def file_hunks(repo, merge_base, head, path, old_path=None, context=0):
    """Hunk ranges for one path, both sides.

    The diff is taken per path under literal pathspecs instead of parsing paths out of a
    combined patch: `diff --git` headers quote and escape attacker-chosen filenames, so
    attribution by header text is spoofable. Here the path we asked for is the answer.
    """
    specs = [p for p in (old_path, path) if p]
    for spec in specs:
        normalize_path(spec)
    args = (["diff"] + list(DIFF_FLAGS) + ["-M", "--unified=%d" % int(context),
                                           merge_base, head, "--"] + specs)
    out = run_git(repo, args, literal=True, timeout=INDEX_TIMEOUT_S).out
    hunks = []
    for line in out.split(b"\n"):
        match = HUNK_RE.match(line)
        if not match:
            continue
        old_start, old_lines, new_start, new_lines = match.groups()
        hunks.append({"old_start": int(old_start),
                      "old_lines": 1 if old_lines is None else int(old_lines),
                      "new_start": int(new_start),
                      "new_lines": 1 if new_lines is None else int(new_lines)})
    return hunks


def diff_text(repo, merge_base, head, path, old_path=None, context=3, max_bytes=None):
    """Unified diff for one path, for the model-facing get_diff tool."""
    specs = [p for p in (old_path, path) if p]
    for spec in specs:
        normalize_path(spec)
    context = max(0, min(int(context), 10))
    args = (["diff"] + list(DIFF_FLAGS) + ["-M", "--unified=%d" % context,
                                           merge_base, head, "--"] + specs)
    cap = max_bytes or CALL_MAX_BYTES
    out = run_git(repo, args, literal=True, timeout=INDEX_TIMEOUT_S, max_bytes=cap + 1).out
    return {"path": path, "old_path": old_path, "context": context,
            "text": out[:cap].decode("utf-8", "replace"), "truncated": len(out) > cap}


def commit_patch(repo, sha, path=None, max_bytes=None):
    """Patch for one of the PR's own commits, against its first parent.

    The per-commit view is what lets a secret added in one commit and removed in a later
    one be seen at all: it is invisible in merge_base..head but still in pushed history.
    """
    require_sha(sha)
    parents = commit_parents(repo, sha)
    args = ["diff-tree", "-p", "--no-commit-id"] + list(DIFF_FLAGS) + ["-M"]
    parent = parents[0] if parents else None
    if parent is None:
        args += ["--root", sha]
    elif not object_exists(repo, parent):
        # Without this check `git diff-tree -p` prints nothing and exits 0 at the shallow
        # boundary, which would look like "this commit changed nothing".
        return {"available": False, "reason": "shallow_boundary", "sha": sha,
                "parent": parent, "text": "", "truncated": False}
    else:
        args += [parent, sha]
    if path is not None:
        args += ["--", normalize_path(path)]
    cap = max_bytes or CALL_MAX_BYTES
    out = run_git(repo, args, literal=True, timeout=INDEX_TIMEOUT_S, max_bytes=cap + 1).out
    return {"available": True, "sha": sha, "parent": parent,
            "text": out[:cap].decode("utf-8", "replace"), "truncated": len(out) > cap}
