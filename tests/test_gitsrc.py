"""Tests for the hardened git layer.

Every hardening assertion here is made in both directions: the attack reproduces with the
control removed, and does not with it in place. A one-sided assertion would pass just as
well against a git layer that does nothing, which is exactly how the `.gitattributes`
fixture in the design would have passed vacuously (an unborn HEAD masks the bug).

All scratch repositories live under $TMPDIR, never in the project tree.
"""
import base64
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import gitsrc as g
from prreview.security.config import Caps, EMPTY_TREE, MIN_GIT_VERSION

VULN_LINE = 'db.query("SELECT * FROM t WHERE id=" + id); // VULNERABLE_MARK'
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# A clean environment for building fixtures, so a developer's global git config
# (autocrlf, a global attributes file, diff.noprefix) cannot change the outcome.
FIXTURE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "1700000000 +0000",
    "GIT_COMMITTER_DATE": "1700000000 +0000",
}


def git(cwd, *args, check=True):
    proc = subprocess.run(["git"] + list(args), cwd=cwd, env=FIXTURE_ENV,
                          capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise AssertionError("git %s failed: %s" % (" ".join(args), proc.stderr))
    return proc


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def add_gitlink(root, path, sha):
    """Stage a submodule entry whose commit object is absent, which is what a submodule
    looks like to a reviewer that never fetches one."""
    git(root, "update-index", "--add", "--cacheinfo", "160000,%s,%s" % (sha, path))


def commit(root, message, gitlinks=()):
    git(root, "add", "-A")
    for path, sha in gitlinks:
        # After `add -A`, which stages the deletion of any path missing from the worktree.
        add_gitlink(root, path, sha)
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD").stdout.strip()


def build_source(root):
    """A PR-shaped fixture: base commit, then a head commit that adds the vulnerable line,
    a suppressing .gitattributes, a rename, a deletion and an addition."""
    os.makedirs(root, exist_ok=True)
    git(root, "init", "-q", "-b", "main", ".")
    write(root, "app.ts", 'const id = req.query.id;\n')
    write(root, "keep.ts", "export const keep = 1;\n")
    write(root, "old_name.txt", "unchanged content\n")
    write(root, "doomed.txt", "this line goes away\nrequireAuth(handler);\n")
    write(root, ".github/workflows/w.yml", "on: pull_request_target\njobs:\n  x:\n"
                                           "    steps:\n      - run: echo DOTDIRMARKER\n")
    write(root, "src/secret.txt", "inside a directory\n")
    write(root, "big.lfs", "version https://git-lfs.github.com/spec/v1\n"
                           "oid sha256:aaaa\nsize 12\n")
    with open(os.path.join(root, "bin.dat"), "wb") as handle:
        handle.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00" * 40)
    os.symlink("/proc/self/environ", os.path.join(root, "envlink"))
    os.symlink("src", os.path.join(root, "dirlink"))
    base = commit(root, "base", gitlinks=[("sub", "1" * 40)])

    write(root, "app.ts", "const id = req.query.id;\n%s\n" % VULN_LINE)
    write(root, ".gitattributes", "*.ts -diff\napp.ts export-ignore\n")
    write(root, "added.txt", "brand new\n")
    os.rename(os.path.join(root, "old_name.txt"), os.path.join(root, "new_name.txt"))
    os.remove(os.path.join(root, "doomed.txt"))
    with open(os.path.join(root, "bin.dat"), "wb") as handle:
        handle.write(b"\x89PNG\r\n\x1a\n\x00\x00\x01" * 40)
    head = commit(root, "head", gitlinks=[("sub", "1" * 40)])
    return {"base": base, "head": head}


def open_bare(scratch, source, head, base, depth=5, born=True, caps=None):
    """Fetch by SHA into a bare repo, then create a ref.

    Creating the ref is not cosmetic: `git init --bare` + fetch-by-SHA leaves HEAD unborn,
    and an unborn HEAD masks .gitattributes suppression entirely (see TestAttrTree).
    """
    repo = g.open_repo(scratch, caps=caps)
    g.fetch_pr(repo, source, head, base, depth, protocols=("file",))
    if born:
        g.run_git(repo, ["update-ref", "refs/heads/main", head])
    return repo


def control_grep(repo, sha, term, attr_tree=True):
    """git grep built here rather than through gitsrc, so a test can remove exactly one
    control and observe the difference."""
    argv = [repo.git_binary, "-c", "core.attributesFile=/dev/null",
            "-c", "core.hooksPath=/dev/null"]
    if attr_tree:
        argv += ["-c", "attr.tree=" + EMPTY_TREE]
    argv += ["grep", "-n", "-I", "--no-color", "-F", "-e", term, sha]
    return subprocess.run(argv, env=g.git_env(repo.git_dir, repo.home),
                          capture_output=True, text=True)


def without_attr_tree(config):
    """The hardened config minus attr.tree: what git < 2.40 effectively runs, since it
    accepts unknown -c keys in silence."""
    out, i = [], 0
    while i < len(config):
        if config[i] == "-c" and config[i + 1].startswith("attr.tree="):
            i += 2
            continue
        out.append(config[i])
        i += 1
    return tuple(out)


def fake_git(path, body):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


class GitFixture(unittest.TestCase):
    """One source repo and one bare mirror of it, shared by the read-only tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sa-gitsrc-")
        cls.source = os.path.join(cls.tmp, "source")
        cls.shas = build_source(cls.source)
        cls.repo = open_bare(os.path.join(cls.tmp, "work"), cls.source,
                             cls.shas["head"], cls.shas["base"])
        cls.index = g.tree_index(cls.repo, cls.shas["head"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)


class TestVersionGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sa-ver-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _fake(self, version):
        return fake_git(os.path.join(self.tmp, "git-%s" % version),
                        'echo "git version %s"\n' % version)

    def test_real_git_is_recent_enough(self):
        self.assertGreaterEqual(g.assert_git_version(), MIN_GIT_VERSION)

    def test_old_git_is_refused_and_new_git_is_not(self):
        # Both directions: the gate must fire below the minimum and stay quiet above it,
        # otherwise it proves nothing about the version it was handed.
        with self.assertRaises(g.GitError) as caught:
            g.assert_git_version(self._fake("2.39.5"))
        self.assertIn("attr.tree", str(caught.exception))
        self.assertEqual(g.assert_git_version(self._fake("2.40.0")), (2, 40))

    def test_unparsable_version_is_an_error(self):
        with self.assertRaises(g.GitError):
            g.assert_git_version(fake_git(os.path.join(self.tmp, "git-x"), "echo hello\n"))


class TestChildEnvironment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sa-env-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dump = fake_git(os.path.join(self.tmp, "git"),
                             'for a in "$@"; do echo "ARGV:$a"; done\n'
                             '/usr/bin/env | sed "s/^/ENV:/"\n'
                             '{ for a in "$@"; do echo "ARGV:$a"; done\n'
                             '  /usr/bin/env | sed "s/^/ENV:/"; } >> "$HOME/dump"\n')
        home = os.path.join(self.tmp, "home")
        os.makedirs(home, exist_ok=True)
        self.repo = g.GitRepo(git_dir=os.path.join(self.tmp, "repo.git"), home=home,
                              git_binary=self.dump, caps=Caps())

    def _child_lines(self, prefix, **kwargs):
        out = g.run_git(self.repo, ["status"], **kwargs).out.decode()
        return [line[len(prefix):] for line in out.splitlines() if line.startswith(prefix)]

    def test_canary_env_var_never_reaches_a_child(self):
        os.environ["SA_CANARY_TOKEN"] = "canary-abc123"
        self.addCleanup(os.environ.pop, "SA_CANARY_TOKEN", None)
        env_lines = self._child_lines("ENV:")
        self.assertNotIn("SA_CANARY_TOKEN", "\n".join(env_lines))
        self.assertNotIn("canary-abc123", "\n".join(env_lines))
        # Non-vacuous: a child that inherits the environment does see the canary, so the
        # assertion above is about our env dict and not about the canary being unset.
        inherited = subprocess.run([self.dump, "status"], capture_output=True, text=True)
        self.assertIn("ENV:SA_CANARY_TOKEN=canary-abc123", inherited.stdout)

    def test_environment_is_exactly_the_allowlist(self):
        allowlist = {"PATH", "HOME", "LANG", "GIT_DIR", "GIT_CONFIG_NOSYSTEM",
                     "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
                     "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS"}
        self.assertEqual(set(g.git_env("/git/dir", "/home")), allowlist)
        # The child adds PWD/SHLVL/_ itself because the fake is a shell script; nothing
        # else may appear, and in particular nothing inherited from this process.
        names = {line.split("=", 1)[0] for line in self._child_lines("ENV:")}
        self.assertEqual(names - {"PWD", "SHLVL", "_"}, allowlist)

    def test_literal_pathspecs_only_when_asked(self):
        self.assertNotIn("GIT_LITERAL_PATHSPECS=1", self._child_lines("ENV:"))
        self.assertIn("GIT_LITERAL_PATHSPECS=1", self._child_lines("ENV:", literal=True))

    def test_hardening_flags_on_every_invocation(self):
        argv = self._child_lines("ARGV:")
        self.assertIn("attr.tree=" + EMPTY_TREE, argv)
        for flag in ("core.attributesFile=/dev/null", "core.hooksPath=/dev/null",
                     "core.fsmonitor=false", "protocol.allow=never"):
            self.assertIn(flag, argv)

    def test_token_travels_in_env_config_not_argv(self):
        env = g._auth_env("https://github.com/o/r", "ghs_supersecret")
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        self.assertNotIn("ghs_supersecret", env["GIT_CONFIG_VALUE_0"])
        self.assertTrue(env["GIT_CONFIG_VALUE_0"].startswith("AUTHORIZATION: basic "))

    def test_token_is_never_sent_to_a_non_https_remote(self):
        with self.assertRaises(g.GitError):
            g._auth_env("http://github.com/o/r", "ghs_supersecret")
        with self.assertRaises(g.GitError):
            g._auth_env("/local/path", "ghs_supersecret")
        self.assertEqual(g._auth_env("/local/path", ""), {})

    def test_fetch_keeps_the_token_out_of_argv(self):
        os.makedirs(self.repo.git_dir, exist_ok=True)
        g.fetch_commits(self.repo, "https://github.com/o/r", [("a" * 40, 2)],
                        token="ghs_supersecret")
        with open(os.path.join(self.repo.home, "dump"), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        argv = [line for line in lines if line.startswith("ARGV:")]
        env = [line for line in lines if line.startswith("ENV:")]
        self.assertTrue(argv)
        self.assertNotIn("ghs_supersecret", "\n".join(argv))
        # Non-vacuous: the credential really was handed to this subprocess, as a base64
        # header in GIT_CONFIG_VALUE_0 rather than on the command line.
        header = base64.b64encode(b"x-access-token:ghs_supersecret").decode()
        self.assertTrue(any(header in line for line in env))
        self.assertTrue(any(line.startswith("ENV:GIT_CONFIG_COUNT=1") for line in env))
        self.assertIn("ARGV:--no-write-fetch-head", argv)


class TestAttrTree(GitFixture):
    """The `.gitattributes` suppression channel, asserted in both directions."""

    def test_unborn_head_masks_the_bug_so_the_fixture_must_create_a_ref(self):
        scratch = os.path.join(self.tmp, "unborn")
        repo = open_bare(scratch, self.source, self.shas["head"], self.shas["base"],
                         born=False)
        self.assertEqual(g.run_git(repo, ["rev-parse", "--verify", "-q", "HEAD"],
                                   allow_fail=True).code, 1)
        masked = control_grep(repo, self.shas["head"], "VULNERABLE_MARK", attr_tree=False)
        self.assertIn("VULNERABLE_MARK", masked.stdout)   # suppression does NOT reproduce
        g.run_git(repo, ["update-ref", "refs/heads/main", self.shas["head"]])
        exposed = control_grep(repo, self.shas["head"], "VULNERABLE_MARK", attr_tree=False)
        self.assertEqual(exposed.returncode, 1)           # now it does
        self.assertEqual(exposed.stdout, "")

    def test_grep_without_attr_tree_is_silenced_and_with_it_is_not(self):
        without = control_grep(self.repo, self.shas["head"], "VULNERABLE_MARK",
                               attr_tree=False)
        self.assertEqual((without.returncode, without.stdout), (1, ""))
        with_flag = control_grep(self.repo, self.shas["head"], "VULNERABLE_MARK",
                                 attr_tree=True)
        self.assertIn("app.ts", with_flag.stdout)
        hits = g.grep(self.repo, self.shas["head"], "VULNERABLE_MARK", self.index)["hits"]
        self.assertEqual([h["path"] for h in hits], ["app.ts"])
        self.assertEqual(hits[0]["line"], 2)

    def test_diff_without_attr_tree_hides_the_hunk_and_trips_the_tripwire(self):
        with_flag = g.diff_index(self.repo, self.shas["base"], self.shas["head"])
        app = [f for f in with_flag["files"] if f["path"] == "app.ts"][0]
        self.assertFalse(app["binary"])
        self.assertEqual(app["added"], 1)
        self.assertTrue(app["hunks"])
        self.assertEqual(with_flag["suspected_suppression"], [])

        # Simulate attr.tree silently doing nothing (git < 2.40, an unknown -c key).
        original = g.HARDENED_CONFIG
        g.HARDENED_CONFIG = without_attr_tree(original)
        self.assertNotIn("attr.tree=" + EMPTY_TREE, g.HARDENED_CONFIG)
        try:
            degraded = g.diff_index(self.repo, self.shas["base"], self.shas["head"])
        finally:
            g.HARDENED_CONFIG = original
        app = [f for f in degraded["files"] if f["path"] == "app.ts"][0]
        self.assertTrue(app["binary"])          # the hunk is gone from the review
        self.assertEqual(app["hunks"], [])
        self.assertTrue(app["suspected_suppression"])
        self.assertIn("app.ts", degraded["suspected_suppression"])

    def test_a_real_binary_file_is_not_flagged_as_suppressed(self):
        diff = g.diff_index(self.repo, self.shas["base"], self.shas["head"])
        binary = [f for f in diff["files"] if f["path"] == "bin.dat"][0]
        self.assertTrue(binary["binary"])
        self.assertFalse(binary["suspected_suppression"])


class TestExportIgnore(GitFixture):
    def test_export_ignore_does_not_hide_a_file_from_us(self):
        self.assertIn("app.ts", self.index)
        self.assertIn("VULNERABLE_MARK",
                      g.read_path(self.repo, self.index, "app.ts")["text"])
        # Non-vacuous: `git archive` without attr.tree really does drop the file, which is
        # why content never comes from an archive. (With our config it would not, because
        # attr.tree neutralises export-ignore too.)
        argv = [self.repo.git_binary, "archive", "--format=tar", self.shas["head"]]
        naive = subprocess.run(argv, env=g.git_env(self.repo.git_dir, self.repo.home),
                               capture_output=True)
        with tarfile.open(fileobj=io.BytesIO(naive.stdout)) as archive:
            names = archive.getnames()
        self.assertNotIn("app.ts", names)
        self.assertIn("keep.ts", names)


class TestPathConfinement(GitFixture):
    def test_traversal_and_absolute_paths_are_rejected(self):
        for bad in ["../etc/passwd", "src/../../etc/passwd", "/etc/passwd", "~/.ssh/id_rsa",
                    "src/./x", "a//b", "", ".", ".."]:
            with self.assertRaises(g.PathError, msg=bad):
                g.normalize_path(bad)

    def test_control_characters_nul_and_overlong_paths_are_rejected(self):
        for bad in ["a\x00b", "a\nb", "a\tb", "a\x7fb", "a" * (g.MAX_PATH_BYTES + 1),
                    "dir\\file", ":(top)app.ts", "-oops"]:
            with self.assertRaises(g.PathError, msg=repr(bad)):
                g.normalize_path(bad)

    def test_ordinary_paths_survive_and_are_nfc_normalised(self):
        self.assertEqual(g.normalize_path("src/app.ts"), "src/app.ts")
        self.assertEqual(g.normalize_path("src/e\u0301.ts"), "src/\u00e9.ts")

    def test_unknown_path_is_an_explicit_error(self):
        with self.assertRaises(g.PathError):
            g.resolve_path(self.index, "no/such/file.ts")

    def test_symlink_returns_its_target_text_and_is_never_followed(self):
        entry = g.read_path(self.repo, self.index, "envlink")
        self.assertEqual(entry["kind"], "symlink")
        self.assertEqual(entry["target"], "/proc/self/environ")
        self.assertNotIn("PATH=", entry["target"])

    def test_paths_through_a_symlinked_directory_do_not_resolve(self):
        self.assertIn("src/secret.txt", self.index)
        self.assertNotIn("dirlink/secret.txt", self.index)
        with self.assertRaises(g.PathError):
            g.resolve_path(self.index, "dirlink/secret.txt")
        # git itself refuses <sha>:symlinkdir/file, so even a bug that built such a string
        # could not read through the link.
        probe = g.run_git(self.repo, ["cat-file", "blob",
                                      "%s:dirlink/secret.txt" % self.shas["head"]],
                          allow_fail=True)
        self.assertNotEqual(probe.code, 0)
        ok = g.run_git(self.repo, ["cat-file", "blob",
                                   "%s:src/secret.txt" % self.shas["head"]], allow_fail=True)
        self.assertEqual(ok.code, 0)


class TestEntryKinds(GitFixture):
    def test_submodule_is_reported_not_fetched(self):
        entry = g.read_path(self.repo, self.index, "sub")
        self.assertEqual(entry["kind"], "submodule")
        self.assertEqual(entry["commit"], "1" * 40)

    def test_binary_blob_is_refused_as_binary(self):
        self.assertEqual(g.read_path(self.repo, self.index, "bin.dat")["kind"], "binary")

    def test_oversize_blob_is_reported_without_being_read(self):
        caps = replace(Caps(), blob_bytes=8)
        entry = g.read_path(self.repo, self.index, "app.ts", caps=caps)
        self.assertEqual(entry["kind"], "oversize")
        self.assertEqual(entry["limit"], 8)
        self.assertNotIn("text", entry)
        self.assertEqual(g.read_path(self.repo, self.index, "app.ts")["kind"], "text")

    def test_lfs_pointer_is_reported_as_such(self):
        entry = g.read_path(self.repo, self.index, "big.lfs")
        self.assertEqual(entry["kind"], "lfs")
        self.assertIn("oid sha256:", entry["pointer"])

    def test_tree_index_records_mode_oid_and_size(self):
        self.assertEqual(self.index["envlink"]["mode"], g.MODE_SYMLINK)
        self.assertEqual(self.index["sub"]["mode"], g.MODE_SUBMODULE)
        self.assertEqual(self.index["sub"]["size"], -1)
        self.assertEqual(self.index["app.ts"]["mode"], "100644")
        self.assertEqual(self.index["app.ts"]["size"],
                         len(g.read_path(self.repo, self.index, "app.ts")["data"]))
        self.assertEqual(len(self.index["app.ts"]["oid"]), 40)

    def test_list_dir_is_computed_from_the_index(self):
        listing = g.list_dir(self.index, "")
        names = {e["name"]: e["type"] for e in listing["entries"]}
        self.assertEqual(names["src"], "dir")
        self.assertEqual(names["envlink"], "symlink")
        self.assertEqual(names["sub"], "submodule")
        self.assertEqual(names["app.ts"], "file")
        self.assertEqual([e["name"] for e in g.list_dir(self.index, "src")["entries"]],
                         ["secret.txt"])
        with self.assertRaises(g.PathError):
            g.list_dir(self.index, "nope")
        truncated = g.list_dir(self.index, "", caps=replace(Caps(), tree_entries=2))
        self.assertTrue(truncated["truncated"])
        self.assertEqual(len(truncated["entries"]), 2)


class TestGrep(GitFixture):
    def test_dot_directories_are_searched(self):
        hits = g.grep(self.repo, self.shas["head"], "DOTDIRMARKER", self.index)["hits"]
        self.assertEqual([h["path"] for h in hits], [".github/workflows/w.yml"])
        scoped = g.grep(self.repo, self.shas["head"], "DOTDIRMARKER", self.index,
                        path_glob=".github/workflows/*.yml")["hits"]
        self.assertEqual(len(scoped), 1)

    def test_pathspec_magic_is_rejected(self):
        for bad in [":(top,exclude)app.ts", ":(glob)*.ts", ":!app.ts", "../*",
                    "src/(x)", "a" * (g.MAX_GLOB_CHARS + 1)]:
            with self.assertRaises(g.PathError, msg=bad):
                g.grep(self.repo, self.shas["head"], "VULNERABLE_MARK", self.index,
                       path_glob=bad)

    def test_a_glob_matching_nothing_is_an_error_not_an_empty_result(self):
        with self.assertRaises(g.PathError):
            g.grep(self.repo, self.shas["head"], "VULNERABLE_MARK", self.index,
                   path_glob="nowhere/*.ts")
        # A glob that does match returns hits, so the error above is about the glob and
        # not about grep being broken.
        found = g.grep(self.repo, self.shas["head"], "VULNERABLE_MARK", self.index,
                       path_glob="*.ts")["hits"]
        self.assertEqual([h["path"] for h in found], ["app.ts"])

    def test_glob_wildcards_do_not_cross_directory_separators(self):
        self.assertEqual(g.glob_paths(self.index, "*.txt"), ["added.txt", "new_name.txt"])
        self.assertEqual(g.glob_paths(self.index, "src/*"), ["src/secret.txt"])
        self.assertEqual(g.glob_paths(self.index, "**/*.yml"), [".github/workflows/w.yml"])

    def test_regex_and_case_insensitive_modes(self):
        hits = g.grep(self.repo, self.shas["head"], "SELECT .*WHERE", self.index,
                      fixed_string=False)["hits"]
        self.assertEqual([h["path"] for h in hits], ["app.ts"])
        self.assertFalse(g.grep(self.repo, self.shas["head"], "vulnerable_mark",
                                self.index)["hits"])
        self.assertTrue(g.grep(self.repo, self.shas["head"], "vulnerable_mark", self.index,
                               ignore_case=True)["hits"])

    def test_hit_cap_is_reported_not_silently_applied(self):
        caps = replace(Caps(), grep_hits=1)
        result = g.grep(self.repo, self.shas["head"], "e", self.index, caps=caps)
        self.assertEqual(len(result["hits"]), 1)
        self.assertTrue(result["truncated"])

    def test_pattern_validation(self):
        for bad in ["", "x" * (g.MAX_PATTERN_CHARS + 1), "a\nb", "a\x00b", None]:
            with self.assertRaises(g.PathError, msg=repr(bad)):
                g.grep(self.repo, self.shas["head"], bad, self.index)


class TestDiffIndex(GitFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.diff = g.diff_index(cls.repo, cls.shas["base"], cls.shas["head"])
        cls.by_path = {f["path"]: f for f in cls.diff["files"]}

    def test_statuses_and_rename_old_path(self):
        self.assertEqual(self.by_path["added.txt"]["status"], "A")
        self.assertEqual(self.by_path["app.ts"]["status"], "M")
        self.assertEqual(self.by_path["doomed.txt"]["status"], "D")
        rename = self.by_path["new_name.txt"]
        self.assertEqual(rename["status"], "R")
        self.assertEqual(rename["old_path"], "old_name.txt")
        self.assertEqual(rename["similarity"], 100)
        self.assertNotIn("old_name.txt", self.by_path)

    def test_line_counts_and_totals(self):
        self.assertEqual((self.by_path["app.ts"]["added"],
                          self.by_path["app.ts"]["removed"]), (1, 0))
        self.assertEqual((self.by_path["doomed.txt"]["added"],
                          self.by_path["doomed.txt"]["removed"]), (0, 2))
        self.assertEqual(self.diff["totals"]["files"], len(self.diff["files"]))
        self.assertGreaterEqual(self.diff["totals"]["added"], 3)

    def test_hunks_carry_both_old_and_new_line_numbers(self):
        hunk = self.by_path["app.ts"]["hunks"][0]
        self.assertEqual((hunk["old_start"], hunk["old_lines"]), (1, 0))
        self.assertEqual((hunk["new_start"], hunk["new_lines"]), (2, 1))
        deleted = self.by_path["doomed.txt"]["hunks"][0]
        self.assertEqual((deleted["old_start"], deleted["old_lines"]), (1, 2))
        self.assertEqual(deleted["new_lines"], 0)

    def test_hunks_for_a_rename_use_both_paths(self):
        self.assertEqual(g.file_hunks(self.repo, self.shas["base"], self.shas["head"],
                                      "new_name.txt", "old_name.txt"), [])

    def test_diff_text_for_one_path(self):
        text = g.diff_text(self.repo, self.shas["base"], self.shas["head"], "app.ts")["text"]
        self.assertIn("VULNERABLE_MARK", text)
        self.assertNotIn("added.txt", text)

    def test_numstat_parses_renames_and_binary_rows(self):
        counts = g._numstat(b"3\t1\t\x00old.txt\x00new.txt\x00-\t-\timg.png\x00")
        self.assertEqual(counts["new.txt"], {"added": 3, "removed": 1, "binary": False})
        self.assertTrue(counts["img.png"]["binary"])
        self.assertNotIn("old.txt", counts)

    def test_hunks_are_omitted_loudly_past_the_file_cap(self):
        diff = g.diff_index(self.repo, self.shas["base"], self.shas["head"],
                            caps=replace(Caps(), max_changed_files=1))
        omitted = [f["path"] for f in diff["files"] if f["hunks_omitted"]]
        self.assertTrue(omitted)


class TestSizeGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sa-size-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_pr_size_gate_runs_without_a_repo(self):
        caps = Caps()
        self.assertEqual(g.check_pr_size(caps, 10, 100, 50)["diff_lines"], 150)
        with self.assertRaises(g.SizeGateError):
            g.check_pr_size(caps, caps.max_changed_files + 1, 1, 1)
        with self.assertRaises(g.SizeGateError):
            g.check_pr_size(caps, 1, caps.max_diff_lines, 1)
        with self.assertRaises(g.SizeGateError):
            g.check_pr_size(caps, 1, 1, 1, changed_bytes=caps.max_fetch_bytes + 1)

    def test_fetch_is_bounded_by_max_fetch_bytes(self):
        source = os.path.join(self.tmp, "source")
        shas = build_source(source)
        tight = replace(Caps(), max_fetch_bytes=1)
        repo = g.open_repo(os.path.join(self.tmp, "tight"), caps=tight)
        with self.assertRaises(g.SizeGateError):   # refused before the first object arrives
            g.fetch_pr(repo, source, shas["head"], shas["base"], 5, protocols=("file",))
        # And refused again once the objects push it over, not only up front.
        mid = g.open_repo(os.path.join(self.tmp, "mid"))
        caps = replace(Caps(), max_fetch_bytes=g._dir_bytes(mid.git_dir) + 1)
        with self.assertRaises(g.SizeGateError):
            g.fetch_pr(mid, source, shas["head"], shas["base"], 5, protocols=("file",),
                       caps=caps)
        # Non-vacuous: the same fetch succeeds under the default cap.
        roomy = g.open_repo(os.path.join(self.tmp, "roomy"))
        stats = g.fetch_pr(roomy, source, shas["head"], shas["base"], 5, protocols=("file",))
        self.assertGreater(stats["bytes"], 0)

    def test_watchdog_trips_on_a_growing_directory(self):
        watched = os.path.join(self.tmp, "watched")
        os.makedirs(watched)
        too_big, stop = [], threading.Event()
        thread = threading.Thread(target=g._watchdog, args=((watched, 64), too_big, stop))
        thread.start()
        with open(os.path.join(watched, "blob"), "wb") as handle:
            handle.write(b"x" * 4096)
        thread.join(timeout=5)
        stop.set()
        self.assertTrue(too_big)

    def test_protocols_are_denied_by_default(self):
        source = os.path.join(self.tmp, "source2")
        shas = build_source(source)
        repo = g.open_repo(os.path.join(self.tmp, "denied"))
        with self.assertRaises(g.GitError):
            g.fetch_pr(repo, source, shas["head"], shas["base"], 5)  # https only, file denied


class TestCommitHistory(unittest.TestCase):
    """The per-commit view a secret seeder needs: a secret added in one commit and removed
    in a later one is invisible in merge_base..head but present in pushed history."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sa-commits-")
        cls.source = os.path.join(cls.tmp, "source")
        os.makedirs(cls.source)
        git(cls.source, "init", "-q", "-b", "main", ".")
        write(cls.source, "config.py", "DEBUG = True\n")
        cls.base = commit(cls.source, "base")
        write(cls.source, "config.py", "DEBUG = True\nAWS_KEY = '%s'\n" % AWS_KEY)
        cls.added = commit(cls.source, "add key")
        write(cls.source, "config.py", "DEBUG = True\nAWS_KEY = os.environ['AWS_KEY']\n")
        cls.removed = commit(cls.source, "remove key")
        cls.repo = open_bare(os.path.join(cls.tmp, "work"), cls.source, cls.removed,
                             cls.base, depth=5)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_commits_between_lists_pr_commits_oldest_first(self):
        listed = g.commits_between(self.repo, self.base, self.removed)
        self.assertEqual(listed["commits"], [self.added, self.removed])
        self.assertFalse(listed["truncated"])
        self.assertTrue(g.commits_between(self.repo, self.base, self.removed,
                                          limit=1)["truncated"])

    def test_secret_is_invisible_in_the_squashed_diff_but_visible_per_commit(self):
        squashed = g.diff_text(self.repo, self.base, self.removed, "config.py")["text"]
        self.assertNotIn(AWS_KEY, squashed)
        patch = g.commit_patch(self.repo, self.added)
        self.assertTrue(patch["available"])
        added_lines = [l for l in patch["text"].splitlines() if l.startswith("+")]
        self.assertTrue(any(AWS_KEY in l for l in added_lines))
        # In the later commit the same key appears only as a removal, which is how a
        # seeder tells "introduced here" from "cleaned up here".
        later = g.commit_patch(self.repo, self.removed)["text"].splitlines()
        self.assertTrue(any(AWS_KEY in l for l in later if l.startswith("-")))
        self.assertFalse(any(AWS_KEY in l for l in later if l.startswith("+")))

    def test_commit_parents_are_read_from_the_commit_object(self):
        self.assertEqual(g.commit_parents(self.repo, self.removed), [self.added])
        self.assertEqual(g.commit_parents(self.repo, self.base), [])

    def test_shallow_boundary_is_reported_not_silently_empty(self):
        shallow = g.open_repo(os.path.join(self.tmp, "shallow"))
        g.fetch_commits(shallow, self.source, [(self.removed, 1)], protocols=("file",))
        result = g.commit_patch(shallow, self.removed)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "shallow_boundary")
        # Without the parent check git prints an empty patch and exits 0 here, which is
        # indistinguishable from "this commit changed nothing".
        raw = g.run_git(shallow, ["diff-tree", "-p", "--no-commit-id", self.removed])
        self.assertEqual(raw.out, b"")
        self.assertTrue(g.commit_patch(self.repo, self.removed)["available"])

    def test_missing_commit_after_fetch_fails_loudly(self):
        repo = g.open_repo(os.path.join(self.tmp, "missing"))
        with self.assertRaises(g.GitError):
            g.fetch_pr(repo, self.source, "b" * 40, self.base, 2, protocols=("file",))

    def test_object_names_must_be_full_shas(self):
        for bad in ["HEAD", "main", self.base[:10], "../../etc", "", None]:
            with self.assertRaises(g.GitError, msg=repr(bad)):
                g.require_sha(bad)


class TestRunnerLimits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sa-limits-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = g.GitRepo(git_dir=os.path.join(self.tmp, "repo.git"),
                              home=os.path.join(self.tmp, "home"),
                              git_binary=fake_git(os.path.join(self.tmp, "git"),
                                                  'sleep "${SLEEP:-0}"\n'
                                                  'head -c "${BYTES:-10}" /dev/zero\n'),
                              caps=Caps())

    def test_output_cap_raises_instead_of_truncating(self):
        with self.assertRaises(g.GitError) as caught:
            g.run_git(self.repo, ["status"], max_bytes=16, env_extra={"BYTES": "100000"})
        self.assertIn("exceeded", str(caught.exception))
        self.assertEqual(len(g.run_git(self.repo, ["status"], max_bytes=16,
                                       env_extra={"BYTES": "8"}).out), 8)

    def test_timeout_kills_the_child(self):
        with self.assertRaises(g.GitError) as caught:
            g.run_git(self.repo, ["status"], timeout=1, env_extra={"SLEEP": "30"})
        self.assertIn("timed out", str(caught.exception))

    def test_failure_message_redacts_secrets(self):
        repo = g.GitRepo(git_dir=self.repo.git_dir, home=self.repo.home,
                         git_binary=fake_git(os.path.join(self.tmp, "git-fail"),
                                             'echo "boom ghs_supersecret" >&2\nexit 3\n'),
                         caps=Caps())
        with self.assertRaises(g.GitError) as caught:
            g.run_git(repo, ["fetch"], redact=("ghs_supersecret",))
        self.assertNotIn("ghs_supersecret", str(caught.exception))
        self.assertIn("***", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
