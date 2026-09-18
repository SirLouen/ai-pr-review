"""Tests for the parent-computed fingerprint scheme."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import fingerprint as fp  # noqa: E402
from prreview.security import routing  # noqa: E402
from prreview.security.routing import ATTACK, SUPPLY, block_id  # noqa: E402

ACCESS_CONTROL = block_id(ATTACK, "Access control")
CRYPTO = block_id(ATTACK, "Cryptography and secrets")
CI_UNTRUSTED = block_id(SUPPLY, "Untrusted code in a privileged workflow")

PY_SOURCE = """\
import os


class SessionStore:
    def __init__(self):
        self.data = {}

    def load(self, token):
        raw = os.environ.get("SECRET")
        return self.data.get(token, raw)


def top_level(request):
    return request.user
"""

TS_SOURCE = """\
export class Renderer {
  render(input: string) {
    this.el.innerHTML = input;
  }
}

export function escapeHtml(s: string) {
  return s.replace(/</g, "&lt;");
}

const handler = async (req, res) => {
  res.send(req.query.next);
};
"""

WORKFLOW = """\
name: ci
on:
  pull_request_target:
    types: [opened]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
"""


class ClassTokenTest(unittest.TestCase):
    def test_design_specified_tokens_are_exact(self):
        self.assertEqual("access-control", fp.class_token(ACCESS_CONTROL))
        self.assertEqual("crypto-secrets", fp.class_token(CRYPTO))
        self.assertEqual("supply.ci-untrusted-code", fp.class_token(CI_UNTRUSTED))

    def test_table_covers_every_routable_class_exactly(self):
        expected = {block_id(ATTACK, n) for n, _t in routing.ORDINARY_CLASSES}
        for _group, (companion, _heading, classes) in routing.COMPANION_GROUPS.items():
            expected |= {block_id(companion, n) for n, _t in classes}
        self.assertEqual(expected, set(fp.CLASS_TOKENS))

    def test_tokens_are_unique_and_well_formed(self):
        tokens = list(fp.CLASS_TOKENS.values())
        self.assertEqual(len(tokens), len(set(tokens)))
        for token in tokens:
            self.assertRegex(token, r"^[a-z0-9][a-z0-9.-]*$")

    def test_unknown_class_fails_closed(self):
        # Assembled at runtime so the codebase-wide block-ref scan does not see it.
        unknown = ATTACK + "#" + "Invented class"
        with self.assertRaises(fp.FingerprintError):
            fp.class_token(unknown)


class EscapeTest(unittest.TestCase):
    def test_separator_characters_cannot_survive_a_component(self):
        for raw in ("a:b.ts", "a@b.ts", "x y.ts", "café.ts", "a+b.ts"):
            escaped = fp.esc(raw)
            self.assertNotIn(":", escaped)
            self.assertNotIn("@", escaped)
            self.assertNotIn(" ", escaped)

    def test_escape_round_trips(self):
        for raw in ("src/a:b.ts", "src/pay‮moc.js", "plain/path.py", "a+b"):
            self.assertEqual(raw, fp.unesc(fp.esc(raw)))

    def test_over_long_component_is_hashed_and_stable(self):
        long_path = "src/" + "deep/" * 60 + "file.ts"
        escaped = fp.esc(long_path)
        self.assertRegex(escaped, r"^h-[0-9a-f]{12}$")
        self.assertEqual(escaped, fp.esc(long_path))
        self.assertNotEqual(escaped, fp.esc(long_path + "x"))
        self.assertIsNone(fp.unesc(escaped))

    def test_short_component_is_not_hashed(self):
        """Without this the hashing assertion above would pass for every path."""
        self.assertNotRegex(fp.esc("src/app.ts"), r"^h-[0-9a-f]{12}$")


class PatternTest(unittest.TestCase):
    def test_every_generated_fingerprint_matches_the_skill_pattern(self):
        samples = [
            fp.build(ACCESS_CONTROL, "src/api/users.ts", "updateUser"),
            fp.build(ACCESS_CONTROL, "src/api/users.ts", "updateUser", variant=2),
            fp.build(CI_UNTRUSTED, ".github/workflows/ci.yml", "jobs.build"),
            fp.build(CRYPTO, "src/a:b.ts", "_top"),
            fp.build(CRYPTO, "src/" + "deep/" * 60 + "x.ts", "_top"),
            fp.build(CRYPTO, "café/été.py", "chargé"),
        ]
        for sample in samples:
            self.assertRegex(sample, fp.PATTERN)

    def test_no_line_wave_agent_or_verdict_is_encoded(self):
        one = fp.for_sink(ACCESS_CONTROL, "a.py", PY_SOURCE, 9)
        two = fp.for_sink(ACCESS_CONTROL, "a.py", PY_SOURCE, 10)
        self.assertEqual(one, two)

    def test_empty_path_is_rejected(self):
        with self.assertRaises(fp.FingerprintError):
            fp.build(ACCESS_CONTROL, "", "sym")

    def test_variant_must_be_a_positive_integer(self):
        with self.assertRaises(fp.FingerprintError):
            fp.build(ACCESS_CONTROL, "a.py", "f", variant=0)


class ParseTest(unittest.TestCase):
    def test_round_trip(self):
        original = fp.build(ACCESS_CONTROL, "src/a:b.ts", "handle", variant=3)
        parts = fp.parse(original)
        self.assertEqual("access-control", parts["token"])
        self.assertEqual(ACCESS_CONTROL, parts["class_ref"])
        self.assertEqual("src/a:b.ts", parts["path"])
        self.assertEqual("handle", parts["symbol"])
        self.assertEqual(3, parts["variant"])

    def test_sink_key_drops_the_variant(self):
        one = fp.build(ACCESS_CONTROL, "src/a.ts", "handle")
        two = fp.build(ACCESS_CONTROL, "src/a.ts", "handle", variant=2)
        self.assertEqual(fp.sink_key(one), fp.sink_key(two))
        self.assertNotEqual(one, two)

    def test_foreign_scheme_is_rejected(self):
        with self.assertRaises(fp.FingerprintError):
            fp.parse("crypto-secrets:src/a.py@rule")


class EnclosingSymbolTest(unittest.TestCase):
    def test_python_method_class_and_module_level(self):
        self.assertEqual("load", fp.enclosing_symbol(PY_SOURCE, 9, "a.py"))
        self.assertEqual("top_level", fp.enclosing_symbol(PY_SOURCE, 14, "a.py"))
        self.assertEqual("_top", fp.enclosing_symbol(PY_SOURCE, 1, "a.py"))

    def test_python_decorator_resolves_to_the_function_below(self):
        source = "@app.route('/x')\ndef handler():\n    return 1\n"
        self.assertEqual("handler", fp.enclosing_symbol(source, 1, "a.py"))

    def test_typescript_method_function_and_arrow(self):
        self.assertEqual("render", fp.enclosing_symbol(TS_SOURCE, 3, "a.ts"))
        self.assertEqual("escapeHtml", fp.enclosing_symbol(TS_SOURCE, 8, "a.ts"))
        self.assertEqual("handler", fp.enclosing_symbol(TS_SOURCE, 13, "a.ts"))

    def test_go_rust_ruby_php_and_c(self):
        go = "package main\n\nfunc (s *S) Handle(w http.ResponseWriter) {\n\tx := 1\n}\n"
        self.assertEqual("Handle", fp.enclosing_symbol(go, 4, "a.go"))
        rust = "pub unsafe fn parse(p: *const u8) {\n    let x = 1;\n}\n"
        self.assertEqual("parse", fp.enclosing_symbol(rust, 2, "a.rs"))
        ruby = "class Users\n  def show\n    @u = 1\n  end\nend\n"
        self.assertEqual("show", fp.enclosing_symbol(ruby, 3, "a.rb"))
        php = "<?php\nclass C {\n  public function run($x) {\n    echo $x;\n  }\n}\n"
        self.assertEqual("run", fp.enclosing_symbol(php, 4, "a.php"))
        c = "#include <stdio.h>\n\nint parse_header(char *buf, int n) {\n  return n;\n}\n"
        self.assertEqual("parse_header", fp.enclosing_symbol(c, 4, "a.c"))

    def test_yaml_resolves_to_job_or_top_level_key(self):
        self.assertEqual("jobs.build", fp.enclosing_symbol(WORKFLOW, 15, "ci.yml"))
        self.assertEqual("jobs.publish", fp.enclosing_symbol(WORKFLOW, 20, "ci.yml"))
        self.assertEqual("on", fp.enclosing_symbol(WORKFLOW, 3, "ci.yml"))
        self.assertEqual("permissions", fp.enclosing_symbol(WORKFLOW, 7, "ci.yml"))

    def test_unknown_language_falls_back_to_top(self):
        self.assertEqual("_top", fp.enclosing_symbol("anything\n", 1, "notes.xyz"))
        self.assertEqual("_top", fp.enclosing_symbol("", 1, "a.py"))

    def test_out_of_range_line_is_clamped(self):
        self.assertEqual("top_level", fp.enclosing_symbol(PY_SOURCE, 9999, "a.py"))
        self.assertEqual("_top", fp.enclosing_symbol(PY_SOURCE, 0, "a.py"))


class StabilityTest(unittest.TestCase):
    def test_stable_across_a_line_shift(self):
        shifted = "# a new header comment\n" * 10 + PY_SOURCE
        before = fp.for_sink(CRYPTO, "store.py", PY_SOURCE, 9)
        after = fp.for_sink(CRYPTO, "store.py", shifted, 9 + 10)
        self.assertEqual(before, after)

    def test_stable_across_reformatting(self):
        reformatted = PY_SOURCE.replace(
            "    def load(self, token):\n        raw = os.environ.get(\"SECRET\")",
            "    def load(\n            self,\n            token,\n    ):\n"
            "        raw = os.environ.get(\n            \"SECRET\",\n        )")
        before = fp.for_sink(CRYPTO, "store.py", PY_SOURCE, 9)
        after = fp.for_sink(CRYPTO, "store.py", reformatted, 12)
        self.assertEqual(before, after)

    def test_a_different_enclosing_symbol_gives_a_different_fingerprint(self):
        """Guards the two tests above against a resolver that always returns _top."""
        in_load = fp.for_sink(CRYPTO, "store.py", PY_SOURCE, 9)
        in_top_level = fp.for_sink(CRYPTO, "store.py", PY_SOURCE, 14)
        self.assertNotEqual(in_load, in_top_level)
        self.assertNotIn("_top@", in_load)

    def test_a_different_class_gives_a_different_fingerprint(self):
        self.assertNotEqual(fp.for_sink(CRYPTO, "store.py", PY_SOURCE, 9),
                            fp.for_sink(ACCESS_CONTROL, "store.py", PY_SOURCE, 9))


class RenameMapTest(unittest.TestCase):
    def test_fingerprint_survives_a_rename(self):
        old = fp.for_sink(CRYPTO, "old/store.py", PY_SOURCE, 9)
        renames = fp.rename_map([{"path": "new/store.py",
                                  "previous_path": "old/store.py"}])
        self.assertEqual(fp.for_sink(CRYPTO, "new/store.py", PY_SOURCE, 9),
                         renames.translate(old))

    def test_rename_without_the_map_does_not_match(self):
        """Without the map the two fingerprints genuinely differ, so this is not vacuous."""
        self.assertNotEqual(fp.for_sink(CRYPTO, "old/store.py", PY_SOURCE, 9),
                            fp.for_sink(CRYPTO, "new/store.py", PY_SOURCE, 9))

    def test_chained_renames_follow_through(self):
        renames = fp.rename_map([{"path": "b.py", "previous_path": "a.py"},
                                 {"path": "c.py", "previous_path": "b.py"}])
        self.assertEqual("c.py", renames.current("a.py"))
        self.assertEqual("a.py", renames.original("c.py"))

    def test_cycle_does_not_hang(self):
        renames = fp.RenameMap([("a.py", "b.py"), ("b.py", "a.py")])
        self.assertIn(renames.current("a.py"), ("a.py", "b.py"))

    def test_unrelated_fingerprint_is_returned_unchanged(self):
        original = fp.for_sink(CRYPTO, "other.py", PY_SOURCE, 9)
        renames = fp.rename_map([{"path": "b.py", "previous_path": "a.py"}])
        self.assertEqual(original, renames.translate(original))

    def test_hashed_path_cannot_be_translated(self):
        long_old = "old/" + "deep/" * 60 + "x.py"
        original = fp.build(CRYPTO, long_old, "_top")
        renames = fp.RenameMap([(long_old, "new/x.py")])
        self.assertEqual(original, renames.translate(original))

    def test_variant_survives_translation(self):
        original = fp.build(CRYPTO, "a.py", "load", variant=2)
        renames = fp.RenameMap([("a.py", "b.py")])
        self.assertEqual(fp.build(CRYPTO, "b.py", "load", variant=2),
                         renames.translate(original))


if __name__ == "__main__":
    unittest.main()
