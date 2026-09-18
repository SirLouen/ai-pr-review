"""Tests for prreview.security.skillpack.

The point of the module is that a prompt cannot silently stop saying what the design says it
says, so most of these tests are pairs: the hardening is asserted, and the failure it prevents
is also reproduced with the hardening removed.
"""
import hashlib
import os
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from prreview.security import skillpack as sk  # noqa: E402

VENDOR = os.path.join(ROOT, "vendor", "security-audit")

# Every block the design (4.3/4.4) cites by line range, against the line range it cites.
# This is the independent check: the ranges come from the design, the text comes from the
# anchors, and neither is derived from the other.
DESIGN_RANGES = [
    ("SKILL.md#Core principles", "SKILL.md", 136, 166),
    ("SKILL.md#Separate priority from certainty", "SKILL.md", 150, 162),
    ("SKILL.md#Anti-patterns", "SKILL.md", 181, 192),
    ("HUNTING.md#Required hunter prompt", "HUNTING.md", 11, 25),
    ("HUNTING.md#Core hunting method", "HUNTING.md", 30, 96),
    ("HUNTING.md#Promotion procedure", "HUNTING.md", 102, 135),
    ("HUNTING.md#Candidate gate", "HUNTING.md", 141, 156),
    ("HUNTING.md#Structured hunter result", "HUNTING.md", 168, 213),
    ("HUNTING.md#Critic contract", "HUNTING.md", 223, 245),
    ("HUNTING.md#Quick-profile critic handling", "HUNTING.md", 249, 249),
    ("VALIDATION-AND-REPORTING.md#Verifier input whitelist",
     "VALIDATION-AND-REPORTING.md", 7, 7),
    ("VALIDATION-AND-REPORTING.md#Candidate-verifier prompt",
     "VALIDATION-AND-REPORTING.md", 12, 45),
    ("VALIDATION-AND-REPORTING.md#Verifier promotion procedure",
     "VALIDATION-AND-REPORTING.md", 51, 84),
    ("VALIDATION-AND-REPORTING.md#Verifier decision rules",
     "VALIDATION-AND-REPORTING.md", 87, 87),
    ("VALIDATION-AND-REPORTING.md#Quick merge", "VALIDATION-AND-REPORTING.md", 124, 124),
    ("VALIDATION-AND-REPORTING.md#Final record checks",
     "VALIDATION-AND-REPORTING.md", 126, 141),
    ("RECONNAISSANCE.md#Agent 1a", "RECONNAISSANCE.md", 12, 19),
    ("RECONNAISSANCE.md#Agent 1b", "RECONNAISSANCE.md", 25, 32),
    ("RECONNAISSANCE.md#Agent 1c", "RECONNAISSANCE.md", 38, 41),
    ("RECONNAISSANCE.md#Agent 1d", "RECONNAISSANCE.md", 47, 54),
    ("RECONNAISSANCE.md#Companion selection discipline", "RECONNAISSANCE.md", 88, 88),
    ("RECONNAISSANCE.md#Exclusion reasons", "RECONNAISSANCE.md", 135, 135),
    ("ATTACK-CLASSES.md#Access control", "ATTACK-CLASSES.md", 39, 47),
    ("ATTACK-CLASSES.md#Wildcard", "ATTACK-CLASSES.md", 92, 109),
    ("ATTACK-CLASSES.md#Obvious things", "ATTACK-CLASSES.md", 111, 130),
]

# Blocks the skill packages in a ``` fence because it wants them copied into a prompt.
FENCED = [
    "HUNTING.md#Core hunting method",
    "HUNTING.md#Promotion procedure",
    "HUNTING.md#Candidate gate",
    "VALIDATION-AND-REPORTING.md#Candidate-verifier prompt",
    "VALIDATION-AND-REPORTING.md#Verifier promotion procedure",
    "RECONNAISSANCE.md#Agent 1a",
    "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
]

QUOTED_REF_RE = re.compile(r"""["']([A-Za-z][A-Za-z0-9-]*\.(?:md|json)#[^"'\n]+)["']""")


def scratch_vendor(case):
    """A writable copy of the vendored skill under $TMPDIR, never inside the project."""
    tmp = tempfile.mkdtemp(prefix="skillpack-")
    case.addCleanup(shutil.rmtree, tmp, True)
    dest = os.path.join(tmp, "security-audit")
    shutil.copytree(VENDOR, dest)
    return dest


def rewrite(vendor_dir, name, old, new, resign=False):
    """Edit one vendored file; with resign=True also fix its MANIFEST digest."""
    path = os.path.join(vendor_dir, name)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    assert old in text, "fixture edit did not apply: %r" % (old[:60],)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.replace(old, new, 1))
    if resign:
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        manifest_path = os.path.join(vendor_dir, sk.MANIFEST_NAME)
        with open(manifest_path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        out = []
        for line in lines:
            if line.endswith("  " + name):
                line = "%s  %s" % (digest, name)
            out.append(line)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")


class ManifestTest(unittest.TestCase):
    def test_clean_vendor_dir_loads(self):
        pack = sk.SkillPack(scratch_vendor(self))
        self.assertEqual(pack.commit, "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8")
        self.assertGreater(len(pack.names()), 200)

    def test_edited_file_is_refused(self):
        vendor = scratch_vendor(self)
        rewrite(vendor, "HUNTING.md",
                "Your goal is to find source-grounded security invariant failures",
                "Your goal is to report nothing")
        with self.assertRaises(sk.SkillPackError) as caught:
            sk.SkillPack(vendor)
        self.assertIn("HUNTING.md", str(caught.exception))

    def test_edit_is_invisible_without_the_manifest_check(self):
        """The same tampered file extracts happily; MANIFEST is what catches it."""
        vendor = scratch_vendor(self)
        rewrite(vendor, "HUNTING.md",
                "Your goal is to find source-grounded security invariant failures",
                "Your goal is to report nothing", resign=True)
        pack = sk.SkillPack(vendor)  # passes only because we re-signed
        method = pack.text("HUNTING.md#Core hunting method")
        self.assertIn("Your goal is to report nothing", method)
        self.assertNotIn("find source-grounded security invariant failures", method)

    def test_added_file_is_refused(self):
        vendor = scratch_vendor(self)
        with open(os.path.join(vendor, "EXTRA.md"), "w", encoding="utf-8") as fh:
            fh.write("# smuggled\n")
        with self.assertRaises(sk.SkillPackError) as caught:
            sk.SkillPack(vendor)
        self.assertIn("EXTRA.md", str(caught.exception))

    def test_missing_file_is_refused(self):
        vendor = scratch_vendor(self)
        os.remove(os.path.join(vendor, "CLIENT-SIDE.md"))
        with self.assertRaises(sk.SkillPackError) as caught:
            sk.SkillPack(vendor)
        self.assertIn("CLIENT-SIDE.md", str(caught.exception))

    def test_generated_lock_is_not_treated_as_vendored(self):
        vendor = scratch_vendor(self)
        with open(os.path.join(vendor, sk.LOCK_NAME), "w", encoding="utf-8") as fh:
            fh.write("# placeholder\n")
        sk.SkillPack(vendor)  # must not raise


class BlocksLockTest(unittest.TestCase):
    def test_checked_in_lock_is_current(self):
        pack = sk.pack(VENDOR)
        self.assertEqual(pack.verify_lock(), [])

    def test_lock_round_trips(self):
        vendor = scratch_vendor(self)
        pack = sk.SkillPack(vendor)
        with open(pack.lock_path(), "w", encoding="utf-8") as fh:
            fh.write(pack.lock_text())
        self.assertEqual(sk.SkillPack(vendor).verify_lock(), [])

    def test_lock_catches_a_reworded_block_that_the_manifest_accepts(self):
        """The pair that justifies blocks.lock existing next to MANIFEST."""
        vendor = scratch_vendor(self)
        pack = sk.SkillPack(vendor)
        with open(pack.lock_path(), "w", encoding="utf-8") as fh:
            fh.write(pack.lock_text())
        rewrite(vendor, "SUPPLY-CHAIN-AND-RELEASE.md",
                "CI configuration is authorization code.",
                "CI configuration is ordinary configuration.", resign=True)
        reloaded = sk.SkillPack(vendor)  # MANIFEST passes: the digest was re-signed
        problems = reloaded.verify_lock()
        self.assertTrue(any("SUPPLY-CHAIN-AND-RELEASE.md#Core discipline" in p
                            for p in problems), problems)

    def test_lock_catches_a_renamed_heading(self):
        vendor = scratch_vendor(self)
        pack = sk.SkillPack(vendor)
        with open(pack.lock_path(), "w", encoding="utf-8") as fh:
            fh.write(pack.lock_text())
        rewrite(vendor, "CLIENT-SIDE.md",
                "## DOM and object-state attack classes (subagent_type: `general`)",
                "## DOM and object-state classes (subagent_type: `general`)", resign=True)
        problems = sk.SkillPack(vendor).verify_lock()
        self.assertIn("block no longer resolves: CLIENT-SIDE.md#DOM and object-state "
                      "attack classes", problems)

    def test_renamed_heading_breaks_the_companion_contract_loudly(self):
        vendor = scratch_vendor(self)
        rewrite(vendor, "CLIENT-SIDE.md",
                "## Validation rules (apply before reporting ANY finding here)",
                "## Rules (apply before reporting ANY finding here)", resign=True)
        with self.assertRaises(sk.SkillPackError) as caught:
            sk.SkillPack(vendor)
        self.assertIn("Validation rules", str(caught.exception))


class ByteExactnessTest(unittest.TestCase):
    """Item 3's CI assertion: extracted bytes are a slice of the file, and nothing else."""

    @classmethod
    def setUpClass(cls):
        cls.pack = sk.pack(VENDOR)

    def test_every_block_is_a_contiguous_file_slice(self):
        for name in self.pack.names():
            with self.subTest(block=name):
                block = self.pack.block(name)
                whole = self.pack.file_text(block.file)
                self.assertEqual(block.text, whole[block.start:block.end])

    def test_every_block_appears_verbatim_in_the_raw_file_bytes(self):
        """Slicing is done on decoded text; assert the bytes survive the round trip."""
        for name in self.pack.names():
            with self.subTest(block=name):
                block = self.pack.block(name)
                with open(os.path.join(VENDOR, block.file), "rb") as fh:
                    raw = fh.read()
                self.assertEqual(raw.count(block.text.encode("utf-8")), 1)

    def test_blocks_match_the_line_ranges_the_design_cites(self):
        for name, filename, first, last in DESIGN_RANGES:
            with self.subTest(block=name):
                lines = self.pack.file_text(filename).split("\n")
                self.assertEqual(self.pack.text(name), "\n".join(lines[first - 1:last]))

    def test_no_block_is_empty_or_padded(self):
        for name in self.pack.names():
            with self.subTest(block=name):
                text = self.pack.text(name)
                self.assertTrue(text.strip())
                self.assertEqual(text, text.rstrip())
                self.assertFalse(text.startswith(("\n", " ")))


class FencePolicyTest(unittest.TestCase):
    """The delimiter lines are stripped, and the file really does have them there."""

    @classmethod
    def setUpClass(cls):
        cls.pack = sk.pack(VENDOR)

    def test_fenced_blocks_carry_no_delimiters(self):
        for name in FENCED:
            with self.subTest(block=name):
                text = self.pack.text(name)
                self.assertFalse(text.startswith("```"))
                self.assertFalse(text.endswith("```"))
                self.assertNotIn("\n```", text)

    def test_the_surrounding_file_slice_does_carry_them(self):
        """Without the strip, every one of these prompts would start with stray backticks."""
        for name in FENCED:
            with self.subTest(block=name):
                block = self.pack.block(name)
                whole = self.pack.file_text(block.file)
                before = whole.rfind("\n", 0, block.start - 1) + 1
                after = whole.find("\n", block.end + 1)
                self.assertTrue(whole[before:block.start].startswith("```"),
                                "no opening fence before %s" % name)
                self.assertTrue(whole[block.end:after].strip().startswith("```"),
                                "no closing fence after %s" % name)

    def test_prose_sections_keep_the_json_fence_they_introduce(self):
        """A fence nested inside a selected prose section is content, not packaging."""
        result = self.pack.text("HUNTING.md#Structured hunter result")
        self.assertIn("```json", result)
        self.assertIn('"coverage_id"', result)
        critic = self.pack.text("HUNTING.md#Critic contract")
        self.assertIn("```json", critic)
        self.assertIn('"missing_units"', critic)


class RegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = sk.pack(VENDOR)

    def test_every_named_spec_resolves(self):
        for name in self.pack.names():
            with self.subTest(block=name):
                self.assertTrue(self.pack.text(name))

    def test_every_ordinary_attack_class_is_registered(self):
        expected = ["Injection", "Access control", "Resource and file handling",
                    "Cryptography and secrets", "Business logic",
                    "Feature abuse and data leakage",
                    "Chained vulnerabilities and trust boundaries", "Wildcard",
                    "Obvious things"]
        for name in expected:
            with self.subTest(block=name):
                self.assertTrue(self.pack.has("ATTACK-CLASSES.md#" + name))

    def test_obvious_things_keeps_the_flag_is_not_a_finding_paragraph(self):
        # The deterministic seeders cite this sentence as the reason a regex hit is a draft
        # candidate and never a finding; losing it would quietly change what they mean.
        text = self.pack.text("ATTACK-CLASSES.md#Obvious things")
        self.assertIn("A flag is not a finding — trace the impact before reporting.", text)

    def test_every_companion_has_the_three_required_sections(self):
        for companion in sk.COMPANIONS:
            for section in (sk.COMPANION_CORE, sk.COMPANION_UNIVERSAL, sk.COMPANION_RULES):
                with self.subTest(companion=companion, section=section):
                    self.assertTrue(self.pack.has("%s#%s" % (companion, section)))

    def test_companion_subsections_are_discovered(self):
        self.assertTrue(
            self.pack.has("WEB-PROTOCOL-AND-AUTH.md#JWT verification and claim binding"))
        self.assertTrue(
            self.pack.has("SUPPLY-CHAIN-AND-RELEASE.md#Untrusted code in a privileged workflow"))
        self.assertTrue(self.pack.has("CLIENT-SIDE.md#DOM-based XSS"))

    def test_companion_blocks_follow_the_required_order(self):
        # HUNTING.md:18: Core discipline, chosen subsections, Universal moves, Validation rules.
        names = self.pack.companion_blocks(
            "WEB-PROTOCOL-AND-AUTH.md", ["JWT verification and claim binding", "Ordinary CSRF"])
        self.assertEqual(names, [
            "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
            "WEB-PROTOCOL-AND-AUTH.md#JWT verification and claim binding",
            "WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF",
            "WEB-PROTOCOL-AND-AUTH.md#Universal moves",
            "WEB-PROTOCOL-AND-AUTH.md#Validation rules"])

    def test_unknown_companion_subsection_is_refused(self):
        with self.assertRaises(sk.SkillPackError):
            self.pack.companion_blocks("CLIENT-SIDE.md", ["Nonexistent class"])

    def test_unknown_block_name_is_refused(self):
        with self.assertRaises(sk.SkillPackError):
            self.pack.block("HUNTING.md#" + "no such section")

    def test_all_three_schema_branches_are_extracted(self):
        import json
        for verdict in ("confirmed", "needs_validation", "rejected"):
            with self.subTest(verdict=verdict):
                text = self.pack.text("report-schema.json#" + verdict)
                branch = json.loads(text)
                self.assertEqual(branch["properties"]["verdict"]["const"], verdict)
                self.assertIs(branch["additionalProperties"], False)

    def test_confirmed_branch_stays_available_to_the_hunter_prompt(self):
        # HUNTING.md:23 requires it even though the parent refuses a confirmed verdict.
        self.assertIn("report-schema.json#confirmed", sk.HUNTER_SCHEMA_BRANCHES)
        self.assertIn("report-schema.json#confirmed", sk.VERIFIER_SCHEMA_BRANCHES)
        self.assertIn('"confirmed"', self.pack.text("report-schema.json#confirmed"))


class AnchorFailureTest(unittest.TestCase):
    """An anchor that stops being unique must fail, not silently pick the first match."""

    def test_duplicate_anchor_is_refused(self):
        vendor = scratch_vendor(self)
        rewrite(vendor, "HUNTING.md", "## Structured hunter result",
                "## Structured hunter result\n\n## Structured hunter result", resign=True)
        pack = sk.SkillPack(vendor)
        with self.assertRaises(sk.SkillPackError) as caught:
            pack.block("HUNTING.md#Structured hunter result")
        self.assertIn("ambiguous", str(caught.exception))

    def test_missing_anchor_is_refused(self):
        vendor = scratch_vendor(self)
        rewrite(vendor, "HUNTING.md", "#### Core hunting method",
                "#### The hunting method", resign=True)
        pack = sk.SkillPack(vendor)
        with self.assertRaises(sk.SkillPackError) as caught:
            pack.block("HUNTING.md#Core hunting method")
        self.assertIn("not found", str(caught.exception))


class MethodSectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = sk.pack(VENDOR)
        cls.policy = ("Run execution policy (set by the parent; authoritative for this run):\n"
                      "The parent-approved OS-enforced sandbox is NOT available.")

    def test_method_then_promotion_then_policy(self):
        section = self.pack.method_section(self.policy)
        method = self.pack.text("HUNTING.md#Core hunting method")
        promotion = self.pack.text("HUNTING.md#Promotion procedure")
        self.assertIn(method, section)
        self.assertIn(promotion, section)
        # HUNTING.md:20 order, and the action's block strictly after both.
        self.assertLess(section.index(method), section.index(promotion))
        self.assertLess(section.index(promotion), section.index(sk.ACTION_BLOCK_OPEN))

    def test_policy_is_delimited_and_never_substituted_for_skill_text(self):
        section = self.pack.method_section(self.policy)
        self.assertIn(sk.ACTION_BLOCK_OPEN, section)
        self.assertIn(sk.ACTION_BLOCK_CLOSE, section)
        # The skill's own no-sandbox rule stays visible; the policy is added, not a swap.
        self.assertIn("If any control is unavailable, do not execute", section)
        self.assertIn("retain `needs_validation` with the exact\n    promotion blocker.",
                      section)

    def test_no_skill_bytes_appear_inside_the_action_block(self):
        section = self.pack.method_section(self.policy)
        start = section.index(sk.ACTION_BLOCK_OPEN)
        end = section.index(sk.ACTION_BLOCK_CLOSE)
        self.assertEqual(section[start + len(sk.ACTION_BLOCK_OPEN):end].strip(), self.policy)


class AccountingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = sk.pack(VENDOR)

    def test_account_totals_match_the_parts(self):
        names = list(sk.SYSTEM_BLOCKS) + list(sk.HUNTER_SCHEMA_BRANCHES)
        totals = self.pack.account(names)
        self.assertEqual(len(totals["blocks"]), len(names))
        self.assertEqual(totals["bytes"], sum(r["bytes"] for r in totals["blocks"]))
        self.assertEqual(totals["tokens"], sum(r["tokens"] for r in totals["blocks"]))
        self.assertEqual(totals["bytes"],
                         sum(len(self.pack.text(n).encode("utf-8")) for n in names))

    def test_token_estimate_is_conservative(self):
        # Four characters per token is the usual rule of thumb; the estimate must not fall
        # below it, or a prompt that "fits" the budget overflows the context window mid-run.
        for name in self.pack.names():
            with self.subTest(block=name):
                block = self.pack.block(name)
                self.assertGreaterEqual(block.tokens, block.nbytes // 5)
                self.assertLessEqual(block.tokens, block.nbytes)

    def test_fits_compares_against_the_budget(self):
        names = ["HUNTING.md#Core hunting method"]
        tokens = self.pack.account(names)["tokens"]
        self.assertTrue(self.pack.fits(names, tokens))
        self.assertFalse(self.pack.fits(names, tokens - 1))

    def test_estimate_tokens_on_empty_text(self):
        self.assertEqual(sk.estimate_tokens(""), 0)


class CodebaseRefTest(unittest.TestCase):
    """Every block reference written anywhere in the codebase must resolve."""

    def test_quoted_block_refs_resolve(self):
        pack = sk.pack(VENDOR)
        checked = 0
        for directory in ("prreview", "tests"):
            for base, dirs, files in os.walk(os.path.join(ROOT, directory)):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for filename in files:
                    if not filename.endswith(".py"):
                        continue
                    path = os.path.join(base, filename)
                    with open(path, "r", encoding="utf-8") as fh:
                        source = fh.read()
                    for ref in QUOTED_REF_RE.findall(source):
                        checked += 1
                        with self.subTest(ref=ref, path=os.path.relpath(path, ROOT)):
                            self.assertTrue(pack.has(ref),
                                            "%s references unknown block %r" % (path, ref))
        self.assertGreater(checked, 40, "the ref scanner found almost nothing to check")

    def test_the_scanner_would_catch_a_bad_ref(self):
        # Assembled at runtime so this file's own fixture does not trip the scan above.
        bad = "HUNTING.md#" + "Not a real section"
        self.assertEqual(QUOTED_REF_RE.findall('"%s"' % bad), [bad])
        self.assertFalse(sk.pack(VENDOR).has(bad))


if __name__ == "__main__":
    unittest.main()
