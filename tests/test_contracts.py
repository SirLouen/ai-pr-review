"""A prompt must never describe an output the tool will refuse.

Two such disagreements reached real runs undetected: the verifier prompt showed a
`blocker_kinds` field the tool rejects, and the recon prompt asked for nine typed facts
where the tool accepted three differently shaped fields, so every recon agent that
followed its prompt was discarded. The fakes in the other tests were written against
the tools, which is why none of them noticed. These tests compare the two directly.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import prompts, tools

CONTRACTS = {"verifier": prompts.VERIFIER_CONTRACT, "recon": prompts.RECON_CONTRACT}
KEY_RE = re.compile(r'"([A-Za-z_]+)"\s*:')


def property_names(schema, found=None):
    """Every property name anywhere in a schema."""
    found = set() if found is None else found
    for name, child in (schema.get("properties") or {}).items():
        found.add(name)
        property_names(child, found)
    if isinstance(schema.get("items"), dict):
        property_names(schema["items"], found)
    return found


class PromptsMatchTools(unittest.TestCase):
    def test_every_field_a_contract_shows_is_one_the_tool_accepts(self):
        for role, text in CONTRACTS.items():
            schema = tools.SUBMIT_SCHEMAS[tools.SUBMIT_TOOLS[role]]
            accepted = property_names(schema)
            shown = set(KEY_RE.findall(text))
            self.assertTrue(shown, "%s contract shows no fields to check" % role)
            self.assertEqual(shown - accepted, set(),
                             "%s prompt asks for fields its tool refuses" % role)

    def test_every_top_level_field_the_tool_takes_is_in_the_contract(self):
        for role, text in CONTRACTS.items():
            schema = tools.SUBMIT_SCHEMAS[tools.SUBMIT_TOOLS[role]]
            shown = set(KEY_RE.findall(text))
            self.assertEqual(set(schema["properties"]) - shown, set(),
                             "%s tool takes fields its prompt never mentions" % role)

    def test_the_check_catches_the_bugs_it_was_written_for(self):
        """The control: both historical mismatches would fail the first test."""
        schema = tools.SUBMIT_SCHEMAS["submit_verdict"]
        self.assertNotIn("blocker_kinds", property_names(schema))
        recon = property_names(tools.SUBMIT_SCHEMAS["submit_recon"])
        self.assertNotIn("units", recon, "the old recon shape must not creep back")
