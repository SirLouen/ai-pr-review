"""The general reviewer's failure path: say WHY the model produced nothing.

On gpx-route-map#26 the review failed roughly every other run, and the log showed only
`Incorrect API key provided: dummy_key` for an OpenAI model this action never configured.
Two faults produced that: PR-Agent kept its default `fallback_models` because its Dynaconf
merges an empty list from the environment instead of replacing it, and this script printed
only the last 4000 characters of PR-Agent's output -- which, after a failure, is the prompt
PR-Agent dumps, not the error. The real cause (DeepSeek timing out) was thousands of lines
earlier.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_review as vr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()

# The shape of the run that failed, abbreviated: the real error, then the prompt dump, then
# the fallback's error last. Written in pieces so no line reads as a credential.
REAL_LOG = "\n".join([
    "2026-09-20 14:40:12 | INFO | starting review",
    "2026-09-20 14:45:12 | WARNING | pr_agent.algo.ai_handlers.litellm_ai_handler:chat_completion"
    ":1201 - Error during LLM inference: litellm.Timeout: APITimeoutError - Request timed out.",
    "2026-09-20 14:45:12 | WARNING | pr_agent.algo.pr_processing:retry_with_fallback_models:349"
    " - Failed to generate prediction with deepseek/deepseek-flash",
] + ["## File: 'src/block.json' hunk line %d" % n for n in range(400)] + [
    "2026-09-20 14:50:02 | WARNING | pr_agent.algo.ai_handlers.litellm_ai_handler:chat_completion"
    ":1201 - Error during LLM inference: litellm.AuthenticationError: OpenAIException - "
    "Incorrect API key provided: " + "dummy" + "_key.",
    "2026-09-20 14:50:02 | WARNING | pr_agent.algo.pr_processing:retry_with_fallback_models:349"
    " - Failed to generate prediction with gpt-5.6-terra",
    "2026-09-20 14:50:02 | ERROR | pr_agent.tools.pr_reviewer:run:346 - Failed to review PR: "
    "Failed to generate prediction with any model of ['deepseek/deepseek-flash', 'gpt-5.6-terra']",
])


class ModelErrors(unittest.TestCase):
    def test_the_first_models_failure_is_reported_not_just_the_last(self):
        lines = "\n".join(vr.model_errors(REAL_LOG))
        self.assertIn("deepseek/deepseek-flash", lines)
        self.assertIn("Timeout", lines, "the actual cause must be shown")
        # The control: the tail alone is what the action used to print, and the timeout is
        # not in it -- which is exactly why the failure read as an OpenAI key problem.
        self.assertNotIn("Timeout", REAL_LOG[-4000:])

    def test_the_lines_are_ordered_oldest_first_and_deduplicated(self):
        found = vr.model_errors(REAL_LOG + "\n" + REAL_LOG)
        self.assertEqual(len(found), len(set(found)))
        self.assertIn("Timeout", found[0], "the first failure in the run comes first")
        joined = "\n".join(found)
        self.assertLess(joined.index("deepseek"), joined.index("gpt-5.6-terra"),
                        "the primary model's failure must be read before the fallback's")

    def test_ansi_colour_does_not_hide_an_error(self):
        coloured = "\x1b[33m\x1b[1mFailed to generate prediction with deepseek/deepseek-flash\x1b[0m"
        self.assertTrue(vr.model_errors(coloured))

    def test_a_clean_log_reports_nothing(self):
        self.assertEqual(vr.model_errors("everything went fine\nPR-Agent raised 2 finding(s)"), [])

    def test_the_list_is_bounded(self):
        noisy = "\n".join(["Failed to generate prediction with model-%d" % n for n in range(99)])
        self.assertLessEqual(len(vr.model_errors(noisy)), 12)


class FallbackModels(unittest.TestCase):
    """The env var cannot do this: PR-Agent's Dynaconf has merge_enabled=True, so `[]`
    merges into the shipped default. The command line calls get_settings().set(), which
    replaces it."""

    def test_the_command_disables_fallback_models_on_the_command_line(self):
        self.assertIn('"--config.fallback_models=[]"', read("verify_review.py"))

    def test_the_action_does_not_pretend_to_set_it_from_the_environment(self):
        self.assertNotIn("CONFIG__FALLBACK_MODELS:", read("action.yml"),
                         "a setting that silently does nothing is worse than no setting")


class Timeouts(unittest.TestCase):
    def test_the_outer_timeout_outlasts_two_model_attempts(self):
        """PR-Agent retries a timed-out call once on the same model (MODEL_RETRIES = 2).
        If the outer timeout were the shorter one it would kill the run mid-retry and the
        bundle of log output would end without the second attempt's verdict."""
        import re
        action = read("action.yml")
        ai = int(re.search(r'CONFIG__AI_TIMEOUT: "(\d+)"', action).group(1))
        outer = int(re.search(r'PR_AGENT_TIMEOUT_SECONDS: "(\d+)"', action).group(1))
        self.assertGreater(outer, 2 * ai, "two attempts must fit inside the outer timeout")
        # And the whole thing has to fit a consumer job's timeout-minutes; 20 is what the
        # README tells them to use, with the pip install ahead of it.
        self.assertLess(outer + 120, 20 * 60)


if __name__ == "__main__":
    unittest.main()
