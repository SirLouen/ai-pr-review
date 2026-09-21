"""The general reviewer's failure path: say WHY the model produced nothing.

On gpx-route-map#26 the review failed roughly every other run, and the log showed only
`Incorrect API key provided: dummy_key` for an OpenAI model this action never configured.
Two faults produced that: PR-Agent kept its default `fallback_models` because its Dynaconf
merges an empty list from the environment instead of replacing it, and this script printed
only the last 4000 characters of PR-Agent's output -- which, after a failure, is the prompt
PR-Agent dumps, not the error. The real cause (DeepSeek timing out) was thousands of lines
earlier.
"""
import importlib.util
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


HAVE_PR_AGENT = importlib.util.find_spec("pr_agent") is not None


class Launcher(unittest.TestCase):
    """What pr_agent_launch.py must do, since PR-Agent's configuration cannot.

    v1.2.1 passed --config.fallback_models=[] instead. It could not work: with merge_enabled,
    setting a list appends to it, so the fallback survived and Alph-One/alphone-enterprise#77
    still ended on OpenAI's dummy_key error. These tests run against the installed PR-Agent
    where it is available, so a change like that fails here rather than in a consumer's run.
    """

    def test_the_review_runs_through_the_launcher_not_the_bare_cli(self):
        source = read("verify_review.py")
        self.assertIn("pr_agent_launch.py", source)
        self.assertNotIn('"-m", "pr_agent.cli"', source)
        self.assertNotIn("--config.fallback_models", source, "it appends; it never cleared anything")

    def test_the_review_asks_for_reasoning_off_and_an_explicit_budget(self):
        source = read("verify_review.py")
        self.assertIn('env["CONFIG__REASONING_EFFORT"] = "none"', source)
        self.assertIn('env["CONFIG__MAX_OUTPUT_TOKENS"]', source)

    def test_the_action_does_not_pretend_to_set_the_fallback_from_the_environment(self):
        self.assertNotIn("CONFIG__FALLBACK_MODELS:", read("action.yml"),
                         "a setting that silently does nothing is worse than no setting")

    @unittest.skipUnless(HAVE_PR_AGENT, "PR-Agent is not installed")
    def test_setting_the_list_appends_which_is_why_a_launcher_is_needed(self):
        """The control: if PR-Agent ever makes set() replace lists, the launcher is redundant."""
        from pr_agent.config_loader import get_settings
        before = list(get_settings().config.fallback_models)
        get_settings().set("CONFIG.FALLBACK_MODELS", ["x-sentinel"], merge=False)
        try:
            self.assertEqual(list(get_settings().config.fallback_models), before + ["x-sentinel"])
        finally:
            get_settings().config.fallback_models = before

    @unittest.skipUnless(HAVE_PR_AGENT, "PR-Agent is not installed")
    def test_a_fallback_the_repository_settings_put_back_is_cleared(self):
        """A .pr_agent.toml, or the org's pr-agent-settings repo, is applied inside PRAgent,
        after the launcher starts, and can set [config] fallback_models."""
        import pr_agent.agent.pr_agent as agent
        import pr_agent_launch as launcher
        from pr_agent.config_loader import get_settings

        def repo_file_sets_a_fallback(pr_url):     # what _apply_repo_settings_file does
            section = dict(get_settings().as_dict()["CONFIG"], fallback_models=["openai/x"])
            get_settings().set("CONFIG", section, merge=False)

        saved = list(get_settings().config.fallback_models)
        real = launcher._apply_repo_settings
        launcher._apply_repo_settings = repo_file_sets_a_fallback
        try:
            agent.apply_repo_settings("https://github.com/o/r/pull/1")   # the name PRAgent calls
            self.assertEqual(list(get_settings().config.fallback_models), [])
        finally:
            launcher._apply_repo_settings = real
            get_settings().config.fallback_models = saved

    @unittest.skipUnless(HAVE_PR_AGENT, "PR-Agent is not installed")
    def test_the_model_is_listed_so_its_reasoning_effort_is_sent(self):
        import pr_agent_launch as launcher
        from pr_agent.algo import SUPPORT_REASONING_EFFORT_MODELS as listed
        saved = list(listed)
        try:
            launcher.allow_reasoning_effort("deepseek/deepseek-flash")
            launcher.allow_reasoning_effort("deepseek/deepseek-flash")
            self.assertEqual(listed.count("deepseek/deepseek-flash"), 1)
            before = len(listed)
            launcher.allow_reasoning_effort("")        # unset CONFIG__MODEL: leave PR-Agent alone
            self.assertEqual(len(listed), before)
        finally:
            listed[:] = saved


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
