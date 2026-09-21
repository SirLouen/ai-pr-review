"""Run PR-Agent's CLI with the two settings its configuration cannot express.

verify_review.py runs this in place of `python -m pr_agent.cli`, with the same arguments.

1. No fallback model. PR-Agent ships `fallback_models = ["gpt-5.6-terra"]`, and neither the
   environment nor `--config.fallback_models=[]` can clear it: PR-Agent's Dynaconf runs with
   merge_enabled, so setting a list APPENDS to it (setting ["x"] yields ["gpt-5.6-terra", "x"]),
   even through set(..., merge=False) on a dotted key. When DeepSeek failed, the call was retried
   against OpenAI with a dummy key, and that error was the one the log ended on. Assigning the
   attribute replaces the value. It is cleared again after PR-Agent applies the reviewed
   repository's settings, because a `.pr_agent.toml` on its default branch, or the organisation's
   `pr-agent-settings` repository, can set `[config] fallback_models` and would put one back.

2. Reasoning off, with an explicit output budget. PR-Agent 0.45.0 sends `reasoning_effort` only to
   models on SUPPORT_REASONING_EFFORT_MODELS, and no DeepSeek model is on it, so the review request
   went out with no max_tokens and reasoning on. DeepSeek counts hidden reasoning against its output
   limit, and on Alph-One/alphone-enterprise#77 the reasoning used all of it: the response came back
   empty with finish_reason "length". Listing the model makes PR-Agent send the configured effort,
   and verify_review.py sets it to "none", which litellm's DeepSeek provider sends as
   thinking: {"type": "disabled"} -- the same setting the verifier calls already use.
"""
import os

import pr_agent.agent.pr_agent as agent
from pr_agent import cli
from pr_agent.algo import SUPPORT_REASONING_EFFORT_MODELS
from pr_agent.config_loader import get_settings


def clear_fallback_models():
    get_settings().config.fallback_models = []


def allow_reasoning_effort(model):
    """Let PR-Agent send config.reasoning_effort to `model`. A blank model is left to PR-Agent."""
    if model and model not in SUPPORT_REASONING_EFFORT_MODELS:
        SUPPORT_REASONING_EFFORT_MODELS.append(model)


_apply_repo_settings = agent.apply_repo_settings


def apply_repo_settings_then_clear_fallback(pr_url):
    # PRAgent._run_command calls this module-level name, so the replacement below is what runs.
    _apply_repo_settings(pr_url)
    clear_fallback_models()


agent.apply_repo_settings = apply_repo_settings_then_clear_fallback


if __name__ == "__main__":
    allow_reasoning_effort(os.environ.get("CONFIG__MODEL", "").strip())
    clear_fallback_models()
    cli.run()
