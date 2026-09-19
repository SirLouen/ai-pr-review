"""Run configuration, caps and the model/price map for the security reviewer.

Every value the rest of the package depends on is resolved here, once, from the
environment the composite action sets. Nothing else reads os.environ: the model
key is popped out of it in load() and lives only in ProviderCreds, so a later
tool or subprocess cannot reach it through the ambient environment.
"""
import os
import re
from dataclasses import dataclass, field, replace

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
MODEL_RE = re.compile(r"^[A-Za-z0-9._@:-]+$")

# The empty tree. Passed as attr.tree so no in-tree .gitattributes is ever
# consulted: a PR that adds "*.ts -diff" would otherwise make git grep and
# git diff report matching files as binary and hide its own changes.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
MIN_GIT_VERSION = (2, 40)  # attr.tree landed in 2.40 and unknown -c keys are ignored silently


class ConfigError(Exception):
    """Raised for an invalid or missing input. The run stops before any model call."""


@dataclass(frozen=True)
class Price:
    """USD per million tokens. DeepSeek bills cache hits and misses differently."""
    cache_miss: float
    cache_hit: float
    output: float

    def usd(self, miss_tokens, hit_tokens, output_tokens):
        return (miss_tokens * self.cache_miss + hit_tokens * self.cache_hit
                + output_tokens * self.output) / 1_000_000


# Peak (01:00-04:00 and 06:00-10:00 UTC, Mon-Fri) is the rate we bill against, so a
# run never costs more than its estimate. Source: api-docs.deepseek.com pricing,
# fetched 2026-09-18. Re-check with `python -m prreview.security prices --check`.
PRICES = {
    "deepseek-flash": Price(cache_miss=0.30, cache_hit=0.006, output=1.20),
    "deepseek-v4-pro": Price(cache_miss=1.32, cache_hit=0.026, output=3.96),
    "claude-sonnet-5": Price(cache_miss=3.00, cache_hit=0.30, output=15.00),
    "claude-opus-5": Price(cache_miss=5.00, cache_hit=0.50, output=25.00),
}

# Context window per model, used to derive the per-conversation context cap.
WINDOWS = {
    "deepseek-flash": 1_000_000,
    "deepseek-v4-pro": 1_000_000,
    "claude-sonnet-5": 200_000,
    "claude-opus-5": 200_000,
}

ROLES = ("recon", "hunter", "critic", "verifier")


@dataclass(frozen=True)
class Caps:
    """Hard limits. Every one of them is enforced by the parent, not by a prompt."""
    max_conversations: int = 18
    max_hunters: int = 6
    max_verifiers: int = 10
    max_usd: float = 1.50
    # Cloudflare's harness keeps each agent under 25% of its context window; beyond
    # that, recall degrades faster than the extra context helps.
    context_fraction: float = 0.25
    tool_output_bytes: int = 300_000
    # Recon at 20, not 30: on the first real pull request the recon agents that ran to
    # turn 30 were the most expensive in the run, because every turn re-sends the whole
    # history. Two turns before the limit the loop tells an agent to submit what it has.
    max_turns = {"recon": 20, "hunter": 26, "critic": 20, "verifier": 25}
    # Cost ceilings on the warm-start pack, in tokens. The pack was sized from the context
    # window alone, and on a 1M-token model that meant up to ~125k tokens of source in every
    # hunter's first message: on gophenberg#225 hunters opened at 102k tokens and the
    # verifier at 80k, the largest single cost in the run. The pack is a warm start; agents
    # open anything beyond it with windowed read_file calls, and what it leaves out is listed.
    pack_tokens = {"hunter": 24_000, "verifier": 16_000}
    blob_bytes: int = 2 * 1024 * 1024
    read_lines: int = 400
    read_bytes: int = 40_000
    grep_hits: int = 200
    grep_bytes: int = 16_000
    tree_entries: int = 500
    diff_lines: int = 1_500
    # Tree indexes are built per ref on demand; a PR with hundreds of commits would
    # otherwise let one conversation index them all.
    max_commit_indexes: int = 8
    # PR-size gate. Computed from the compare API before anything is fetched.
    max_changed_files: int = 300
    max_diff_lines: int = 20_000
    max_fetch_bytes: int = 512 * 1024 * 1024
    run_deadline_s: int = 2_400
    conversation_deadline_s: int = 720
    request_timeout_s: int = 300
    parallel_conversations: int = 6

    def context_tokens(self, model):
        return int(WINDOWS.get(model, 128_000) * self.context_fraction)

    def tool_output_budget(self, model):
        """Tool output can never exceed the context it has to fit into.

        A flat byte cap is wrong across providers: 300 KB of source is roughly
        75-100k tokens, which overflows a 50k-token budget on a 200k window.
        """
        return min(self.tool_output_bytes, int(self.context_tokens(model) * 3.5))


@dataclass(frozen=True)
class ProviderCreds:
    """Secrets for one run. Deliberately not part of RunConfig, never logged or repr'd.

    The GitHub token rides here rather than staying in the environment so that the fetch
    can be handed it explicitly, and so no other code has to read os.environ to find it.
    """
    deepseek_key: str = ""
    anthropic_key: str = ""
    github_token: str = ""

    def __repr__(self):  # keeps keys out of tracebacks and debug dumps
        return "ProviderCreds(deepseek=%s, anthropic=%s, github=%s)" % (
            "set" if self.deepseek_key else "unset",
            "set" if self.anthropic_key else "unset",
            "set" if self.github_token else "unset")


@dataclass(frozen=True)
class RunConfig:
    repository: str
    pr_number: int
    head_sha: str
    base_sha: str
    out_dir: str
    vendor_dir: str
    models: dict = field(default_factory=lambda: dict(DEFAULT_MODELS))
    caps: Caps = field(default_factory=Caps)
    recon_mode: str = "baseline-delta"      # baseline-delta | per-run
    disclosure: str = "auto"                # auto | all | summary-only
    allow_custom_base_url: bool = False
    workflow_ref: str = ""
    github_api: str = "https://api.github.com"

    @property
    def run_id(self):
        return "pr%d-%s" % (self.pr_number, self.head_sha[:12])


# Every role on DeepSeek-V4.1-Flash, whose API id is `deepseek-flash` (the API accepts
# only `deepseek-flash` and `deepseek-v4-pro`; a `deepseek/` prefix is LiteLLM routing
# syntax, not part of the id). In the M1 spike flash hunters cost about a fifth of a
# v4-pro verifier per conversation.
DEFAULT_MODELS = {
    "recon": "deepseek-flash",
    "hunter": "deepseek-flash",
    "critic": "deepseek-flash",
    "verifier": "deepseek-flash",
}


def _require(name, pattern=None):
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise ConfigError("%s is required" % name)
    if pattern and not pattern.match(value):
        raise ConfigError("%s is malformed: %r" % (name, value[:80]))
    return value


def _parse_models(raw):
    """Parse 'recon=deepseek-flash,verifier=deepseek-v4-pro' into the role map."""
    models = dict(DEFAULT_MODELS)
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        role, _, model = part.partition("=")
        role, model = role.strip(), model.strip()
        if role not in ROLES:
            raise ConfigError("unknown model role %r (expected one of %s)"
                              % (role, ", ".join(ROLES)))
        if not MODEL_RE.match(model):
            raise ConfigError("malformed model name for %s: %r" % (role, model))
        models[role] = model
    # A verifier on the hunter's model is allowed. The skill requires a FRESH verifier
    # that did not hunt the candidate (VALIDATION-AND-REPORTING.md:5), which separate
    # conversations already guarantee. A different model is a further hedge against a
    # shared blind spot, borrowed from Cloudflare's harness; the report says when it is
    # not in use rather than the run refusing to start.
    return models


def shares_verifier_model(models):
    return models.get("verifier") == models.get("hunter")


def load(environ=None):
    """Build (RunConfig, ProviderCreds) and remove the secrets from the environment."""
    env = os.environ if environ is None else environ
    previous, os.environ = os.environ, env
    try:
        repository = _require("SA_REPOSITORY", REPO_RE)
        head_sha = _require("SA_HEAD_SHA", SHA_RE)
        base_sha = _require("SA_BASE_SHA", SHA_RE)
        pr_raw = _require("SA_PR_NUMBER")
        if not pr_raw.isdigit() or not 0 < int(pr_raw) < 10 ** 9:
            raise ConfigError("SA_PR_NUMBER is malformed: %r" % pr_raw[:40])
        caps = _caps_from_env()
        cfg = RunConfig(
            repository=repository,
            pr_number=int(pr_raw),
            head_sha=head_sha,
            base_sha=base_sha,
            out_dir=_require("SA_OUT_DIR"),
            vendor_dir=env.get("SA_VENDOR_DIR") or _default_vendor_dir(),
            models=_parse_models(env.get("SA_MODELS")),
            caps=caps,
            recon_mode=_choice("SA_RECON_MODE", "baseline-delta",
                               ("baseline-delta", "per-run")),
            disclosure=_choice("SA_DISCLOSURE", "auto", ("auto", "all", "summary-only")),
            allow_custom_base_url=_flag("SA_ALLOW_CUSTOM_BASE_URL"),
            workflow_ref=env.get("GITHUB_WORKFLOW_REF", ""),
        )
    finally:
        os.environ = previous

    creds = ProviderCreds(deepseek_key=env.get("DEEPSEEK_API_KEY", ""),
                          anthropic_key=env.get("ANTHROPIC_API_KEY", ""),
                          github_token=env.get("SA_GITHUB_TOKEN", ""))
    if not creds.deepseek_key and not creds.anthropic_key:
        raise ConfigError("no model credential: set DEEPSEEK_API_KEY or ANTHROPIC_API_KEY")
    for name in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "SA_GITHUB_TOKEN"):
        env.pop(name, None)
    return cfg, creds


def _default_vendor_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "vendor", "security-audit"))


def _choice(name, default, allowed):
    value = (os.environ.get(name) or default).strip()
    if value not in allowed:
        raise ConfigError("%s must be one of %s, got %r" % (name, ", ".join(allowed), value))
    return value


def _flag(name):
    return (os.environ.get(name) or "").strip().lower() == "true"


def _caps_from_env():
    caps = Caps()
    overrides = {}
    for field_name, cast in (("max_conversations", int), ("max_hunters", int),
                             ("max_verifiers", int), ("max_usd", float)):
        raw = (os.environ.get("SA_" + field_name.upper()) or "").strip()
        if not raw:
            continue
        try:
            value = cast(raw)
        except ValueError:
            raise ConfigError("SA_%s is not a number: %r" % (field_name.upper(), raw[:40]))
        if value <= 0:
            raise ConfigError("SA_%s must be positive" % field_name.upper())
        overrides[field_name] = value
    return replace(caps, **overrides) if overrides else caps
