"""Deterministic companion routing: a lexical pre-filter over the PR's changed files.

The skill selects companion files by the trust boundary reconnaissance actually found,
not by language or dependency name (RECONNAISSANCE.md:88). This module cannot find a
boundary -- it only reads paths and diff lines -- so it is deliberately an
over-inclusive PRE-FILTER whose output is passed to the agents as hints, labelled
with PRE_FILTER_NOTE. Loading a domain is never evidence that a boundary exists.

Two things make it worth its zero cost. First, companions are cheap (1-3k tokens) so
over-inclusion costs little while a miss costs a whole attack class. Second, every
selection carries structured reasons and every considered-but-unselected block carries
a parent-authored reason, which is what the ledger's `excluded_blocks` requires
(RECONNAISSANCE.md:135).

One companion is not vendored: `supplements/github-actions.md` is written by this action,
because the pinned skill has no GitHub Actions guidance at all. It is routed here beside the
SUPPLY-CHAIN CI groups whenever a CI signal fires, and it is kept in its own fields so that
nothing walking `companions` or `selections` can mistake it for skill text. prompts.py marks
it with its own provenance markers for the same reason.

Removals and renames are signals in their own right: deleting a `permissions:` block, a
CODEOWNERS entry or an auth middleware line removes a control, so diff-content regexes
run over removed lines as well as added ones, and path globs are matched against
`previous_path` as well as `path`.

Paths and diff text reaching this module are written by whoever opened the pull request.
Reason records keep the raw path in `path` for programmatic use, and only `evidence` is
sanitised for display; callers must still frame both as untrusted data before putting
them in a prompt or a Markdown comment.
"""
import hashlib
import re
import unicodedata
from dataclasses import dataclass

ATTACK = "ATTACK-CLASSES.md"
AI = "AI-AND-LLM.md"
CLIENT = "CLIENT-SIDE.md"
CLOUD = "CLOUD-AND-DEPLOYMENT.md"
DATA = "DATA-ISOLATION-AND-LIFECYCLE.md"
DESKTOP = "DESKTOP-MOBILE-AND-LOCAL-IPC.md"
MEMORY = "MEMORY-SAFETY-AND-BINARY.md"
PROTO = "PROTOCOLS-RPC-AND-MESSAGING.md"
RESOURCE = "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md"
SUPPLY = "SUPPLY-CHAIN-AND-RELEASE.md"
WEB = "WEB-PROTOCOL-AND-AUTH.md"

# The action's own companion, which is NOT vendored skill text. The pinned skill contains no
# GitHub Actions material at all: SUPPLY-CHAIN-AND-RELEASE.md names the generic CI classes and
# stops, so a pull request touching a workflow -- the highest-value class this action sees --
# would be hunted without the platform's own boundaries. The block-id prefix keeps the
# `supplements/` directory in the name, so a block reference in a ledger or a prompt can never
# be mistaken for one of the files under vendor/.
SUPPLEMENT_FILE = "github-actions.md"
SUPPLEMENT = "supplements/" + SUPPLEMENT_FILE

# HUNTING.md:7 orders budget-limited work: lowest-trust surfaces and the boundaries
# protecting credentials, code execution and release authority come first.
DOMAIN_PRIORITY = (SUPPLY, WEB, AI, DATA, CLOUD, CLIENT, PROTO, MEMORY, DESKTOP, RESOURCE)

# Every companion carries these three blocks alongside each selected class
# (RECONNAISSANCE.md:135). Heading text only, before any parenthetical qualifier.
FIXED_BLOCKS = ("Core discipline", "Universal moves", "Validation rules")

PRE_FILTER_NOTE = (
    "The companion blocks below were chosen by a deterministic lexical pre-filter over "
    "changed paths and diff lines. A loaded domain is not evidence. Per "
    "RECONNAISSANCE.md:88, select a class only because you found the trust-sensitive "
    "boundary its 'When to use this file' section describes; name that boundary in "
    "source or return nothing for it.")

MAX_REASONS_PER_BLOCK = 6
MAX_EVIDENCE_CHARS = 120

# Ordinary ATTACK-CLASSES blocks, in file order, with their fingerprint class tokens.
ORDINARY_CLASSES = (
    ("Injection", "injection"),
    ("Access control", "access-control"),
    ("Resource and file handling", "resource-file"),
    ("Cryptography and secrets", "crypto-secrets"),
    ("Business logic", "business-logic"),
    ("Feature abuse and data leakage", "feature-abuse"),
    ("Chained vulnerabilities and trust boundaries", "chained-trust"),
    ("Wildcard", "wildcard"),
    ("Obvious things", "obvious"),
)

# group key -> (companion file, exact group heading, ((class name, class token), ...)).
# The group key doubles as the fingerprint token prefix, so
# "supply.ci" + "-" + "untrusted-code" == "supply.ci-untrusted-code" (design 8.3).
# Class names are copied verbatim from the vendored files; tests/test_routing.py
# re-reads the vendored text and fails if any of them drifts.
COMPANION_GROUPS = {
    "supply.dep": (SUPPLY, "Dependency and build-input attack classes", (
        ("Dependency source and namespace confusion", "namespace-confusion"),
        ("Mutable and unbound build inputs", "unbound-inputs"),
        ("Generated-source and codegen provenance gaps", "codegen-provenance"),
        ("Build-context inclusion", "build-context"))),
    "supply.ci": (SUPPLY, "CI and automation attack classes", (
        ("Untrusted code in a privileged workflow", "untrusted-code"),
        ("Workflow command and expression confusion", "expression-confusion"),
        ("Cache, artifact, and workspace trust mixing", "cache-trust-mixing"),
        ("Automation identity overreach", "identity-overreach"))),
    "supply.release": (SUPPLY, "Release and update attack classes", (
        ("Build-to-promotion substitution", "promotion-substitution"),
        ("Release authorization and signing-policy gaps", "signing-policy"),
        ("Update metadata and rollback confusion", "update-metadata"),
        ("Plugin and extension trust expansion", "plugin-trust"))),

    "web.framing": (WEB, "HTTP framing and cache attack classes", (
        ("Request framing and desynchronization", "request-smuggling"),
        ("Web cache poisoning through unkeyed input", "cache-poisoning"),
        ("Cache deception and private-response caching", "cache-deception"),
        ("Host and forwarded-header trust", "host-header"),
        ("Response-header injection", "header-injection"))),
    "web.session": (WEB, "Browser-session attack classes", (
        ("Ordinary CSRF", "csrf"),
        ("Session fixation and invalidation", "session-fixation"),
        ("Cookie scope and transport", "cookie-scope"))),
    "web.federated": (WEB, "Federated-identity attack classes", (
        ("JWT verification and claim binding", "jwt-verification"),
        ("OAuth/OIDC request and callback binding", "oauth-binding"),
        ("SAML signed-object and assertion binding", "saml-binding"))),
    "web.mfa": (WEB, "MFA, passkey, and account-transition attack classes", (
        ("MFA enrollment and assurance downgrade", "mfa-downgrade"),
        ("Step-up binding and bypass", "step-up"),
        ("WebAuthn and passkey verification", "webauthn"),
        ("Account linking and identity collision", "account-linking"),
        ("Password reset and broader recovery", "account-recovery"))),
    "web.apikey": (WEB, "API-key and mTLS attack classes", (
        ("API-key scope and resource binding", "apikey-scope"),
        ("API-key exposure and unsafe transport", "apikey-exposure"),
        ("mTLS peer and application-identity confusion", "mtls-identity"),
        ("Certificate lifecycle fallback", "cert-lifecycle"))),

    "ai.context": (AI, "Context, retrieval, and memory attack classes", (
        ("Indirect injection through retrieved or ingested content", "indirect-injection"),
        ("Cross-session or cross-tenant context bleed", "context-bleed"),
        ("Persistent memory poisoning", "memory-poisoning"),
        ("Prompt role and provenance confusion", "role-confusion"))),
    "ai.tool": (AI, "Tool and action attack classes", (
        ("Tool-argument injection into a downstream sink", "arg-injection"),
        ("Excessive agency and confused-deputy authority", "excessive-agency"),
        ("Action-confirmation and approval binding", "approval-binding"),
        ("Tool-schema and dispatcher disagreement", "schema-mismatch"),
        ("Unbounded delegated action loops", "delegation-loops"))),
    "ai.mcp": (AI, "MCP and sub-agent trust classes", (
        ("Sub-agent and MCP trust inheritance", "trust-inheritance"),
        ("MCP server and tool identity confusion", "server-identity"),
        ("MCP metadata and schema as policy", "metadata-as-policy"))),
    "ai.output": (AI, "Output and disclosure attack classes", (
        ("Insecure output rendering", "insecure-rendering"),
        ("Sensitive context extraction", "context-extraction"))),

    "data.tenant": (DATA, "Tenant and object-isolation attack classes", (
        ("Missing tenant or owner enforcement", "missing-tenant-scope"),
        ("Composite-key and namespace collision", "key-collision"),
        ("Policy and query disagreement", "policy-query-drift"),
        ("Blob and signed-reference overreach", "blob-overreach"))),
    "data.derived": (DATA, "Derived-data and disclosure attack classes", (
        ("Search, cache, and index ACL drift", "index-acl-drift"),
        ("Analytics, logs, traces, and diagnostics as alternate readers", "telemetry-readers"),
        ("Enumeration and aggregate oracles", "enumeration-oracles"))),
    "data.export": (DATA, "Export, backup, restore, and migration attack classes", (
        ("Export and backup scope expansion", "export-scope"),
        ("Import and restore authority expansion", "restore-authority"),
        ("Migration default and ownership confusion", "migration-defaults"),
        ("Backup and replication boundary drift", "replication-drift"))),
    "data.deletion": (DATA, "Deletion, revocation, and lifecycle attack classes", (
        ("Soft-delete and tombstone bypass", "soft-delete-bypass"),
        ("Stale authorization and derived copy use", "stale-authorization"),
        ("Retention and queued-work overrun", "retention-overrun"),
        ("Restore reintroduces invalid state", "restore-reintroduction"))),

    "cloud.identity": (CLOUD, "Workload identity and IAM attack classes", (
        ("Workload identity overreach", "workload-overreach"),
        ("Cross-account or cross-tenant role confusion", "role-confusion"),
        ("Application authorization delegated to cloud metadata", "metadata-authz"))),
    "cloud.ingress": (CLOUD, "Ingress, network, and control-plane attack classes", (
        ("Unexpected service or management-plane reachability", "mgmt-reachability"),
        ("Trusted-proxy and mesh identity bypass", "proxy-bypass"),
        ("Metadata and internal-service reachability", "internal-reachability"))),
    "cloud.container": (CLOUD, "Container and orchestration attack classes", (
        ("Host or control-plane capability exposure", "host-capability"),
        ("Admission and policy path inconsistency", "admission-policy"),
        ("Namespace and label trust confusion", "namespace-trust"))),
    "cloud.config": (CLOUD, "Configuration and secret lifecycle attack classes", (
        ("Security-control precedence drift", "precedence-drift"),
        ("Secret exposure across workload boundaries", "secret-exposure"),
        ("Credential renewal and outage fallback", "credential-renewal"))),
    "cloud.storage": (CLOUD, "Managed storage, events, and edge attack classes", (
        ("Object and signed-URL policy confusion", "signed-url"),
        ("Event-source identity confusion", "event-source"),
        ("Edge/runtime boundary mismatch", "edge-boundary"))),

    "client.dom": (CLIENT, "DOM and object-state attack classes", (
        ("DOM-based XSS", "dom-xss"),
        ("DOM clobbering", "dom-clobbering"),
        ("Prototype pollution and gadget chain", "prototype-pollution"))),
    "client.messaging": (CLIENT, "Cross-origin messaging and network attack classes", (
        ("`postMessage` origin and source trust", "postmessage-origin"),
        ("Cross-site WebSocket request use", "cswsh"),
        ("Credentialed CORS trust", "cors-credentialed"))),
    "client.storage": (CLIENT, "Service-worker and browser-storage attack classes", (
        ("Service-worker registration and scope takeover", "sw-scope"),
        ("Service-worker cache and identity confusion", "sw-cache"),
        ("Browser-storage disclosure and stale authorization", "storage-disclosure"),
        ("Cross-context storage and broadcast confusion", "broadcast-confusion"))),
    "client.leaks": (CLIENT, "Cross-site information leak classes", (
        ("XS-Leaks and cross-origin state oracles", "xs-leaks"),
        ("Window and opener state disclosure", "opener-disclosure"))),
    "client.uiredress": (CLIENT, "UI-redress and navigation attack classes", (
        ("Clickjacking", "clickjacking"),
        ("Client-side navigation confusion", "navigation-confusion"))),

    "proto.framing": (PROTO, "Framing, schema, and interpretation attack classes", (
        ("Message boundary and canonicalization disagreement", "framing-canon"),
        ("Union, enum, and default confusion", "union-default"),
        ("Envelope and payload identity mismatch", "envelope-identity"))),
    "proto.rpc": (PROTO, "RPC identity and authorization attack classes", (
        ("Interceptor and method-path inconsistency", "interceptor-path"),
        ("Peer identity to application-principal confusion", "peer-principal"),
        ("Per-item and streaming authorization gaps", "streaming-authz"),
        ("Callback and reply-correlation confusion", "reply-correlation"))),
    "proto.broker": (PROTO, "Broker and queue isolation attack classes", (
        ("Topic, routing-key, and subscription scope gaps", "topic-scope"),
        ("Dead-letter, retry, and diagnostic disclosure", "dead-letter-disclosure"),
        ("Untrusted producer treated as control plane", "producer-control-plane"))),
    "proto.replay": (PROTO, "Replay, ordering, and transaction attack classes", (
        ("Duplicate delivery and idempotency gaps", "idempotency"),
        ("Out-of-order and stale message acceptance", "stale-ordering"),
        ("Acknowledgment/commit ordering defects", "ack-ordering"),
        ("Partial multi-consumer transitions", "partial-transition"))),

    "memory.bounds": (MEMORY, "Bounds, integer, and representation attack classes", (
        ("Out-of-bounds read or write", "oob"),
        ("Integer overflow, underflow, truncation, and signedness", "integer"),
        ("Unit and pointer-depth confusion", "unit-confusion"),
        ("Uninitialized or partially initialized data", "uninitialized"))),
    "memory.lifetime": (MEMORY, "Lifetime, type, and concurrency attack classes", (
        ("Use-after-free, stale view, and double free", "uaf"),
        ("Type confusion and invalid downcast", "type-confusion"),
        ("Reference-count and ownership races", "refcount-race"),
        ("Shared-state races and TOCTOU", "shared-state-race"),
        ("Lock-order, deadlock, and starvation", "lock-order"))),
    "memory.ffi": (MEMORY, "FFI and ABI attack classes", (
        ("Pointer-length and ownership contract mismatch", "ptr-contract"),
        ("Layout, alignment, and enum disagreement", "layout-mismatch"),
        ("Unwind, exception, and thread-affinity violations", "unwind-affinity"))),
    "memory.loader": (MEMORY, "Binary loading and runtime attack classes", (
        ("Library, plugin, and executable search-order trust", "search-order"),
        ("Missing artifact identity or signature binding", "artifact-identity"),
        ("Malformed binary metadata and relocation handling", "binary-metadata"),
        ("JIT and generated-code consistency", "jit-consistency"),
        ("Unload, reload, and teardown safety", "teardown-safety"))),
    "memory.kernel": (MEMORY, "Kernel and privileged-interface attack classes", (
        ("User-copy bounds and repeated reads", "user-copy"),
        ("Privileged object lifecycle and dispatch consistency", "object-lifecycle"),
        ("Under-authorized powerful interfaces", "under-authorized-interface"))),

    "desktop.deeplink": (DESKTOP, "Deep-link, callback, and navigation attack classes", (
        ("Custom-scheme and deep-link ambiguity", "deep-link-ambiguity"),
        ("App and account handoff confusion", "handoff-confusion"),
        ("File-open and intent authority confusion", "intent-authority"))),
    "desktop.webview": (DESKTOP, "Webview and native-bridge attack classes", (
        ("Navigation-origin to bridge confusion", "bridge-origin"),
        ("Over-broad native bridge capabilities", "bridge-capabilities"),
        ("Webview file and universal access", "webview-file-access"))),
    "desktop.ipc": (DESKTOP, "Local IPC and exported-component attack classes", (
        ("IPC peer-authentication gaps", "peer-auth"),
        ("Claimed principal versus channel identity", "claimed-principal"),
        ("Exported service, activity, receiver, or provider overreach", "exported-component"),
        ("IPC lifecycle and correlation confusion", "ipc-correlation"))),
    "desktop.helper": (DESKTOP, "Privileged-helper and local-file attack classes", (
        ("Privileged helper as confused deputy", "helper-deputy"),
        ("Install, update, and repair path trust", "install-path-trust"),
        ("Local file ownership and TOCTOU", "local-file-toctou"),
        ("Credential-store and local-secret boundary mismatch", "credential-store"))),
    "desktop.appstate": (DESKTOP, "Application-state and device-lifecycle attack classes", (
        ("Account switch, logout, and device restore leakage", "account-switch-leakage"),
        ("Pending-action and user-presence confusion", "user-presence"))),

    "resource.compute": (RESOURCE, "Computational amplification attack classes", (
        ("Superlinear parsing, matching, or evaluation", "superlinear"),
        ("Decompression and representation amplification", "decompression"),
        ("Database and downstream query amplification", "query-amplification"))),
    "resource.accumulation": (RESOURCE, "Resource accumulation attack classes", (
        ("Unbounded buffering and cardinality", "unbounded-buffering"),
        ("File descriptor, handle, and temporary-resource leaks", "handle-leak"),
        ("Detached work after cancellation", "detached-work"))),
    "resource.quota": (RESOURCE, "Quota and scheduling attack classes", (
        ("Pre-authentication work imbalance", "preauth-work"),
        ("Quota-accounting scope and reset gaps", "quota-accounting"),
        ("Worker, pool, and priority starvation", "starvation"))),
    "resource.failure": (RESOURCE, "Failure and recovery attack classes", (
        ("Reachable fatal error or deadlock", "fatal-error"),
        ("Retry storm and fail-open amplification", "retry-storm"),
        ("Poison-record and head-of-line blocking", "poison-record"),
        ("Unsafe recovery and capacity rollback", "unsafe-recovery"))),
}

# The same shape as COMPANION_GROUPS, for the action-authored supplement. Names are copied
# from supplements/github-actions.md; tests/test_supplement_wiring.py re-reads that file and
# fails if any of them drifts, exactly as tests/test_routing.py does for the vendored files.
# These groups are kept out of COMPANION_GROUPS on purpose: a supplement group is never a
# companion for clustering (it costs no per-hunter companion slot and has no HUNTING.md:7
# domain rank), and nothing that walks the vendored table may pick it up by accident.
SUPPLEMENT_GROUPS = {
    "gha.trigger": (SUPPLEMENT, "Trigger and checkout attack classes", (
        ("Privileged trigger executing contributor-controlled code", "privileged-trigger"),
        ("Approval and label gates that do not bind a commit", "unbound-approval"),
        ("`workflow_run` and artifact re-entry", "workflow-run-reentry"))),
    "gha.expression": (SUPPLEMENT, "Expression and environment attack classes", (
        ("Untrusted `${{ }}` interpolation into a shell or script", "expression-injection"),
        ("`GITHUB_ENV`, `GITHUB_OUTPUT` and `GITHUB_PATH` injection", "env-file-injection"),
        ("Composite-action and reusable-workflow input laundering", "input-laundering"))),
    "gha.state": (SUPPLEMENT, "Cross-run state attack classes", (
        ("Cache poisoning across a trust boundary", "cache-poisoning"),
        ("Artifact trust mixing between runs", "artifact-trust"))),
    "gha.identity": (SUPPLEMENT, "Identity and dependency attack classes", (
        ("Token permission overreach with a reachable action", "token-overreach"),
        ("`id-token: write` and cloud trust-policy binding", "oidc-binding"),
        ("Unpinned or mutable `uses:`", "unpinned-uses"),
        ("Self-hosted runner reuse", "self-hosted-reuse"))),
    "gha.agents": (SUPPLEMENT, "Agents in CI", (
        ("An AI reviewer or agent reachable by pull-request content", "agent-in-ci"),)),
}

# Which supplement group covers which vendored CI class. It is the bridge a caller uses when
# all it holds is a unit's selected blocks: the ledger builds its CI units from the vendored
# class names, so the supplement has to be reachable from those names alone.
SUPPLEMENT_FOR_CI_CLASS = {
    "Untrusted code in a privileged workflow": ("gha.trigger",),
    "Workflow command and expression confusion": ("gha.expression",),
    "Cache, artifact, and workspace trust mixing": ("gha.state",),
    "Automation identity overreach": ("gha.identity",),
}

DOC_GLOBS = ("*.md", "*.markdown", "*.rst", "*.txt", "*.adoc", "docs/**", "doc/**",
             "**/*.md", "**/*.rst", "LICENSE*", "COPYING*", "CHANGELOG*", "AUTHORS*",
             "**/CHANGELOG*", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico",
             "**/*.png", "**/*.svg")

# Agent-instruction files are Markdown but steer CI agents, so they are never "docs".
AGENT_INSTRUCTION_GLOBS = (
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
    ".github/copilot-instructions.md", ".github/instructions/**", ".claude/**",
    ".cursor/**", "**/AGENTS.md", "**/CLAUDE.md", "prompts/**", "**/*.prompt",
    "**/*.prompt.md", ".mcp.json", "mcp.json", "**/claude_desktop_config.json")

CODE_EXTS = frozenset((
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".go", ".rb", ".rake", ".java", ".kt", ".kts", ".scala", ".php", ".rs", ".c",
    ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".cs", ".swift",
    ".ex", ".exs", ".erl", ".clj", ".lua", ".pl", ".pm", ".sh", ".bash", ".zsh",
    ".ps1", ".vue", ".svelte", ".astro", ".dart", ".groovy", ".r", ".jl", ".zig",
    ".nim", ".hs", ".ml", ".fs", ".vb", ".sql", ".tf", ".proto", ".graphql"))

CI_GLOBS = (
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml",
    ".github/actions/**/action.yml", ".github/actions/**/action.yaml",
    "action.yml", "action.yaml", "**/action.yml", "**/action.yaml",
    ".gitlab-ci.yml", ".gitlab/**", ".circleci/**", "azure-pipelines*.yml",
    "azure-pipelines*.yaml", "Jenkinsfile", "Jenkinsfile.*", "**/Jenkinsfile",
    ".buildkite/**", "bitbucket-pipelines.yml", ".drone.yml", ".woodpecker*",
    "appveyor.yml", ".travis.yml", ".teamcity/**")

MANIFEST_GLOBS = (
    "package.json", "**/package.json", "package-lock.json", "**/package-lock.json",
    "yarn.lock", "**/yarn.lock", "pnpm-lock.yaml", "**/pnpm-lock.yaml",
    "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "Cargo.toml", "Cargo.lock",
    "**/Cargo.toml", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "go.mod", "go.sum", "**/go.mod", "requirements*.txt", "**/requirements*.txt",
    "pyproject.toml", "**/pyproject.toml", "setup.py", "setup.cfg", "build.rs",
    "pom.xml", "**/pom.xml", "build.gradle", "build.gradle.kts", "**/build.gradle*",
    "gradle/**", "gradle-wrapper.properties", "**/gradle-wrapper.properties",
    "*.csproj", "**/*.csproj", "NuGet.config", ".npmrc", "**/.npmrc", ".yarnrc",
    ".yarnrc.yml", "pip.conf", ".gitmodules", "vendor/**", "third_party/**",
    "flake.nix", "flake.lock", "Podfile", "Podfile.lock", "mix.exs", "mix.lock")


class RoutingError(Exception):
    """Raised for a malformed changed-file record. The run stops before any model call."""


def _glob_re(pattern):
    """Compile a path glob where `*` stops at `/` and `**` does not.

    fnmatch is not usable here: its `*` crosses `/`, so `.github/workflows/*.yml`
    would silently also match a nested path and `*.md` would match every file in
    `docs/`. Routing decisions hang on that distinction.
    """
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append(r"(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(r".*")
            i += 2
        elif ch == "*":
            out.append(r"[^/]*")
            i += 1
        elif ch == "?":
            out.append(r"[^/]")
            i += 1
        elif ch == "{":
            end = pattern.find("}", i)
            if end < 0:
                raise RoutingError("unterminated { in glob %r" % pattern)
            alts = pattern[i + 1:end].split(",")
            out.append("(?:%s)" % "|".join(re.escape(a) for a in alts))
            i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("".join(out) + r"\Z")


_GLOB_CACHE = {}


def matches_glob(path, pattern):
    rx = _GLOB_CACHE.get(pattern)
    if rx is None:
        rx = _GLOB_CACHE[pattern] = _glob_re(pattern)
    return rx.match(path) is not None


def matches_any(path, patterns):
    return any(matches_glob(path, p) for p in patterns)


def _rx(pattern):
    return re.compile(pattern)


@dataclass(frozen=True)
class Signal:
    """One routing rule. `groups` are companion group keys, `ordinary` are class names.

    `paths` matches the path (and previous_path). `content` is searched in diff lines,
    restricted to `content_paths` when set. `sides` limits a content rule to added or
    removed lines; the default sees both, because removing a control is a signal.

    `supplements` are SUPPLEMENT_GROUPS keys: the action-authored blocks this signal needs
    alongside its vendored `groups`, never instead of them.
    """
    id: str
    groups: tuple = ()
    supplements: tuple = ()
    ordinary: tuple = ()
    paths: tuple = ()
    content: object = None
    content_all: tuple = ()
    content_paths: tuple = ()
    sides: tuple = ("added", "removed")
    mandatory: bool = False
    tags: tuple = ()
    requires_path_match: bool = False


_WF = (".github/workflows/*.yml", ".github/workflows/*.yaml",
       ".github/workflows/**/*.yml", ".github/workflows/**/*.yaml",
       "action.yml", "action.yaml", "**/action.yml", "**/action.yaml")

SIGNALS = (
    # --- Supply chain: CI is always mandatory when CI config moves at all. ---
    # Every rule that fires on a CI path also names the supplement groups that carry the
    # GitHub-specific boundaries for it (design 4.5, row 1). A CI change with no more
    # specific signal still gets trigger and identity: which event runs the job and whose
    # commit it executes, and what that job holds, are the two facts nothing else supplies.
    Signal("ci-config", groups=("supply.ci",), supplements=("gha.trigger", "gha.identity"),
           paths=CI_GLOBS, mandatory=True, tags=("ci",)),
    Signal("ci-privileged-trigger", groups=("supply.ci",), supplements=("gha.trigger",),
           content_paths=CI_GLOBS,
           content=_rx(r"pull_request_target|workflow_run|issue_comment|"
                       r"pull_request_review|repository_dispatch|workflow_call"),
           tags=("ci", "privileged-trigger")),
    Signal("ci-head-checkout", groups=("supply.ci",), supplements=("gha.trigger",),
           content_paths=CI_GLOBS,
           content=_rx(r"(?:actions/checkout|ref:\s*\S*)"),
           content_all=(_rx(r"head\.sha|head\.ref|head_sha|head_branch|refs/pull/"),),
           tags=("ci", "head-checkout")),
    Signal("ci-expression-injection", groups=("supply.ci",), supplements=("gha.expression",),
           content_paths=CI_GLOBS,
           content=_rx(r"\$\{\{\s*(?:github\.event\.|github\.head_ref|inputs\.)"),
           tags=("ci",)),
    Signal("ci-env-file-write", groups=("supply.ci",), supplements=("gha.expression",),
           content_paths=CI_GLOBS,
           content=_rx(r"\$GITHUB_(?:ENV|OUTPUT|PATH)|GITHUB_(?:ENV|OUTPUT|PATH)\b"),
           tags=("ci",)),
    Signal("ci-permissions", groups=("supply.ci",), supplements=("gha.identity",),
           content_paths=CI_GLOBS,
           content=_rx(r"^\s*permissions:|write-all|id-token:\s*write|self-hosted|"
                       r"^\s*environment:|secrets\."),
           tags=("ci", "automation-identity")),
    Signal("ci-oidc", groups=("cloud.identity",), supplements=("gha.identity",),
           content_paths=CI_GLOBS,
           content=_rx(r"id-token:\s*write|token\.actions\.githubusercontent\.com|"
                       r"aws-actions/configure-aws-credentials|"
                       r"google-github-actions/auth|azure/login"),
           tags=("ci", "cloud-identity")),
    Signal("ci-cache-artifact", groups=("supply.ci",), supplements=("gha.state",),
           content_paths=CI_GLOBS,
           content=_rx(r"actions/(?:cache|upload-artifact|download-artifact)"),
           tags=("ci",)),
    Signal("ci-ai-agent", groups=("supply.ci", "ai.context", "ai.tool"),
           supplements=("gha.agents",), content_paths=CI_GLOBS,
           content=_rx(r"anthropics/claude-code-action|openai/codex-action|pr-agent|"
                       r"qodo-ai|ANTHROPIC_API_KEY|OPENAI_API_KEY|DEEPSEEK_API_KEY|"
                       r"GEMINI_API_KEY"),
           tags=("ci", "ai-in-ci")),
    Signal("ci-mutable-input", groups=("supply.dep",), supplements=("gha.identity",),
           content_paths=CI_GLOBS,
           content=_rx(r"uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)|docker://\S*:latest|"
                       r"curl\s[^|]*\|\s*(?:ba)?sh"),
           tags=("ci",)),
    # Review gates and attribute files are controls: their removal is the interesting
    # case, and .gitattributes can suppress diff and grep output for the reviewer. The
    # supplement's gate class is the one that asks whether approval binds a commit.
    Signal("review-gate", groups=("supply.ci",), supplements=("gha.trigger",),
           mandatory=True,
           paths=("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
                  ".gitattributes", "**/.gitattributes", ".github/dependabot.yml",
                  ".github/dependabot.yaml", "renovate.json", "renovate.json5",
                  ".renovaterc*", ".pre-commit-config.yaml", ".github/ruleset*.json"),
           tags=("review-gate",)),

    # --- Supply chain: dependency and release inputs. ---
    Signal("manifest", groups=("supply.dep",), paths=MANIFEST_GLOBS,
           tags=("manifest",)),
    Signal("registry-source", groups=("supply.dep",),
           content=_rx(r"--extra-index-url|--index-url|^\s*registry\s*=|"
                       r'"resolved":\s*"http|\bgit\+(?:https?|ssh)://|"file:'),
           tags=("manifest",)),
    Signal("install-hook", groups=("supply.dep",),
           content_paths=("package.json", "**/package.json"),
           content=_rx(r'"(?:preinstall|postinstall|prepare|prepublish)"\s*:'),
           tags=("manifest",)),
    Signal("release-tooling", groups=("supply.release",),
           paths=(".goreleaser*", ".releaserc*", "release-please-config.json",
                  "**/*.nuspec"),
           tags=("release",)),
    Signal("release-content", groups=("supply.release",),
           content=_rx(r"\bcosign\b|sigstore|attestation|provenance|electron-updater|"
                       r"autoUpdater|appcast|Sparkle|npm publish|twine upload"),
           tags=("release",)),

    # --- Cloud and deployment. ---
    Signal("container", groups=("cloud.container", "cloud.config"),
           paths=("Dockerfile", "Dockerfile.*", "**/Dockerfile", "**/Dockerfile.*",
                  "*.dockerfile", "**/*.dockerfile", "docker-compose*.yml",
                  "docker-compose*.yaml", "compose.yml", "compose.yaml",
                  ".dockerignore", "**/.dockerignore"),
           tags=("container",)),
    Signal("build-context", groups=("supply.dep",),
           content_paths=("Dockerfile", "Dockerfile.*", "**/Dockerfile",
                          "**/Dockerfile.*", "*.dockerfile", "**/*.dockerfile"),
           content=_rx(r"^\s*COPY\s+\.\s|^\s*COPY\s+\./|^\s*ADD\s+\.\s"),
           tags=("container",)),
    Signal("iac", groups=("cloud.identity", "cloud.ingress", "cloud.storage"),
           paths=("*.tf", "**/*.tf", "*.tfvars", "**/*.tfvars", "*.hcl", "**/*.hcl",
                  "Pulumi.*", "cdk.json", "*.bicep", "**/*.bicep",
                  "serverless.yml", "serverless.yaml", "template.yml", "template.yaml"),
           tags=("iac",)),
    Signal("iam-policy", groups=("cloud.identity",),
           content=_rx(r"AWSTemplateFormatVersion|\"Effect\"\s*:|\"Action\"\s*:|"
                       r'"Principal"\s*:|assume_role_policy|iam:PassRole'),
           tags=("iac",)),
    Signal("k8s", groups=("cloud.container", "cloud.ingress", "cloud.identity"),
           paths=("Chart.yaml", "**/Chart.yaml", "values*.yaml", "**/values*.yaml",
                  "kustomization.yaml", "**/kustomization.yaml", "helmfile*",
                  "k8s/**", "manifests/**", "deploy/**"),
           tags=("k8s",)),
    Signal("k8s-content", groups=("cloud.container", "cloud.ingress"),
           content=_rx(r"^kind:\s*(?:Deployment|DaemonSet|StatefulSet|Ingress|Role|"
                       r"ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|"
                       r"ServiceAccount|PodSecurityPolicy|Service)\b"),
           tags=("k8s",)),
    Signal("edge-config", groups=("cloud.storage", "cloud.ingress", "web.framing"),
           paths=("wrangler.toml", "wrangler.json", "wrangler.jsonc", "vercel.json",
                  "netlify.toml", "fly.toml", "app.yaml", "nginx.conf", "**/nginx.conf",
                  "*.nginx", "envoy*.yml", "envoy*.yaml", "haproxy.cfg", "Caddyfile",
                  "*.vcl", "**/*.vcl", "cloudfront*.json"),
           tags=("edge",)),

    # --- Web protocol and auth. ---
    Signal("auth-path", groups=("web.session", "web.federated"),
           ordinary=("Access control",),
           paths=("**/auth/**", "**/auth*.*", "**/login*.*", "**/logout*.*",
                  "**/session*.*", "**/sessions/**", "**/oauth*.*", "**/oidc*.*",
                  "**/sso*.*", "**/saml*.*", "**/jwt*.*", "**/token*.*",
                  "**/mfa*.*", "**/otp*.*", "**/webauthn*.*", "**/passkey*.*",
                  "**/password*.*", "**/reset*.*", "**/recovery*.*", "**/apikey*.*",
                  "**/api_key*.*", "**/middleware/**", "**/middlewares/**",
                  "**/guard/**", "**/guards/**", "**/policy/**", "**/policies/**",
                  "**/permission/**", "**/permissions/**", "**/rbac*.*"),
           tags=("auth",)),
    Signal("jwt", groups=("web.federated",),
           content=_rx(r"jsonwebtoken|\bjose\b|PyJWT|jwt\.(?:decode|sign|verify)|"
                       r"golang-jwt|verify_signature|algorithms\s*=|\balg\b\s*[:=]"),
           tags=("auth",)),
    Signal("oauth", groups=("web.federated",),
           content=_rx(r"\bpassport\b|next-auth|@auth/|authlib|oauthlib|redirect_uri|"
                       r"response_type=|\bstate=|client_secret|code_verifier"),
           tags=("auth",)),
    Signal("saml", groups=("web.federated",),
           content=_rx(r"python3-saml|xmlsec|samlify|SAMLResponse|urn:oasis:names:tc:SAML"),
           tags=("auth",)),
    Signal("session-cookie", groups=("web.session",),
           content=_rx(r"express-session|cookie-parser|Set-Cookie|SameSite|\bcsrf\b|"
                       r"csurf|session\.regenerate|HttpOnly"),
           tags=("auth",)),
    Signal("forwarded-headers", groups=("web.framing",),
           content=_rx(r"X-Forwarded-|^\s*Forwarded:|request\.host|\breq\.host\b|"
                       r"Cache-Control|\bVary\b|Transfer-Encoding|Content-Length"),
           tags=("http",)),
    Signal("mfa", groups=("web.mfa",),
           content=_rx(r"@simplewebauthn|webauthn|\btotp\b|pyotp|speakeasy|otplib|"
                       r"recovery_code|backup_code"),
           tags=("auth",)),
    Signal("apikey-mtls", groups=("web.apikey",),
           content=_rx(r"X-Api-Key|api[_-]?key|\bmTLS\b|client_cert|ssl_client|"
                       r"SSLContext|verify=False|rejectUnauthorized"),
           tags=("auth",)),
    Signal("authz-decorator", ordinary=("Access control",),
           content=_rx(r"@login_required|\[Authorize\]|permission_classes|@PreAuthorize|"
                       r"requireAuth|isAuthenticated|ensureLoggedIn|before_action|"
                       r"@roles_required|can\(|authorize!"),
           tags=("auth",)),
    Signal("http-route", ordinary=("Access control",),
           content=_rx(r"@app\.(?:get|post|put|patch|delete|route)|"
                       r"router\.(?:get|post|put|patch|delete|use)\(|"
                       r"@(?:Get|Post|Put|Patch|Delete)Mapping|app\.use\("),
           tags=("route",)),

    # --- Client side. ---
    Signal("dom-sink", groups=("client.dom",),
           content=_rx(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|"
                       r"dangerouslySetInnerHTML|v-html|\{@html|bypassSecurityTrust|"
                       r"\.html\(|srcdoc"),
           tags=("frontend",)),
    Signal("prototype-pollution", groups=("client.dom",),
           content=_rx(r"__proto__|lodash\.merge|defaultsDeep|Object\.assign\(\s*\{\s*\}|"
                       r"\bdeepMerge\b"),
           tags=("frontend",)),
    Signal("cross-origin-messaging", groups=("client.messaging",),
           content=_rx(r"postMessage|addEventListener\(\s*['\"]message|"
                       r"Access-Control-Allow-(?:Origin|Credentials)|new WebSocket|"
                       r"WebSocketServer"),
           tags=("frontend",)),
    Signal("browser-storage", groups=("client.storage",),
           content=_rx(r"localStorage|sessionStorage|indexedDB|BroadcastChannel|"
                       r"serviceWorker\.register|caches\.open"),
           tags=("frontend",)),
    Signal("service-worker", groups=("client.storage",),
           paths=("sw.js", "**/sw.js", "service-worker.js", "**/service-worker.*",
                  "**/serviceWorker.*"),
           tags=("frontend",)),
    Signal("browser-extension", groups=("client.storage", "client.messaging"),
           content_paths=("manifest.json", "**/manifest.json"),
           content=_rx(r'"manifest_version"|"content_scripts"|"web_accessible_resources"'),
           tags=("frontend",)),
    Signal("ui-redress", groups=("client.uiredress", "client.leaks"),
           content=_rx(r"frame-ancestors|X-Frame-Options|window\.open\(|"
                       r"location\.href\s*=|window\.opener|target=[\"']_blank"),
           tags=("frontend",)),
    Signal("server-template", ordinary=("Injection",),
           paths=("*.ejs", "**/*.ejs", "*.hbs", "**/*.hbs", "**/*.jinja", "**/*.j2",
                  "**/*.twig", "**/*.erb", "**/*.mustache"),
           tags=("template",)),
    Signal("template-escape-off", ordinary=("Injection",),
           content=_rx(r"\|\s*safe\b|mark_safe|render_template_string|autoescape\s*=\s*"
                       r"False|\{\{\{|triple_mustache|new Function\(|\beval\("),
           tags=("template",)),

    # --- AI and LLM. ---
    Signal("agent-instructions", groups=("ai.context", "ai.tool"), mandatory=True,
           paths=AGENT_INSTRUCTION_GLOBS, tags=("agent-config",)),
    Signal("mcp-config", groups=("ai.mcp", "ai.tool"), mandatory=True,
           paths=(".mcp.json", "mcp.json", "**/.mcp.json",
                  "**/claude_desktop_config.json"),
           tags=("agent-config",)),
    Signal("llm-sdk", groups=("ai.context", "ai.tool"),
           content=_rx(r"\bopenai\b|\banthropic\b|@anthropic-ai/sdk|litellm|langchain|"
                       r"llama[_-]index|@modelcontextprotocol|google-genai|@google/genai|"
                       r"generativeai|mistralai|\bcohere\b|\bollama\b|\bdeepseek\b|"
                       r"semantic-kernel|autogen|crewai|\bdspy\b|pydantic_ai|instructor"),
           tags=("llm",)),
    Signal("llm-tools", groups=("ai.tool", "ai.mcp"),
           content=_rx(r"tool_calls|function_call|tools\s*=\s*\[|@tool\b|server\.tool\(|"
                       r"role[\"']?\s*:\s*[\"']system|system_prompt|list_tools"),
           tags=("llm",)),
    Signal("vector-store", groups=("ai.context",),
           content=_rx(r"\bpinecone\b|chromadb|pgvector|\bfaiss\b|weaviate|\bqdrant\b|"
                       r"embeddings?\.create|similarity_search"),
           tags=("llm",)),

    # --- Protocols, RPC and messaging. ---
    Signal("proto-schema", groups=("proto.framing", "proto.rpc"),
           paths=("*.proto", "**/*.proto", "*.thrift", "**/*.thrift", "*.capnp",
                  "**/*.capnp", "*.avsc", "**/*.avsc", "*.avdl", "*.fbs"),
           tags=("rpc",)),
    Signal("graphql", groups=("proto.framing", "proto.rpc", "resource.compute"),
           paths=("*.graphql", "**/*.graphql", "*.gql", "**/*.gql"),
           tags=("rpc",)),
    Signal("rpc-lib", groups=("proto.rpc",),
           content=_rx(r"\bgrpc\b|\btonic\b|@grpc/|apollo-server|graphql-yoga|"
                       r"strawberry|graphene|gqlgen|ServerInterceptor|UnaryInterceptor"),
           tags=("rpc",)),
    Signal("messaging-lib", groups=("proto.broker", "proto.replay"),
           content=_rx(r"kafkajs|confluent_kafka|\bsarama\b|amqplib|\bpika\b|\bnats\b|"
                       r"bullmq|\bcelery\b|sidekiq|\btemporal\b|SQSClient|SNSClient|"
                       r"EventBridge|PubSub|\bXADD\b|\.subscribe\("),
           tags=("messaging",)),
    # "Untrusted producer treated as control plane" lives in the broker group, not
    # the RPC-identity group the design's routing table puts it in.
    Signal("webhook-path", groups=("proto.rpc", "proto.broker"),
           ordinary=("Cryptography and secrets",),
           paths=("**/webhook*/**", "**/webhook*.*", "**/callback*.*", "**/hooks/**"),
           tags=("webhook",)),
    Signal("webhook-signature", groups=("proto.rpc", "proto.broker"),
           ordinary=("Cryptography and secrets",),
           content=_rx(r"X-Hub-Signature|Stripe-Signature|X-Slack-Signature|\bsvix\b|"
                       r"constructEvent|compare_digest|hmac\.new|createHmac|timingSafeEqual"),
           tags=("webhook",)),
    Signal("raw-socket", groups=("proto.framing",),
           content=_rx(r"net\.createServer|socket\.bind|asyncio\.start_server|"
                       r"ServerSocket|SO_REUSEADDR|\.listen\("),
           tags=("socket",)),

    # --- Memory safety. ---
    Signal("native-source", groups=("memory.bounds", "memory.lifetime"),
           paths=("*.c", "**/*.c", "*.h", "**/*.h", "*.cc", "**/*.cc", "*.cpp",
                  "**/*.cpp", "*.cxx", "**/*.cxx", "*.hpp", "**/*.hpp", "*.hh",
                  "*.m", "**/*.m", "*.mm", "**/*.mm", "*.s", "*.S", "*.asm",
                  "*.pyx", "**/*.pyx", "*.pxd", "binding.gyp", "**/binding.gyp"),
           tags=("native",)),
    Signal("unsafe-rust", groups=("memory.ffi", "memory.bounds"),
           content_paths=("*.rs", "**/*.rs"),
           content=_rx(r"\bunsafe\b|extern\s+\"C\"|#\[no_mangle\]|from_raw_parts|"
                       r"transmute|ptr::|MaybeUninit"),
           tags=("native",)),
    Signal("cgo", groups=("memory.ffi",),
           content_paths=("*.go", "**/*.go"),
           content=_rx(r"import\s+\"C\"|unsafe\.(?:Pointer|Slice|String)"),
           tags=("native",)),
    Signal("ffi", groups=("memory.ffi", "memory.loader"),
           content=_rx(r"JNIEXPORT|\bctypes\b|\bcffi\b|\bdlopen\b|LoadLibrary|"
                       r"DllImport|NativeLibrary|System\.loadLibrary"),
           tags=("native",)),
    Signal("kernel", groups=("memory.kernel",),
           content=_rx(r"module_init|copy_from_user|copy_to_user|\bioctl\b|"
                       r"MODULE_LICENSE|__user\b"),
           tags=("native",)),

    # --- Data isolation and lifecycle. ---
    Signal("migrations", groups=("data.tenant", "data.export"),
           paths=("migrations/**", "**/migrations/**", "db/migrate/**",
                  "alembic/versions/**", "schema.prisma", "**/schema.prisma",
                  "*.sql", "**/*.sql", "schema.rb", "db/schema.rb",
                  "models/**", "**/models/**", "repositories/**", "**/repositories/**"),
           tags=("data",)),
    Signal("tenant-scope", groups=("data.tenant",),
           content=_rx(r"tenant_id|org_id|organization_id|account_id|owner_id|"
                       r"workspace_id|CREATE POLICY|ROW LEVEL SECURITY|unscoped|"
                       r"withoutGlobalScope|\.objects\.all\(|\.raw\(|session\.execute\("),
           tags=("data", "tenant")),
    Signal("soft-delete", groups=("data.deletion",),
           content=_rx(r"deleted_at|soft_delete|\bparanoid\b|tombstone|is_deleted|"
                       r"purge_after|retention_days"),
           tags=("data",)),
    Signal("signed-url", groups=("data.tenant", "cloud.storage"),
           content=_rx(r"presign|getSignedUrl|generate_presigned_url|SAS token|"
                       r"createSignedUrl"),
           tags=("data",)),
    Signal("search-index", groups=("data.derived",),
           content=_rx(r"elasticsearch|opensearch|\balgolia\b|meilisearch|typesense|"
                       r"\bsolr\b|reindex"),
           tags=("data",)),
    Signal("telemetry", groups=("data.derived",),
           content=_rx(r"\bsentry\b|\bsegment\b|mixpanel|posthog|amplitude|datadog|"
                       r"\bopentelemetry\b"),
           tags=("data",)),
    Signal("export-backup", groups=("data.export",),
           paths=("**/export*/**", "**/export*.*", "**/backup*.*", "**/restore*.*",
                  "**/import*.*", "**/purge*.*", "**/retention*.*"),
           tags=("data",)),

    # --- Desktop, mobile and local IPC. ---
    Signal("native-manifest", groups=("desktop.deeplink", "desktop.ipc"),
           paths=("AndroidManifest.xml", "**/AndroidManifest.xml", "Info.plist",
                  "**/Info.plist", "*.entitlements", "**/*.entitlements",
                  "src-tauri/**", "tauri.conf.json", "**/*.xcconfig"),
           tags=("desktop",)),
    Signal("electron", groups=("desktop.webview", "desktop.ipc"),
           content=_rx(r"BrowserWindow|webPreferences|nodeIntegration|contextBridge|"
                       r"ipcMain|ipcRenderer|contextIsolation|\bpreload\b"),
           tags=("desktop",)),
    Signal("webview-native", groups=("desktop.webview",),
           content=_rx(r"WKWebView|addJavascriptInterface|setAllowFileAccess|"
                       r"shouldOverrideUrlLoading|setJavaScriptEnabled|loadUrl\("),
           tags=("desktop",)),
    Signal("deep-link", groups=("desktop.deeplink",),
           content=_rx(r"intent-filter|CFBundleURLTypes|assetlinks\.json|"
                       r"apple-app-site-association|onNewIntent|openURL"),
           tags=("desktop",)),
    Signal("local-ipc", groups=("desktop.ipc", "desktop.helper"),
           content=_rx(r"NSXPCConnection|\bD-Bus\b|\bdbus\b|\bpolkit\b|AF_UNIX|"
                       r"\.sock\b|\\\\\.\\pipe|SMJobBless|launchd"),
           tags=("desktop",)),
    Signal("privileged-install", groups=("desktop.helper", "supply.release"),
           paths=("*.wxs", "**/*.wxs", "*.nsi", "**/*.nsi", "**/postinstall*",
                  "**/preinstall*", "*.policy", "**/*.policy", "**/sudoers*",
                  "**/*.service", "**/*.socket", "**/*.timer"),
           tags=("desktop",)),

    # --- Resource exhaustion: specific hits only, never on any config change. ---
    Signal("regex-dos", groups=("resource.compute",),
           content=_rx(r"re\.compile|new RegExp\(|regexp\.MustCompile"),
           content_all=(_rx(r"[+*]\)[+*?]|\{\d+,\}|req\.|request\.|params|\bbody\b|"
                            r"input|user"),),
           tags=("resource",)),
    Signal("decompression", groups=("resource.compute",),
           content=_rx(r"\bzlib\b|\bgzip\b|zipfile|tarfile|\binflate\b|\bbrotli\b|"
                       r"\bunzip\b|ZipFile|extractall|decompress"),
           tags=("resource",)),
    Signal("limits-config", groups=("resource.quota", "resource.accumulation"),
           content=_rx(r"bodyParser[^\n]*limit|MAX_CONTENT_LENGTH|client_max_body_size|"
                       r"max_request_size|pool_size|max_connections|\bpage_size\b|"
                       r"\bper_page\b|rate_?limit"),
           tags=("resource",)),
    Signal("retry-failure", groups=("resource.failure",),
           content=_rx(r"\bbackoff\b|max_retries|retry_count|retries:\s*\d|"
                       r"circuit_?breaker|panic!\(|process\.exit\("),
           tags=("resource",)),

    # --- Ordinary crypto and secret handling. ---
    Signal("crypto-primitives", ordinary=("Cryptography and secrets",),
           content=_rx(r"\bhashlib\b|\bhmac\b|\bCipher\b|\bAES\b|\bRSA\b|pbkdf2|"
                       r"\bbcrypt\b|\bscrypt\b|\bargon2\b|Math\.random|\brandint\b|"
                       r"\bmd5\b|\bsha1\b|createCipher|urandom|secrets\.token"),
           tags=("crypto",)),
    Signal("secret-material", ordinary=("Cryptography and secrets",),
           content=_rx(r"BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_|"
                       r"\bxox[abprs]-|api[_-]?secret|client_secret|"
                       r"(?:password|passwd|secret|token)\s*[:=]\s*[\"'][^\"']{8,}"),
           tags=("crypto", "secret")),
)

# Every group that some signal can select; used to build the excluded_blocks universe.
_GROUP_SIGNALS = {}
_SUPPLEMENT_SIGNALS = {}
_ORDINARY_SIGNALS = {}
for _sig in SIGNALS:
    for _g in _sig.groups:
        if _g not in COMPANION_GROUPS:
            raise RoutingError("signal %s names unknown group %s" % (_sig.id, _g))
        _GROUP_SIGNALS.setdefault(_g, []).append(_sig.id)
    for _g in _sig.supplements:
        if _g not in SUPPLEMENT_GROUPS:
            raise RoutingError("signal %s names unknown supplement group %s" % (_sig.id, _g))
        _SUPPLEMENT_SIGNALS.setdefault(_g, []).append(_sig.id)
    for _o in _sig.ordinary:
        _ORDINARY_SIGNALS.setdefault(_o, []).append(_sig.id)

for _key, _groups in SUPPLEMENT_FOR_CI_CLASS.items():
    if _key not in dict(COMPANION_GROUPS["supply.ci"][2]):
        raise RoutingError("%s is not a CI class of supply.ci" % _key)
    for _g in _groups:
        if _g not in SUPPLEMENT_GROUPS:
            raise RoutingError("unknown supplement group %s for CI class %s" % (_g, _key))


def block_id(companion_file, name):
    """A ledger block reference: file plus the exact class or heading text."""
    return "%s#%s" % (companion_file, name)


def _group_entry(group_key):
    """One row of either group table. The supplement is addressed the same way as a companion."""
    entry = COMPANION_GROUPS.get(group_key) or SUPPLEMENT_GROUPS.get(group_key)
    if entry is None:
        raise RoutingError("no such block group: %r" % (group_key,))
    return entry


def group_classes(group_key):
    """Block ids for every class in one companion or supplement group."""
    companion, _heading, classes = _group_entry(group_key)
    return tuple(block_id(companion, name) for name, _token in classes)


def group_block(group_key):
    """Block id of the group heading itself, used when the group is excluded."""
    companion, heading, _classes = _group_entry(group_key)
    return block_id(companion, heading)


def is_supplement_block(block):
    """Is this block reference the action's own companion rather than vendored skill text?"""
    return block.startswith(SUPPLEMENT + "#")


def supplement_block_names():
    """Every block the supplement must contain: the three fixed sections and every class."""
    names = [block_id(SUPPLEMENT, fixed) for fixed in FIXED_BLOCKS]
    for group in SUPPLEMENT_GROUPS:
        names.extend(group_classes(group))
    return tuple(names)


def supplement_blocks_for(blocks):
    """Supplement class blocks implied by an already-selected set of vendored blocks.

    The ledger builds its CI coverage units from the vendored CI class names alone, so a
    caller holding only a unit's blocks still has to be able to reach the supplement; this
    is that bridge, and it is why nothing downstream has to carry a second block list.
    """
    selected = set(blocks)
    groups, ci_classes = [], dict(COMPANION_GROUPS["supply.ci"][2])
    for name in ci_classes:
        if block_id(SUPPLY, name) not in selected:
            continue
        for group in SUPPLEMENT_FOR_CI_CLASS.get(name, ()):
            if group not in groups:
                groups.append(group)
    # An agent running in CI is only in scope when both halves are: the workflow classes and
    # the AI classes. Either alone is an ordinary CI change or an ordinary agent change.
    if groups and any(b.startswith(AI + "#") for b in selected):
        groups.append("gha.agents")
    out = []
    for group in SUPPLEMENT_GROUPS:
        if group in groups:
            out.extend(group_classes(group))
    return tuple(out)


_CONTROL_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))


def sanitize(text, limit=MAX_EVIDENCE_CHARS):
    """Make a repo-derived fragment safe to display: no control, format or bidi bytes.

    Path and diff text are attacker-chosen. This is for the `evidence` field only;
    the raw path stays in `path` because the ledger and the git tools need it byte
    for byte, and the caller is responsible for framing it as untrusted data.
    """
    kept = [c for c in text if unicodedata.category(c) not in _CONTROL_CATEGORIES]
    out = re.sub(r"\s+", " ", "".join(kept)).strip()
    return out[:limit] + "..." if len(out) > limit else out


def parse_patch(patch):
    """Split a unified diff into (added_lines, removed_lines), without the +/- marker."""
    added, removed = [], []
    for line in (patch or "").splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return added, removed


def _line_list(value):
    """A list of line strings, or [] for anything else (counts, None, a string)."""
    if isinstance(value, (list, tuple)):
        return [str(line) for line in value]
    return []


def normalize_change(entry):
    """Accept a GitHub files-API record or a plain dict and return the routing shape."""
    path = entry.get("path") or entry.get("filename") or ""
    if not path:
        raise RoutingError("changed file has no path: %r" % (sorted(entry),))
    previous = entry.get("previous_path") or entry.get("previous_filename") or ""
    status = (entry.get("status") or "modified").strip().lower()
    # `added` means a line count in a git numstat record and the added lines themselves
    # in a routing record. Only a sequence is line text; a count falls through to the
    # patch, which is what a caller holding numstat data has.
    added = _line_list(entry.get("added")) or _line_list(entry.get("added_lines"))
    removed = _line_list(entry.get("removed")) or _line_list(entry.get("removed_lines"))
    if not added and not removed and entry.get("patch"):
        added, removed = parse_patch(entry["patch"])
    return {"path": path, "previous_path": previous, "status": status,
            "added": added, "removed": removed,
            "changed_lines": len(added) + len(removed)}


def is_doc(path):
    """Docs carry no code signal -- except agent-instruction files, which steer agents."""
    if matches_any(path, AGENT_INSTRUCTION_GLOBS):
        return False
    return matches_any(path, DOC_GLOBS)


def is_code(path):
    dot = path.rfind(".")
    return dot > 0 and path[dot:].lower() in CODE_EXTS


@dataclass(frozen=True)
class Routing:
    """The pre-filter result. Reasons are structured so the prompt builder can frame them."""
    ordinary_blocks: tuple
    companion_blocks: tuple
    companions: tuple
    selections: tuple          # ({block, companion, group, mandatory, reasons}, ...)
    excluded: tuple            # ({block, companion, group, reason}, ...)
    path_tags: dict            # path -> sorted tuple of tags
    self_modification: bool
    stats: dict
    pre_filter_note: str = PRE_FILTER_NOTE
    # The action-authored supplement is kept in its own fields, in the same shapes. It is not
    # a companion: it takes no per-hunter companion slot, it has no HUNTING.md:7 domain rank,
    # and a consumer that walks `companions` or `selections` expecting vendored files must not
    # meet it there. Its unselected groups do go into `excluded`, because a reason for every
    # considered block is the ledger's contract (RECONNAISSANCE.md:135), not the skill's.
    supplement_blocks: tuple = ()
    supplement_selections: tuple = ()
    supplements: tuple = ()

    def reasons_for(self, block):
        for sel in self.selections + self.supplement_selections:
            if sel["block"] == block:
                return sel["reasons"]
        return ()

    def companion_order(self):
        """Companions ranked by HUNTING.md:7, for clustering under the per-hunter cap."""
        return tuple(sorted(self.companions, key=lambda f: DOMAIN_PRIORITY.index(f)))


def _content_hits(sig, change):
    """Yield (side, line_no, line) for each diff line this signal's regexes match."""
    if sig.content is None and not sig.content_all:
        return
    if sig.content_paths and not (
            matches_any(change["path"], sig.content_paths)
            or (change["previous_path"]
                and matches_any(change["previous_path"], sig.content_paths))):
        return
    for side in sig.sides:
        for index, line in enumerate(change[side], start=1):
            if sig.content is not None and not sig.content.search(line):
                continue
            if any(not rx.search(line) for rx in sig.content_all):
                continue
            yield side, index, line


def _path_hits(sig, change):
    if not sig.paths:
        return ()
    hits = []
    if matches_any(change["path"], sig.paths):
        hits.append(("path", change["path"]))
    # A rename out of a routed directory is itself a signal: the old location is
    # what carried the control.
    if change["previous_path"] and matches_any(change["previous_path"], sig.paths):
        hits.append(("previous_path", change["previous_path"]))
    return tuple(hits)


def _reason(sig, change, kind, side, evidence, line=None):
    return {"signal": sig.id, "kind": kind, "side": side, "path": change["path"],
            "previous_path": change["previous_path"], "status": change["status"],
            "line": line, "evidence": sanitize(evidence),
            "control_removed": side == "removed" or change["status"] == "removed"}


def _add_hit(hits, key, reasons, mandatory):
    slot = hits.setdefault(key, {"mandatory": False, "reasons": []})
    slot["reasons"].extend(reasons)
    slot["mandatory"] |= mandatory


def _match_signals(changes):
    """Run every signal over every change.

    Returns (group hits, supplement group hits, ordinary hits, tags).
    """
    group_hits, supplement_hits, ordinary_hits = {}, {}, {}
    tags = {}
    for change in changes:
        for sig in SIGNALS:
            reasons = []
            for side, value in _path_hits(sig, change):
                reasons.append(_reason(sig, change, "path", side, value))
            for side, line_no, line in _content_hits(sig, change):
                if sig.requires_path_match and not _path_hits(sig, change):
                    continue
                reasons.append(_reason(sig, change, "content", side, line, line_no))
            if not reasons:
                continue
            tags.setdefault(change["path"], set()).update(sig.tags)
            for group in sig.groups:
                _add_hit(group_hits, group, reasons, sig.mandatory)
            for group in sig.supplements:
                _add_hit(supplement_hits, group, reasons, sig.mandatory)
            for name in sig.ordinary:
                _add_hit(ordinary_hits, name, reasons, sig.mandatory)
    return group_hits, supplement_hits, ordinary_hits, tags


def _always_on(changes):
    """Ordinary blocks the parent adds regardless of any signal (design 4.5)."""
    out = {}

    def add(name, reason):
        out.setdefault(name, []).append(reason)

    add("Obvious things", "always on: every run")
    add("Chained vulnerabilities and trust boundaries", "always on: every run")
    non_doc = [c for c in changes if not is_doc(c["path"])]
    if non_doc:
        for name in ("Injection", "Access control", "Resource and file handling",
                     "Cryptography and secrets"):
            add(name, "non-documentation files changed")
    app_lines = sum(c["changed_lines"] for c in changes if is_code(c["path"]))
    if app_lines > 50:
        for name in ("Business logic", "Feature abuse and data leakage", "Wildcard"):
            add(name, "application code changed with %d changed lines (>50)" % app_lines)
    return out


def _self_modification(changes, workflow_ref, action_slugs):
    """Does this PR change the reviewer itself? Deterministic, never model-decided."""
    ref_path = ""
    if workflow_ref:
        # GITHUB_WORKFLOW_REF is "owner/repo/.github/workflows/x.yml@refs/heads/main".
        without_ref = workflow_ref.split("@", 1)[0]
        parts = without_ref.split("/", 2)
        ref_path = parts[2] if len(parts) == 3 else without_ref
    slug_rx = None
    if action_slugs:
        slug_rx = re.compile("|".join(re.escape(s) for s in action_slugs))
    for change in changes:
        if ref_path and ref_path in (change["path"], change["previous_path"]):
            return True
        if slug_rx is None or not matches_any(change["path"], CI_GLOBS):
            continue
        for side in ("added", "removed"):
            if any(slug_rx.search(line) for line in change[side]):
                return True
    return False


def route(changed_files, workflow_ref="", action_slugs=("ai-pr-review",)):
    """Map a PR's changed files onto companion blocks and ordinary attack classes.

    Returns a Routing. Selections carry structured reasons; every companion group and
    ordinary class that was considered and not selected appears in `excluded` with a
    parent-authored reason, which is what the ledger's `excluded_blocks` records.
    """
    changes = [normalize_change(e) for e in changed_files]
    group_hits, supplement_hits, ordinary_hits, tags = _match_signals(changes)
    always = _always_on(changes)

    # A pull request that edits the reviewer itself always gets the CI classes and the
    # platform blocks behind them, even when no path or diff line matched a signal. The
    # reason goes in front, because a block keeps only its first MAX_REASONS_PER_BLOCK.
    self_mod = _self_modification(changes, workflow_ref, action_slugs)
    if self_mod:
        reason = {"signal": "self-modification", "kind": "policy", "side": "policy",
                  "path": "", "previous_path": "", "status": "", "line": None,
                  "control_removed": False,
                  "evidence": "this PR changes the reviewer's own workflow or action"}
        for hits, key in ((group_hits, "supply.ci"), (supplement_hits, "gha.trigger"),
                          (supplement_hits, "gha.identity")):
            slot = hits.setdefault(key, {"mandatory": False, "reasons": []})
            slot["reasons"].insert(0, reason)
            slot["mandatory"] = True

    selections, ordinary_blocks = [], []
    for name, token in ORDINARY_CLASSES:
        reasons, mandatory = [], False
        for text in always.get(name, ()):
            reasons.append({"signal": "always-on", "kind": "policy", "side": "policy",
                            "path": "", "previous_path": "", "status": "",
                            "line": None, "evidence": text, "control_removed": False})
            mandatory = True
        hit = ordinary_hits.get(name)
        if hit:
            reasons.extend(hit["reasons"])
            mandatory |= hit["mandatory"]
        if not reasons:
            continue
        block = block_id(ATTACK, name)
        ordinary_blocks.append(block)
        selections.append({"block": block, "companion": ATTACK, "group": None,
                           "token": token, "mandatory": mandatory,
                           "reasons": tuple(reasons[:MAX_REASONS_PER_BLOCK]),
                           "reason_count": len(reasons)})

    companion_blocks, companions = [], []
    for group in sorted(group_hits, key=_group_sort_key):
        companion, _heading, classes = COMPANION_GROUPS[group]
        hit = group_hits[group]
        if companion not in companions:
            companions.append(companion)
        for name, token in classes:
            block = block_id(companion, name)
            companion_blocks.append(block)
            selections.append({"block": block, "companion": companion, "group": group,
                               "token": "%s-%s" % (group, token),
                               "mandatory": hit["mandatory"],
                               "reasons": tuple(hit["reasons"][:MAX_REASONS_PER_BLOCK]),
                               "reason_count": len(hit["reasons"])})
    for companion in companions:
        for fixed in FIXED_BLOCKS:
            companion_blocks.append(block_id(companion, fixed))

    supplement_blocks, supplement_selections = [], []
    for group in SUPPLEMENT_GROUPS:                   # declaration order is file order
        hit = supplement_hits.get(group)
        if hit is None:
            continue
        companion, _heading, classes = SUPPLEMENT_GROUPS[group]
        for name, token in classes:
            block = block_id(companion, name)
            supplement_blocks.append(block)
            supplement_selections.append(
                {"block": block, "companion": companion, "group": group,
                 "token": "%s-%s" % (group, token), "mandatory": hit["mandatory"],
                 "reasons": tuple(hit["reasons"][:MAX_REASONS_PER_BLOCK]),
                 "reason_count": len(hit["reasons"])})
    supplements = (SUPPLEMENT,) if supplement_blocks else ()
    if supplements:
        supplement_blocks.extend(block_id(SUPPLEMENT, fixed) for fixed in FIXED_BLOCKS)

    excluded = _excluded_blocks(set(group_hits), {s["block"] for s in selections},
                                set(supplement_hits))

    stats = {"changed_files": len(changes),
             "doc_only": bool(changes) and all(is_doc(c["path"]) for c in changes),
             "changed_lines": sum(c["changed_lines"] for c in changes),
             "code_files": sum(1 for c in changes if is_code(c["path"])),
             "deleted_files": sum(1 for c in changes if c["status"] == "removed"),
             "renamed_files": sum(1 for c in changes if c["status"] == "renamed"),
             "signals_fired": sorted({r["signal"]
                                      for s in selections + supplement_selections
                                      for r in s["reasons"]})}
    return Routing(ordinary_blocks=tuple(ordinary_blocks),
                   companion_blocks=tuple(companion_blocks),
                   companions=tuple(companions),
                   selections=tuple(selections),
                   excluded=excluded,
                   path_tags={p: tuple(sorted(t)) for p, t in sorted(tags.items())},
                   self_modification=self_mod,
                   stats=stats,
                   supplement_blocks=tuple(supplement_blocks),
                   supplement_selections=tuple(supplement_selections),
                   supplements=supplements)


def _group_sort_key(group):
    companion = COMPANION_GROUPS[group][0]
    return (DOMAIN_PRIORITY.index(companion), group)


def _excluded_blocks(selected_groups, selected_blocks, selected_supplements=()):
    """Considered-but-unselected blocks, with a parent-authored reason each.

    Excluding at group granularity keeps the list to a few dozen entries instead of
    ~160. A group heading is a legal block reference (RECONNAISSANCE.md:94 accepts a
    heading, and the heading text can never collide with a class name), so a group and
    its classes are never both listed.
    """
    out = []
    for group in sorted(COMPANION_GROUPS, key=_group_sort_key):
        if group in selected_groups:
            continue
        signals = _GROUP_SIGNALS.get(group, ())
        reason = ("no changed path or diff line matched the pre-filter signals for this "
                  "group (%s)" % ", ".join(sorted(signals))) if signals else (
            "no pre-filter signal routes to this group; select it only from a boundary "
            "reconnaissance finds in source")
        out.append({"block": group_block(group), "companion": COMPANION_GROUPS[group][0],
                    "group": group, "reason": reason})
    for group in SUPPLEMENT_GROUPS:
        if group in selected_supplements:
            continue
        out.append({"block": group_block(group), "companion": SUPPLEMENT, "group": group,
                    "reason": "no changed path or diff line matched the pre-filter signals "
                              "for this group (%s); this block is the action's own companion "
                              "and not security-audit skill text"
                              % ", ".join(sorted(_SUPPLEMENT_SIGNALS.get(group, ())))})
    for name, _token in ORDINARY_CLASSES:
        block = block_id(ATTACK, name)
        if block in selected_blocks:
            continue
        signals = _ORDINARY_SIGNALS.get(name, ())
        reason = ("not always-on for this change set and no signal matched (%s)"
                  % ", ".join(sorted(signals))) if signals else (
            "not always-on for this change set")
        out.append({"block": block, "companion": ATTACK, "group": None,
                    "reason": reason})
    return tuple(out)


def routed_ci_classes(routing):
    """CI class block ids, for the per-workflow coverage-floor units (design 4.5 step 3c)."""
    wanted = set(group_classes("supply.ci"))
    return tuple(b for b in routing.companion_blocks if b in wanted)


def floor_paths(routing, changed_files):
    """Non-doc changed paths with the ordinary class each one needs at the floor.

    Design 4.5 step 3(d): every changed non-doc file gets an Injection unit, plus
    Access control where routing tagged it auth-relevant. Returned as data so the
    ledger builder owns unit construction.
    """
    out = []
    for entry in changed_files:
        change = normalize_change(entry)
        if is_doc(change["path"]):
            continue
        tags = set(routing.path_tags.get(change["path"], ()))
        classes = [block_id(ATTACK, "Injection")]
        if tags & {"auth", "route", "tenant"}:
            classes.append(block_id(ATTACK, "Access control"))
        out.append({"path": change["path"], "status": change["status"],
                    "previous_path": change["previous_path"],
                    "tags": tuple(sorted(tags)), "attack_classes": tuple(classes)})
    return tuple(out)


def routing_digest(routing):
    """Stable digest of the routing decision, for run-metadata and cross-push diffing."""
    payload = "\n".join(list(routing.ordinary_blocks) + list(routing.companion_blocks)
                        + list(routing.supplement_blocks))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
