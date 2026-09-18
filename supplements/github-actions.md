# GitHub Actions and CI Identity Hunting

> **Action-authored companion. Not part of Cloudflare's `security-audit` skill, and not
> to be attributed to it.** The vendored skill under `vendor/security-audit/` is MIT
> Cloudflare work and is read-only here; it contains no occurrence of
> `pull_request_target`, `GITHUB_TOKEN`, `${{ github.event.* }}`, `workflow_run`,
> `GITHUB_ENV`, `id-token` or `self-hosted`. `SUPPLY-CHAIN-AND-RELEASE.md` names the
> generic classes — *Untrusted code in a privileged workflow*, *Workflow command and
> expression confusion*, *Cache, artifact, and workspace trust mixing*, *Automation
> identity overreach* — and this file supplies the GitHub-specific boundaries, defaults
> and results they need on this platform. It extends that file, never replaces it, and
> never lowers its evidence bar.

#### When to use this file

Reach for this file when the target contains `.github/workflows/**`, a composite or
JavaScript `action.yml`, a reusable workflow, a self-hosted runner registration, or any
CI job that a person outside the repository's write set can cause to run. The important
data flow is *contributor-controlled ref, event payload or artifact → a workflow the
contributor cannot review → a token, secret, runner, cache or release the contributor
does not hold*.

Use it alongside `SUPPLY-CHAIN-AND-RELEASE.md`, not instead of it. Use
`CLOUD-AND-DEPLOYMENT.md` for what a cloud role does once OIDC has handed it over, and
`AI-AND-LLM.md` for an agent's own tool and context boundaries once CI has reached it.
Split large targets by trigger, expression handling, cross-run state, identity, and
third-party building blocks.

## Core discipline (include in every agent prompt for this domain)

```
- A workflow is authorization code. Before anything else, establish four facts from source: which event triggers it, whose commit the runner executes, which secrets and token scopes exist in that job, and what the job may write.
- On this platform the definition that runs is not always the definition in the diff. `pull_request`, `pull_request_target` and `workflow_run` each resolve the workflow file differently; state which one applies before claiming a change takes effect.
- A missing hardening measure is not a finding. Least-privilege `permissions:`, a pinned action, a narrower cache key: each is a hardening note unless you can name a lower-trust principal who reaches a boundary because it is missing.
- Name the principal precisely. "Anyone who can open a pull request" and "anyone with write access" are different attackers with different results; a defect only reachable by a repository writer is usually not a boundary crossing, because a writer can already push a workflow.
- Secrets are not readable from a workflow's logs by default, but a job that can run arbitrary contributor code in the same job as a secret has already lost it. Trace the secret to the step, not to the workflow.
- CI defaults are version- and setting-dependent (default `permissions:`, fork approval, cache scope, artifact retention). Repository and organization settings are not in source: an argument that rests on one is `needs_validation` with the exact setting an owner must read.
- Use `confirmed` only for an in-repo control-flow failure with bounded local evidence. Use `needs_validation` for runner configuration, branch protection, environment approval, organization policy, or registry and cloud trust-policy facts that source cannot show.
```

## Trigger and checkout attack classes (subagent_type: `general`)

**Privileged trigger executing contributor-controlled code**
A `pull_request_target`, `workflow_run`, `issue_comment`, `discussion_comment` or
`schedule`-plus-ref workflow runs with secrets and a write token, and some step executes
code the pull-request author controls: a checkout of the head ref followed by a build,
install, test, lint, formatter, codegen or `npm`/`pip` lifecycle script; a `Makefile`
target; a devcontainer; or an action resolved from the PR tree. GitHub's documentation is
explicit that for `pull_request_target` "the workflow file and checkout commit will
always be taken from the repository base", which is precisely why adding `ref:
${{ github.event.pull_request.head.sha }}` re-introduces the attacker's code under the
privileged context. Establish the trigger, the checked-out ref, any approval or label
gate, the environment protection rules, and one concrete step that runs head-controlled
code. The result to demonstrate is a secret, write token, deployment or runner reached by
a principal with no write access.

**Approval and label gates that do not bind a commit**
A maintainer gate exists (a label, an `environment:` approval, a "first-time contributor"
prompt) but authorization is not bound to one head SHA, so a later push inherits it.
Check whether the workflow re-reads `head.sha` at run time, whether the label survives
`synchronize`, and whether the approved and executed commits can differ. The result is
unreviewed code executing under an approval given for other code.

**`workflow_run` and artifact re-entry**
A privileged `workflow_run` workflow consumes the output of an unprivileged one:
downloading its artifact, reading a PR number or ref out of it, checking that ref out, or
echoing its contents. The unprivileged run is contributor-controlled, so every byte it
produces is attacker input crossing into a privileged job. Name the producing workflow,
the consumed value, and the privileged action it steers.

## Expression and environment attack classes (subagent_type: `general`)

**Untrusted `${{ }}` interpolation into a shell or script**
GitHub expands `${{ }}` *before* the shell sees the script, so an attacker-controlled
context field is not a variable — it is source code spliced into the step. The
contributor-controlled fields include `github.event.pull_request.title`, `.body`,
`.head.ref`, `.head.label`, `.head.repo.*`, `github.event.issue.title`/`.body`,
`github.event.comment.body`, `github.event.review.body`, `github.event.discussion.*`,
`github.head_ref`, `github.event.commits[*].message`, `github.event.head_commit.*`, and
any `steps.*.outputs.*` derived from them. The same applies inside
`actions/github-script`'s `script:`, `run:` in a composite action, and `with:` inputs of
an action that later interpolates them. Establish the writer of the field, the step that
interpolates it, and code execution on the runner in a job that holds a secret or write
token. A branch name containing a shell metacharacter that only breaks the build is a
correctness bug, not a finding.

**`GITHUB_ENV`, `GITHUB_OUTPUT` and `GITHUB_PATH` injection**
A step appends an attacker-influenced value to one of the environment files. Because
these are line-oriented files, a value containing a newline writes an *additional*
variable of the attacker's choosing, and a multi-line delimiter that the attacker can
guess or forge lets them close the block early. The high-value targets are
`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`, `PERL5OPT`, `PYTHONSTARTUP`, `GIT_*`, and any
variable a later privileged step uses as a path, a ref or a command. `GITHUB_PATH` is
stronger still: one line prepends an attacker-writable directory to `PATH`, so the next
step's `node`, `npm` or `python` is theirs. Establish the untrusted value, the write, and
a later step in the same job that consumes the injected variable or shadowed binary.

**Composite-action and reusable-workflow input laundering**
An input arrives at a composite action or reusable workflow already interpolated, so the
callee's own quoting cannot help, or a `secrets: inherit` call hands the callee every
secret the caller holds. Compare the caller's expression, the callee's `run:` blocks, and
which secrets cross the call. Trace at least one untrusted caller.

## Cross-run state attack classes (subagent_type: `general`)

**Cache poisoning across a trust boundary**
GitHub scopes caches by branch, and a cache written on a pull-request branch is readable
from that PR's runs, while a cache written on the default branch is readable from *every*
branch. The dangerous direction is a lower-trust job writing an entry a higher-trust job
restores and then executes: `actions/cache`, `setup-node`/`setup-python`/`setup-go` with
`cache:` enabled, a Docker layer cache, a compiler or bundler cache, or any restore path
that lands executable content. Under `pull_request_target` the cache scope is the base
branch's, which is the crossing to look for. Name the writing principal, the cache key
and restore key, and the higher-trust step that runs or ships the restored bytes.

**Artifact trust mixing between runs**
An artifact is consumed by name without proving who produced it. The producing run's
event, workflow path, repository and head repository are all available from the Actions
API, and none of them are checked by `actions/download-artifact` on its own. Unpacking is
a second boundary: absolute paths, `..` traversal, symlinks and compression bombs inside
a downloaded archive all reach the consuming runner's filesystem. Establish a producer a
lower-trust principal controls, the consumer that trusts it, and what the consumed
content decides or executes.

## Identity and dependency attack classes (subagent_type: `general`)

**Token permission overreach with a reachable action**
`permissions:` is per-job. Look for `write-all`, a workflow-level block that a
secret-holding job inherits, `contents: write` beside code the contributor influences, or
`actions: write` (which can cancel or re-run other workflows, including a required
check). Missing least privilege is a hardening note on its own — `SUPPLY-CHAIN-AND-
RELEASE.md` says so directly. It becomes a finding when an untrusted input selects the
resource the excess scope acts on, or when contributor-controlled code runs in the same
job as the token.

**`id-token: write` and cloud trust-policy binding**
A job that can mint an OIDC token exchanges it for a cloud role. The security of that
exchange lives in the trust policy's subject claim, not in the workflow. A policy that
matches `repo:org/name:*`, or `ref:refs/heads/*`, accepts a token minted from any branch
or any pull request of that repository — so any principal who can cause a job with
`id-token: write` to run gets the role. Read the workflow's `environment:` and ref
alongside the claim the policy pins, and hand to `CLOUD-AND-DEPLOYMENT.md` from there.
When the trust policy is not in the repository, this is `needs_validation` naming the
exact claim an owner must read.

**Unpinned or mutable `uses:`**
An action referenced by tag, branch or major-version alias resolves to whatever that ref
points at when the job runs, and the publisher, or anyone who compromises them, can move
it. GitHub's hardening guidance is to pin third-party actions to a full-length commit
SHA. A floating tag alone is a hardening note; it becomes a finding when the action runs
in a job holding secrets, a write token or release authority, or when the reference
resolves through an attacker-influenceable path (a fork, a deleted-and-recreated
namespace, a `docker://` tag, a `uses:` interpolated from an untrusted context field, or
an action loaded from the PR tree under a privileged trigger).

**Self-hosted runner reuse**
A self-hosted runner does not start clean. State left by one job — a working directory,
a global package cache, `~/.npmrc`, `~/.docker/config.json`, a running daemon, a modified
`PATH`, a background process — is visible to the next. GitHub's own documentation warns
against using self-hosted runners with public repositories for this reason. The finding
shape is: a job a lower-trust principal can trigger writes state on the runner, and a
later job of a different trust level reads or executes it. Name both jobs and the
persisted path. A self-hosted runner with no public or fork-reachable trigger is a
hardening note.

## Agents in CI (subagent_type: `general`)

**An AI reviewer or agent reachable by pull-request content**
CI increasingly runs an agent over the diff: a review bot, a triage bot, an
autofix or "apply this suggestion" job, or a coding agent invoked from a comment. Three
distinct boundaries matter and must be separated. (1) *Reach*: does pull-request text —
diff content, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`, `.github/copilot-
instructions.md`, a test fixture, a lockfile comment — enter the agent's context? (2)
*Capability*: what can the agent do from there — run shell, install dependencies, read
the job's environment, push a commit, post as the bot, approve a review, or call an MCP
server? (3) *Sink*: where does its output go without a deterministic check — a `run:`
block, a commit, a comment rendered as Markdown, a `GITHUB_OUTPUT` line, a merge? A
prompt telling the model to ignore injected instructions is not a control
(`AI-AND-LLM.md` Core discipline). The finding is the code path from (1) to (3), never the
injected text by itself. Loading a skill, agent definition or MCP configuration from the
pull-request tree under a privileged trigger is code execution, and should be reported as
such rather than as a prompt-injection finding.

## Universal moves (apply across the above)

- Build one table before hunting: every workflow file × its events × the checked-out ref
  × the secrets in scope × each job's `permissions:` × its runner label. Most findings in
  this domain are a single row where the ref is contributor-controlled and the secrets
  column is not empty.
- Walk backward from each secret, `id-token: write` job, `contents: write` job,
  self-hosted label and release step to every principal who can cause it to run.
- Diff the trusted and untrusted event paths for the *same* logic. A repository usually
  has a `pull_request` copy and a `pull_request_target` copy of a similar job; the defect
  is normally one step that exists in only one of them.
- Treat every persisted channel — cache, artifact, runner filesystem, environment file,
  step output, branch, tag, PR comment — as a crossing to be labelled with its writer's
  trust level and its reader's.
- Read removals as carefully as additions. Deleting a `permissions:` block, a
  `persist-credentials: false`, an `if:` guard or an approval gate is a control removal,
  and the diff shows it only on the left side.

## Validation rules (apply before reporting ANY finding here)

1. Name the lower-trust principal in GitHub's own terms (any GitHub user opening a pull
   request from a fork; any user who can comment; a contributor with write access; a
   compromised third-party action publisher). Name the crossed boundary and the concrete
   result: a specific secret, a token scope, a cloud role, a release, a runner, or a
   protected branch.
2. State which workflow definition executes for the claimed event, and from which ref.
   A claim about a file in the diff is wrong if that event resolves the definition from
   the base or default branch.
3. Show the untrusted value's path end to end: the event field or artifact that carries
   it, every step that passes it on, and the exact expansion, file write or execution
   that consumes it. A field that is merely present in the payload is not reachable.
4. A missing hardening measure with no reachable boundary violation is a hardening note,
   not a finding. This applies to unpinned actions, broad `permissions:`, absent
   `harden-runner`, absent concurrency limits and unscoped cache keys alike.
5. Repository, organization and enterprise settings, branch protection, environment
   approvals, runner-group scoping and cloud trust policies are not source-visible.
   Return `needs_validation` naming the exact setting and where an owner reads it, and do
   not assume a platform default that is not in the repository.
6. Keep local validation bounded: a fixture repository you own, a dummy secret marker, a
   local runner, and no real deployment, registry or release namespace. Never trigger a
   workflow on someone else's repository to test a claim.
7. Return `confirmed` only with a complete source-visible path and a meaningful result.
   Otherwise return `needs_validation` with the precise trigger, runner, permission,
   setting or trust-policy fact that would settle it.

## References (platform behaviour these classes rest on)

- Events that trigger workflows — `pull_request_target`, `workflow_run`, `issue_comment`:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>
- Security hardening for GitHub Actions (untrusted input, pinning actions to a full-length
  commit SHA, self-hosted runner risk):
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- Automatic token authentication — `GITHUB_TOKEN` and `permissions:`:
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication>
- Workflow commands and environment files — `GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_PATH`:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#environment-files>
- Cache restrictions and branch scoping:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#restrictions-for-accessing-a-cache>
- OpenID Connect hardening and subject claims:
  <https://docs.github.com/en/actions/concepts/security/openid-connect>
- Self-hosted runner security:
  <https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners>
- GitHub Security Lab, "Preventing pwn requests":
  <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>
- GitHub Security Lab, "Untrusted input":
  <https://securitylab.github.com/resources/github-actions-untrusted-input/>
- GitHub Security Lab, "How to trust your building blocks":
  <https://securitylab.github.com/resources/github-actions-building-blocks/>
