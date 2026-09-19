# AI PR Review (DeepSeek)

A composite GitHub Action that reviews a pull request with
[PR-Agent](https://github.com/The-PR-Agent/pr-agent) running on DeepSeek, then runs a second
pass that tries to refute each finding against the full diff. Only findings that survive are
posted; refuted ones are listed in a collapsed section.

Each run posts the review as a new PR comment, below the commits it reviewed, and hides the
earlier reviews as outdated. Only the latest review is expanded; older ones stay one click away.

There is a second, separate reviewer in this repository: see
[AI security review](#ai-security-review) for the skill-based security pass.

## Usage

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  review:
    runs-on: ubuntu-latest
    concurrency:
      group: ai-review-${{ github.event.pull_request.number }}
      cancel-in-progress: true
    steps:
      - uses: SirLouen/ai-pr-review@v1
        with:
          pr-number: ${{ github.event.pull_request.number }}
          deepseek-api-key: ${{ secrets.DEEPSEEK_API_KEY }}
          github-token: ${{ github.token }}
```

| Input | Default | |
|---|---|---|
| `pr-number` | – | Pull request to review |
| `publish` | `true` | Anything other than `true` is a dry run |
| `deepseek-api-key` | – | DeepSeek API key |
| `github-token` | – | Use `github.token`; reviews are then posted by `github-actions[bot]` |
| `model` | `deepseek-flash` | DeepSeek model name |

Per-repository review guidance can be added with a `.pr_agent.toml` in the reviewed
repository, for example `[pr_reviewer] extra_instructions = "..."`.

Put `concurrency` on the job rather than the workflow. At workflow level, a run whose job is
skipped (for example, a `labeled` event for a different label) still cancels an in-progress
review.

## Security notes

- The action never checks out or executes code from the pull request; PR-Agent reads the diff
  through the GitHub API.
- Pass `github.token`, not a personal access token. A classic PAT reaches every repository its
  account can access, so a leak from one repository exposes all of them.
- Every Python dependency is pinned with hashes in `requirements.lock`. Regenerate it
  deliberately when upgrading:
  `echo "pr-agent==<version>" | uv pip compile - --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes -o requirements.lock`
- Pull requests from forks do not receive repository secrets; run it only for same-repository
  pull requests.
- The PR diff is sent to DeepSeek.

---

## AI security review

A second, independent action that runs Cloudflare's `security-audit` skill over a pull
request as a **security** reviewer. It is not the general reviewer above with a security
prompt: it has its own coverage ledger, its own evidence bar, and its own report.

Enable it with the example workflow in
[`.github/workflows/security-review.example.yml`](.github/workflows/security-review.example.yml).

### What it does

A run reads the pull request's diff and the source around it, and produces **ranked
leads**: places in the changed code where a boundary looks crossable, each with the
specific local test that would settle it. It routes the changed files onto the skill's
attack classes, seeds a coverage unit for every changed non-documentation file, runs one
hunting wave, then hands every candidate to a *fresh* verifier that never sees the
hunter's reasoning. Every unit the run did not reach is printed with the reason.

**P1 / P2 / P3 on a lead is review order, not severity.** It is the skill's hunting order:
what to look at first. It says nothing about impact.

### Why nothing is ever "confirmed"

The action never executes pull-request code. It has no sandbox, no runtime, no worktree —
it fetches git objects into a bare repository and reads them. A vulnerability is confirmed
by *observing* an exploit, and this run observes nothing. So a record can only ever be:

| Verdict | What it means for you |
|---|---|
| `needs_validation` | The source supports the claim, and nobody ran it. Each one names the blocker (`[execution]`, `[deployment]`, `[context]`) and a concrete local check — usually a unit test you can write in five minutes. |
| `rejected` | A verifier read the code and the claim did not hold. Kept in the bundle so the run's own false positives are visible. |

There is no `severity` field anywhere in the output, and `confirmed` is not merely
filtered — the tool schemas cannot express it.

Every surface says the same thing: this is a **partial, diff-scoped, quick-profile pass**.
It is not an audit, and a run that reports nothing is not a clean bill of health.

### The two-job trust model

The work is split so that no single job holds both a model key and a write token:

| Job | Holds | Permissions | Posts |
|---|---|---|---|
| `analyze` | the model key | `contents: read`, `pull-requests: read`, `issues: read`, `actions: read` | nothing — it uploads a bundle artifact |
| `publish` | the write token | `pull-requests: write`, `issues: write`, `checks: write` | the review, summary and check run |
| `baseline` (scheduled) | the model key | `contents: read`, `actions: read` | nothing — it uploads the baseline artifact |

`analyze` reads attacker-controlled source, so it gets no way to write. `publish` writes,
so it gets no model and no repository source: it re-runs both vendored validators over the
downloaded bundle, checks every file against a digest the analyze job recorded, and drops
anything that fails. No job is granted `contents: write` or `id-token: write`.

### Inputs

`security/analyze`:

| Input | Default | |
|---|---|---|
| `pr-number` | – | Pull request to review |
| `head-sha` | – | Full 40-character sha, from the triggering event |
| `base-sha` | – | Full 40-character sha of the base commit |
| `github-token` | – | Read-only; use `github.token` |
| `deepseek-api-key` | – | DeepSeek key (or `anthropic-api-key`) |
| `models` | see below | `role=model`, comma separated |
| `max-conversations` / `max-hunters` / `max-verifiers` | `18` / `6` / `10` | Hard caps |
| `max-usd` | `1.50` | The run stops rather than cross it |
| `disclosure` | `auto` | `auto`, `all` or `summary-only` |

Default models: every role on `deepseek-flash`, which is DeepSeek-V4.1-Flash. DeepSeek's
API accepts only `deepseek-flash` and `deepseek-v4-pro` as model ids; the `deepseek/`
prefix you may see elsewhere is LiteLLM routing syntax, not part of the id.

Verifiers may share the hunters' model. The skill requires a *fresh* verifier that did not
hunt the candidate, and each verifier is a separate conversation built only from the
structured candidate, so that holds either way. A different model is an extra hedge against
a blind spot both share; set `models: verifier=deepseek-v4-pro` to use one. When they match,
the report says so.

`security/publish`: `pr-number`, `head-sha`, `github-token`, `fail-on`
(`never` by default), `sarif` (`false` by default).

### Cost and latency

Measured on real pull requests with every role on `deepseek-flash`, priced at DeepSeek's
peak rates (off-peak, which by the pricing table includes weekends, is about half):

| Pull request | Changed files | Cost | Wall clock |
|---|---|---|---|
| gopherium/gophenberg#225 | 9 (1 production, 6 tests) | **$0.23** | **3 min 40 s** |
| gopherium/AlphOne#132 | 4 | $0.29 | 4 min 30 s |

The #132 run predates the turn caps and the capped warm-start pack; #225 measured $0.41
before those changes, then $0.30, then $0.23. A typical run is seven or eight model
conversations: three reconnaissance agents, one hunter per coverage unit (test files share
the diff-wide units rather than getting their own), the coverage critic, and one verifier
per candidate. Agents within a phase run concurrently; the phases run in order, because the
skill requires the critic to finish before any verifier starts.

Hidden reasoning is a large share of the output. `SA_REASONING=recon=off,critic=off`
disables it for roles that record facts and coverage rather than verdicts; hunters and
verifiers keep it. DeepSeek's `low`, `medium` and `high` effort levels were measured to
have no effect and are refused.

For comparison, the general PR-Agent review above costs $0.02–0.04. The difference is the
price of the skill's evidence bar: every candidate is traced through source beyond the diff
and re-derived by an independent verifier. On both pull requests above, that is what reached
the right answer: the reviewer followed the change to the server-side authorization and the
documented deletion contract, and rejected a plausible candidate on evidence.

### Fork pull requests

Fork PRs are **label-gated per head**. A maintainer applies `security-review`, and the run
reviews exactly the head sha from that `labeled` event. The `unlabel-on-push` job strips
the label on every push, so each new fork head needs approval again.

The gate is for cost and noise, not for secrets: the reviewer holds no capability a key
could be exfiltrated through. The model calls no network tool, reads no environment, and
never sees the API key.

The workflow uses `pull_request_target`, which always runs the **default branch's** copy of
the workflow, so a pull request cannot edit or disable the reviewer that reviews it.
Nothing is ever checked out and no `actions/cache` is used. If you run it as a plain
`pull_request` instead, the pull request under review controls the workflow reviewing it,
and prior-run state must not be trusted.

### This is advisory. Do not make it a required check

The check run is **neutral** by default and `fail-on` defaults to `never`.

A pull request's own content reaches the model as data, and indirect prompt injection can
*suppress* findings — an agent can be talked into reporting nothing. That failure mode is
bounded here (a code-enforced coverage floor that no model output can shrink, independent
verifiers, `attr.tree` and literal pathspecs closing the two mechanical suppression
channels, and every unreached unit printed with its reason) but it is not eliminated, and
it cannot be.

So a green result means "this partial pass reported no leads", never "this code is safe".
Making it a required check would convert a false negative into an approval, which is worse
than not running it at all.
