# AI PR Review (DeepSeek)

A composite GitHub Action that reviews a pull request with
[PR-Agent](https://github.com/The-PR-Agent/pr-agent) running on DeepSeek, then runs a second
pass that tries to refute each finding against the full diff. Only findings that survive are
posted; refuted ones are listed in a collapsed section.

The review lives in one PR comment that is updated on every run, so re-reviewing on each push
does not add new comments.

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
