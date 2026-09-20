"""
Adversarially verified PR review: PR-Agent on DeepSeek, plus a refutation pass.

PR-Agent has no verification step, so a confident-but-wrong finding is posted with the same
weight as a real bug. This script runs PR-Agent without publishing, extracts its findings,
asks the model to refute each one against the full PR diff, and posts only what survives.

Each run posts the review as a new PR comment and hides the earlier ones as outdated, so a
re-review after a push is visible and notifies, while older reviews stay one click away.

Usage:  python verify_review.py --pr-url <url> [--publish]

Environment:
  DEEPSEEK_API_KEY     DeepSeek API key                                  (required)
  GITHUB_TOKEN_REVIEW  token that reads the PR and posts the comment     (required)
  REVIEW_MODEL         DeepSeek model name                (default: deepseek-flash)
  Plus the CONFIG__* / PR_REVIEWER__* variables consumed by PR-Agent itself.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

API_BASE = "https://api.deepseek.com"
MODEL = os.environ.get("REVIEW_MODEL", "deepseek-flash")
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
GH_TOKEN = os.environ.get("GITHUB_TOKEN_REVIEW", "")
MARKER = "<!-- ai-verified-review -->"
ACTIONS_BOT = "github-actions[bot]"
PR_AGENT_TIMEOUT = int(os.environ.get("PR_AGENT_TIMEOUT_SECONDS", "900"))
USAGE = {"prompt": 0, "completion": 0, "cache_hit": 0, "calls": 0}

REFUTE_SYSTEM = """You are auditing a proposed code-review finding against the actual diff.

Decide whether the finding is a real problem. Judge it on the evidence in the diff, not on how
confidently it is worded.

REFUTE it only when you can show it is wrong, e.g.:
- the triggering condition demonstrably cannot occur in this code
- a guard, type, or earlier check visible in the diff already prevents it
- it describes intended, documented behaviour as though it were a defect
- it is purely a style, naming, or formatting preference
- it restates something a compiler or type checker would reject outright

Mark it UNCERTAIN when the finding is plausible but you cannot confirm the triggering path from
the diff alone - for example when it depends on code that is not shown.

Otherwise it SURVIVES.

Do not refute a finding merely because it is narrow, low severity, or unlikely in practice. A real
bug with a rare trigger is still a real bug. Missing tests, unchecked errors, and absent validation
are legitimate findings, not noise. When you genuinely cannot tell, prefer UNCERTAIN over REFUTED -
a human reads these, and silently discarding real problems is the worse failure.

Respond with a single JSON object only, no prose:
{"verdict": "survives" | "uncertain" | "refuted", "reason": "at most 2 sentences"}"""


def log(message):
    print(message, flush=True)


def gh(path, payload=None, method=None):
    headers = {"Authorization": f"Bearer {GH_TOKEN}",
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "ai-pr-review"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"https://api.github.com{path}", data=data, headers=headers,
                                 method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(req, timeout=90) as r:
        body = r.read().decode("utf-8")
        return json.loads(body) if body else {}


def gh_paginated(path):
    """GET every page of a list endpoint."""
    sep = "&" if "?" in path else "?"
    items, page = [], 1
    while True:
        chunk = gh(f"{path}{sep}per_page=100&page={page}")
        if not isinstance(chunk, list) or not chunk:
            break
        items.extend(chunk)
        if len(chunk) < 100:
            break
        page += 1
    return items


def call_model(system, user, max_tokens=500):
    """Chat completion with thinking disabled and JSON output enforced."""
    payload = {"model": MODEL,
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": user}],
               "max_tokens": max_tokens,
               "temperature": 0.0,
               "thinking": {"type": "disabled"},
               "response_format": {"type": "json_object"}}
    req = urllib.request.Request(f"{API_BASE}/chat/completions",
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {API_KEY}"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read().decode("utf-8"))
    u = d.get("usage") or {}
    USAGE["prompt"] += u.get("prompt_tokens", 0)
    USAGE["completion"] += u.get("completion_tokens", 0)
    USAGE["cache_hit"] += u.get("prompt_cache_hit_tokens", 0)
    USAGE["calls"] += 1
    msg = d["choices"][0]["message"]
    return (msg.get("content") or "").strip() or (msg.get("reasoning_content") or "").strip()


def _as_text(value):
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def run_pr_agent(pr_url):
    """Run PR-Agent without publishing. Returns (exit code or None on timeout, log output)."""
    env = os.environ.copy()
    env["CONFIG__PUBLISH_OUTPUT"] = "false"
    env["CONFIG__VERBOSITY_LEVEL"] = "2"        # needed so the model response is logged
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        # `--config.<key>=<value>` reaches get_settings().set(), which REPLACES the value.
        # The env var CONFIG__FALLBACK_MODELS cannot: PR-Agent builds its Dynaconf with
        # merge_enabled=True, so an empty list merges into the shipped default and leaves
        # it in place. Without this, a DeepSeek failure is retried against that default
        # (an OpenAI model this action has no key for) and the only error the log shows is
        # OpenAI's "Incorrect API key provided: dummy_key", which hides the real cause.
        p = subprocess.run([sys.executable, "-m", "pr_agent.cli", "--pr_url", pr_url,
                            "review", "--config.fallback_models=[]"],
                           capture_output=True, text=True, env=env, encoding="utf-8",
                           errors="replace", timeout=PR_AGENT_TIMEOUT)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:      # keep partial output so a timeout is diagnosable
        return None, _as_text(e.stdout) + _as_text(e.stderr)


# The reason a run produced nothing is logged by PR-Agent when the call fails, thousands of
# lines before the end of its output -- it dumps the whole prompt after it. Printing only the
# tail showed the LAST model's error and buried the first model's, which is the real one.
MODEL_ERROR_RE = re.compile(
    r"(?:Failed to generate prediction|Error during LLM inference|Failed to review PR)[^\n]*")


def model_errors(out, limit=12):
    """Every model-failure line anywhere in PR-Agent's output, oldest first, deduplicated."""
    seen, found = set(), []
    for match in MODEL_ERROR_RE.finditer(ANSI_RE.sub("", out or "")):
        line = match.group(0).strip()
        if line not in seen:
            seen.add(line)
            found.append("      " + line)
    return found[:limit]


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOGLINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
FENCE_OPEN_RE = re.compile(r"^\s*```\s*ya?ml\s*$")


def extract_findings(out):
    """Parse the YAML review PR-Agent logs after its last 'AI response:' marker.

    The response is everything up to the next log line. Only an opening ```yaml fence on its
    first line and a closing ``` on its last line are removed: fenced snippets quoted inside a
    finding are indented block-scalar content and must not be mistaken for the review.
    Returns (raw_yaml or None if unparsable, findings).
    """
    out = ANSI_RE.sub("", out)
    i = out.rfind("AI response:")
    if i < 0:
        return None, []
    kept = []
    for line in out[i + len("AI response:"):].split("\n"):
        if LOGLINE_RE.match(line.strip()):
            break
        kept.append(line)
    lines = "\n".join(kept).strip("\n").split("\n")
    if lines and FENCE_OPEN_RE.match(lines[0]):
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    raw = "\n".join(lines)
    if not raw.strip():
        return None, []

    try:
        import yaml
        data = yaml.safe_load(raw)
    except Exception:
        return None, []
    if not isinstance(data, dict):
        return None, []
    review = data.get("review") if isinstance(data.get("review"), dict) else data
    if not isinstance(review, dict) or "key_issues_to_review" not in review:
        return None, []                          # not a review: treat as a failure, not "0 findings"

    findings = []
    for f in review.get("key_issues_to_review") or []:
        if isinstance(f, dict):
            findings.append({"file": str(f.get("relevant_file", "")).strip(),
                             "header": str(f.get("issue_header", "")).strip(),
                             "content": str(f.get("issue_content", "")).strip(),
                             "start_line": f.get("start_line")})
    sec = review.get("security_concerns")
    if sec and not _is_no(sec):
        findings.append({"file": "", "header": "Security concern",
                         "content": str(sec).strip(), "start_line": None})
    return raw, findings


NO_RE = re.compile(r"^(no|none|n/?a)\b", re.I)


def _is_no(value):
    """True when security_concerns is a negative answer rather than a finding.

    The prompt asks for "No" without explaining why, but models write "No." or
    "No security concerns identified". Matching only the exact words posted those
    as a finding with no file and no line.
    """
    text = str(value).strip().strip("*_`\"' ")
    if not text:
        return True
    if NO_RE.match(text):
        # "No" and "No security concerns found" are negatives; "No sanitization is
        # applied to ..." is a finding that happens to start with the same word.
        return len(text.split()) <= 6 or "concern" in text.lower()
    return False


def parse_verdict(raw):
    """Return the verdict dict from the model output, or None.

    Tries the whole (optionally fenced) text first, then decodes from every '{' so that braces
    inside the reason - common when quoting code - do not break the match.
    """
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    candidates = []
    try:
        candidates.append(json.loads(text))
    except ValueError:
        decoder = json.JSONDecoder()
        for m in re.finditer(r"\{", raw):
            try:
                obj, _ = decoder.raw_decode(raw[m.start():])
                candidates.append(obj)
            except ValueError:
                continue
    found = [c for c in candidates if isinstance(c, dict) and "verdict" in c]
    return found[-1] if found else None


def diff_context(files, primary_file, budget=30000):
    """Full-PR diff for the verifier, the finding's own file first so it survives truncation.

    Findings often span files (a caller in one, the function it relies on in another); showing
    only the primary file leaves the verifier unable to confirm them.
    """
    ordered = ([f for f in files if f.get("filename") == primary_file] +
               [f for f in files if f.get("filename") != primary_file])
    parts, used = [], 0
    for f in ordered:
        patch = f.get("patch") or ""
        if not patch:
            continue
        chunk = f"--- {f.get('filename')} ---\n{patch}\n"
        if used + len(chunk) > budget:
            if budget - used > 500:
                parts.append(chunk[:budget - used] + "\n... (truncated)\n")
            break
        parts.append(chunk)
        used += len(chunk)
    return "".join(parts)


def verify(finding, files):
    user = (f"PRIMARY FILE: {finding['file'] or '(repository-wide)'}\n"
            f"FINDING TITLE: {finding['header']}\n"
            f"FINDING BODY:\n{finding['content']}\n\n"
            "DIFF FOR ALL CHANGED FILES IN THIS PR (primary file first):\n"
            f"```diff\n{diff_context(files, finding['file']) or '(no diff available)'}\n```\n\n"
            "Refute this finding, mark it uncertain, or confirm it survives. Answer in JSON.")
    try:
        raw = call_model(REFUTE_SYSTEM, user)
    except Exception as e:                       # fail open: never silently drop a finding
        return {"verdict": "uncertain", "reason": f"verifier call failed ({type(e).__name__})"}
    verdict = parse_verdict(raw)
    if verdict is None:
        return {"verdict": "uncertain", "reason": "verifier returned no JSON verdict"}
    v = str(verdict.get("verdict", "")).lower()
    if v not in ("survives", "uncertain", "refuted"):
        v = "uncertain"
    return {"verdict": v, "reason": str(verdict.get("reason", ""))[:400]}


def render(survivors, dropped, total, head_sha):
    lines = [MARKER, f"## 🔍 AI review · {MODEL} (adversarially verified)", "",
             f"Reviewed commit `{head_sha[:7]}`.", ""]
    if not survivors:
        lines += [f"No findings survived verification ({total} raised, {len(dropped)} refuted).", ""]
    else:
        lines += [f"{len(survivors)} of {total} findings survived a refutation pass.", ""]
        for f in survivors:
            loc = f["file"] or "repository-wide"
            if f.get("start_line"):
                loc += f":{f['start_line']}"
            tag = " *(unconfirmed)*" if f["verdict"]["verdict"] == "uncertain" else ""
            lines += [f"### {f['header']}{tag}", f"`{loc}`", "", f["content"], "",
                      f"> **Verifier:** {f['verdict']['reason']}", ""]
    if dropped:
        lines += [f"<details><summary>Refuted findings ({len(dropped)})</summary>", ""]
        for f in dropped:
            lines += [f"- **{f['header']}** (`{f['file'] or 'n/a'}`) — {f['verdict']['reason']}"]
        lines += ["", "</details>", ""]
    return "\n".join(lines)


def reviewer_login():
    """Login of the account the token posts as.

    GET /user is refused (403) for the Actions GITHUB_TOKEN and for app installation tokens;
    those post as github-actions[bot].
    """
    try:
        return gh("/user").get("login") or ACTIONS_BOT
    except urllib.error.HTTPError:
        return ACTIONS_BOT


def graphql(query, variables):
    """POST a GraphQL request. GraphQL reports errors inside a 200 response, so raise on them."""
    d = gh("/graphql", {"query": query, "variables": variables})
    if d.get("errors"):
        raise RuntimeError("; ".join(str(e.get("message", e)) for e in d["errors"]))
    return d.get("data") or {}


MINIMIZED_QUERY = """query($ids: [ID!]!) {
  nodes(ids: $ids) { ... on IssueComment { id isMinimized } }
}"""
MINIMIZE_MUTATION = """mutation($id: ID!) {
  minimizeComment(input: {subjectId: $id, classifier: OUTDATED}) { minimizedComment { isMinimized } }
}"""


def hide_outdated(comments):
    """Minimize earlier reviews as outdated, skipping those already hidden by a previous run.

    Never fatal: the new review is already posted, so a failure here only leaves an old one visible.
    """
    ids = [c["node_id"] for c in comments if c.get("node_id")]
    pending = []
    for start in range(0, len(ids), 100):        # the nodes query accepts at most 100 ids
        chunk = ids[start:start + 100]
        try:
            nodes = graphql(MINIMIZED_QUERY, {"ids": chunk}).get("nodes") or []
            pending += [n["id"] for n in nodes if n and n.get("id") and not n.get("isMinimized")]
        except Exception as e:
            log(f"warning: could not check which earlier reviews are hidden ({e})")
            pending += chunk
    for node_id in pending:
        try:
            graphql(MINIMIZE_MUTATION, {"id": node_id})
            log(f"hid earlier review {node_id} as outdated")
        except Exception as e:
            log(f"warning: could not hide earlier review {node_id} ({e})")


def publish(owner, repo, num, body):
    """Post the review as a new comment, then hide this reviewer's earlier reviews as outdated.

    A new comment lands below the commits it reviews and notifies the PR's subscribers; editing
    one comment in place did neither, so reviews of later pushes went unnoticed.
    """
    me = reviewer_login()
    earlier = [c for c in gh_paginated(f"/repos/{owner}/{repo}/issues/{num}/comments")
               if MARKER in (c.get("body") or "") and (c.get("user") or {}).get("login") == me]
    c = gh(f"/repos/{owner}/{repo}/issues/{num}/comments", {"body": body})
    log(f"posted review comment {c.get('id')} (as {me})")
    hide_outdated(earlier)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr-url", required=True)
    ap.add_argument("--publish", action="store_true")
    a = ap.parse_args()

    if not API_KEY or not GH_TOKEN:
        log("ERROR: DEEPSEEK_API_KEY and GITHUB_TOKEN_REVIEW must both be set")
        return 2
    m = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/(\d+)", a.pr_url)
    if not m:
        log(f"ERROR: cannot parse PR url: {a.pr_url}")
        return 2
    owner, repo, num = m.group(1), m.group(2), int(m.group(3))

    log(f"[1/3] running PR-Agent on {owner}/{repo}#{num} ...")
    rc, out = run_pr_agent(a.pr_url)
    raw, findings = extract_findings(out)
    if raw is None:
        reason = f"timed out after {PR_AGENT_TIMEOUT}s" if rc is None else f"exit code {rc}"
        log(f"ERROR: no parsable review in PR-Agent output ({reason})")
        dump = os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(),
                            "pr_agent_output.txt")
        try:
            with open(dump, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(out)
            log(f"full PR-Agent output written to {dump}")
        except OSError:
            pass
        for line in model_errors(out):
            log(line)
        log(out[-4000:])
        return 1
    log(f"      PR-Agent raised {len(findings)} finding(s)")

    pr = gh(f"/repos/{owner}/{repo}/pulls/{num}")
    head_sha = (pr.get("head") or {}).get("sha", "")
    survivors, dropped = [], []
    if findings:
        files = gh_paginated(f"/repos/{owner}/{repo}/pulls/{num}/files")
        log(f"[2/3] verifying {len(findings)} finding(s) ...")
        for i, f in enumerate(findings, 1):
            f["verdict"] = verify(f, files)
            v = f["verdict"]["verdict"]
            log(f"      [{i}/{len(findings)}] {v.upper():9} {f['header']} -- {f['verdict']['reason'][:100]}")
            (dropped if v == "refuted" else survivors).append(f)
    else:
        log("[2/3] nothing to verify")
    body = render(survivors, dropped, len(findings), head_sha)

    log("[3/3] result:")
    log("-" * 60)
    log(body)
    log("-" * 60)
    if USAGE["calls"]:
        log(f"verifier usage: calls={USAGE['calls']} prompt={USAGE['prompt']} "
            f"cache_hit={USAGE['cache_hit']} completion={USAGE['completion']}")
    if a.publish:
        publish(owner, repo, num, body)
    else:
        log("dry run - not posted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
