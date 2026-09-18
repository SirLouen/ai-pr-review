"""M1 spike: go/no-go measurements for running the security reviewer on DeepSeek.

Everything else in this repository was built and tested against scripted and replayed
models. This measures the assumptions the design rests on, against the real API, under a
hard spend cap. Each probe is independent and records what it saw:

  model-name     Does an unknown model name fail loudly, or silently run another model?
  passback       Does a tool loop fail when reasoning_content is dropped from history?
  reasoning-cap  Does max_tokens count reasoning, so a small cap truncates the answer?
  json-thinking  Does json_object output stay valid JSON with thinking on?
  strict-tools   Does the /beta strict mode accept this action's real tool schemas?
  verifier       First-try validity of real verifier conversations: the go/no-go number.
  hunter         Multi-turn tool use by real hunter conversations.

The verifier and hunter probes run the production pipeline -- the real prompts, tool
surface, vendored validators and loop -- over a seeded SQL-injection fixture, so they
measure the thing that has to work rather than a toy request.

Exit criterion (design M1): at least 90% first-try validity, or a named fallback. The
fallback already exists in the loop (up to two rounds of validator feedback), so the
report gives both numbers and says which one carries the decision.

Every model exchange is recorded to a cassette, so the real responses become zero-cost
regression fixtures for the replay provider afterwards.

    DEEPSEEK_API_KEY=... python scripts/m1_spike.py --out /tmp/spike --max-usd 2
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import __main__ as cli                          # noqa: E402
from prreview.security import gitsrc, orchestrator, prompts, tools     # noqa: E402
from prreview.security import validate as validatemod                  # noqa: E402
from prreview.security.config import Caps, RunConfig                   # noqa: E402
from prreview.security.providers.base import CostMeter, ProviderError  # noqa: E402
from prreview.security.providers.deepseek import DeepSeekProvider      # noqa: E402
from prreview.security.providers.replay import ReplayProvider          # noqa: E402
from prreview.security.skillpack import SkillPack                      # noqa: E402

VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "vendor", "security-audit")
FIRST_TRY_TARGET = 0.90
BETA_URL = "https://api.deepseek.com/beta"

SAFE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
"""
VULNERABLE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = " + req.query.id);
}
"""
FINGERPRINT = "sa1:injection:src/users.js@getUser"


# ------------------------------------------------------------------------- fixture

def _git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text)


def _rev(root):
    return subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()


def build_fixture(root):
    """A two-commit repository whose head concatenates a request parameter into SQL."""
    source = os.path.join(root, "source")
    os.makedirs(source)
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "spike@example.invalid")
    _git(source, "config", "user.name", "Spike")
    _write(source, "src/users.js", SAFE)
    _write(source, "README.md", "# fixture\n")
    _git(source, "add", "-A")
    _git(source, "commit", "-qm", "base")
    base = _rev(source)
    _write(source, "src/users.js", VULNERABLE)
    _git(source, "add", "-A")
    _git(source, "commit", "-qm", "head")
    head = _rev(source)
    repo = gitsrc.open_repo(os.path.join(root, "work"))
    gitsrc.fetch_pr(repo, source, head, base, 3, protocols=("file",))
    return repo, base, head


def candidate():
    """The hunter-shaped candidate every verifier conversation is asked to judge."""
    return {"fingerprint": FINGERPRINT, "proposed_verdict": "needs_validation",
            "title": "Request parameter concatenated into a SQL query",
            "description": "An attacker controls the WHERE clause of a user lookup.",
            "claimed_root_cause": "req.query.id reaches db.query as string concatenation",
            "trace": [{"kind": "entrypoint", "file": "src/users.js", "line": 1,
                       "scope": "getUser", "description": "req.query.id enters"},
                      {"kind": "sink", "file": "src/users.js", "line": 2,
                       "scope": "getUser", "description": "concatenated into SQL"}],
            "evidence": [{"file": "src/users.js", "line": 2,
                          "description": "the query is built by concatenation"}],
            "blockers": ["[execution] the action does not run the service"],
            "validation_plan": {"local": "unit test with req.query.id = \"1 OR 1=1\"",
                                "deployment": None}}


# -------------------------------------------------------------------------- probes

class Report:
    def __init__(self):
        self.probes = {}

    def record(self, name, ok, **detail):
        self.probes[name] = dict(detail, ok=ok)
        status = "ok " if ok else "FAIL" if ok is False else "?  "
        print("  [%s] %-14s %s" % (status, name, detail.get("summary", "")), flush=True)


def _raw(provider, body):
    """One request with no parsing beyond JSON, so a probe can see errors verbatim."""
    started = time.monotonic()
    try:
        data = provider._post("/chat/completions", body)
        return {"ok": True, "data": data, "seconds": time.monotonic() - started}
    except ProviderError as exc:
        return {"ok": False, "error": str(exc)[:400], "seconds": time.monotonic() - started}


def _tool(name, description, properties):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": list(properties), "additionalProperties": False}}}


def probe_model_name(provider, report):
    body = {"model": "deepseek-flash-does-not-exist", "max_tokens": 16,
            "messages": [{"role": "user", "content": "Say ok."}]}
    got = _raw(provider, body)
    if not got["ok"]:
        report.record("model-name", True, summary="unknown model is refused",
                      error=got["error"])
        return
    echoed = (got["data"] or {}).get("model", "")
    report.record("model-name", False,
                  summary="unknown model was ANSWERED by %r: a typo silently changes the "
                          "model, so the configured name must be asserted" % echoed,
                  echoed_model=echoed)


def probe_passback(provider, report, model):
    read = _tool("read_file", "Read a file.", {"path": {"type": "string"}})
    messages = [{"role": "system", "content": "Use the read_file tool, then answer."},
                {"role": "user", "content": "Read README.md and tell me its first word."}]
    first = _raw(provider, {"model": model, "max_tokens": 2000, "messages": messages,
                            "tools": [read]})
    if not first["ok"]:
        report.record("passback", None, summary="first turn failed: %s" % first["error"])
        return
    message = first["data"]["choices"][0]["message"]
    calls = message.get("tool_calls") or []
    if not calls:
        report.record("passback", None, summary="model answered without a tool call; "
                                                "cannot test the loop")
        return
    tool_result = {"role": "tool", "tool_call_id": calls[0].get("id", ""),
                   "content": "# fixture"}
    kept = dict(message)
    dropped = {k: v for k, v in message.items() if k != "reasoning_content"}
    with_it = _raw(provider, {"model": model, "max_tokens": 2000, "tools": [read],
                              "messages": messages + [kept, tool_result]})
    without = _raw(provider, {"model": model, "max_tokens": 2000, "tools": [read],
                              "messages": messages + [dropped, tool_result]})
    has_reasoning = bool(message.get("reasoning_content"))
    report.record("passback", with_it["ok"],
                  summary="with reasoning passed back: %s; dropped: %s (reasoning present: %s)"
                          % ("ok" if with_it["ok"] else "ERROR",
                             "ok" if without["ok"] else "ERROR", has_reasoning),
                  with_passback=with_it.get("error", "ok"),
                  without_passback=without.get("error", "ok"),
                  reasoning_present=has_reasoning)


def probe_reasoning_cap(provider, report, model):
    body = {"model": model, "max_tokens": 64,
            "messages": [{"role": "user", "content":
                          "Reason carefully step by step: is 7919 prime? "
                          "Then answer with exactly one word."}]}
    got = _raw(provider, body)
    if not got["ok"]:
        report.record("reasoning-cap", None, summary="request failed: %s" % got["error"])
        return
    choice = got["data"]["choices"][0]
    usage = got["data"].get("usage") or {}
    reasoning = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0)
    content = choice["message"].get("content") or ""
    counts = choice.get("finish_reason") == "length" and not content.strip()
    report.record("reasoning-cap", not counts,
                  summary=("max_tokens INCLUDES reasoning: a 64-token cap left no answer, so "
                           "per-turn caps must budget reasoning" if counts else
                           "answer survived a 64-token cap"),
                  finish_reason=choice.get("finish_reason"), reasoning_tokens=reasoning,
                  completion_tokens=usage.get("completion_tokens"),
                  content_chars=len(content))


def probe_json_thinking(provider, report, model):
    body = {"model": model, "max_tokens": 1500,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": "Reply with a JSON object only."},
                         {"role": "user", "content": 'Return {"answer": <the capital of '
                                                     'France>} as JSON.'}]}
    got = _raw(provider, body)
    if not got["ok"]:
        report.record("json-thinking", False, summary="request failed: %s" % got["error"])
        return
    content = got["data"]["choices"][0]["message"].get("content") or ""
    try:
        parsed = json.loads(content)
        report.record("json-thinking", isinstance(parsed, dict),
                      summary="valid JSON object with thinking on", sample=content[:120])
    except ValueError:
        report.record("json-thinking", False,
                      summary="json_object returned non-JSON (%d chars)" % len(content),
                      sample=content[:200])


def probe_strict_tools(api_key, report, model):
    """Our real verifier catalogue, sent to the beta strict endpoint.

    Accepted means DeepSeek can enforce the schema itself. Refused is not a blocker --
    tools.check_schema re-checks every argument either way -- but it names what to drop.
    """
    beta = DeepSeekProvider(api_key, base_url=BETA_URL, allow_custom_base_url=True)
    catalogue = tools.tool_definitions("verifier", strict=True)
    body = {"model": model, "max_tokens": 1500, "tools": catalogue,
            "messages": [{"role": "user", "content": "Call list_changed_files."}]}
    got = _raw(beta, body)
    report.record("strict-tools", got["ok"],
                  summary=("beta strict mode accepted %d tool schemas" % len(catalogue)
                           if got["ok"] else "beta strict mode REFUSED the schemas"),
                  error=got.get("error", ""))


def probe_pipeline(provider, report, workdir, n_verifiers, n_hunters, max_usd):
    """The go/no-go: real verifier and hunter conversations through the production code."""
    repo, base, head = build_fixture(os.path.join(workdir, "fixture"))
    commits = gitsrc.commits_between(repo, base, head)["commits"]
    caps = Caps(max_conversations=4 + n_hunters + n_verifiers + 2,
                max_hunters=max(1, n_hunters), max_verifiers=n_verifiers, max_usd=max_usd)
    cfg = RunConfig(repository="spike/fixture", pr_number=1, head_sha=head, base_sha=base,
                    out_dir=os.path.join(workdir, "out"), vendor_dir=VENDOR, caps=caps)
    validator = validatemod.Validator(vendor_dir=VENDOR)
    try:
        skill = SkillPack(VENDOR)
        source = tools.RepoSource(repo, head, base, commits=commits, caps=caps)
        parent = orchestrator.Orchestrator(cfg, provider, validator, source, skill)
        facts = prompts.RunFacts.from_config(cfg, skill_commit=skill.commit,
                                             commit_count=len(commits))
        diff = gitsrc.diff_index(repo, base, head, caps=caps)
        changes = orchestrator.routing_changes(repo, base, head, diff)
        parent.plan(diff, changes, len(commits), cli.symbol_resolver(source, diff))

        if n_hunters:
            parent.hunt(facts, list(parent.assignments)[:n_hunters])
        parent.verify(facts, [candidate() for _ in range(n_verifiers)])
    finally:
        validator.close()

    by_role = {}
    for conversation in parent.conversations:
        by_role.setdefault(conversation.role, []).append(conversation)
    _summarise(report, "verifier", by_role.get("verifier", []))
    _summarise(report, "hunter", by_role.get("hunter", []))
    return parent


def _summarise(report, role, conversations):
    if not conversations:
        report.record(role, None, summary="no %s conversations ran" % role)
        return
    rows = []
    for c in conversations:
        state = c.state or {}
        rows.append({"status": c.status, "reason": c.reason[:160], "turns": c.turns,
                     "seconds": round(c.seconds, 1), "rounds": state.get("submit_rounds"),
                     "tool_calls": state.get("tool_calls"), "usage": c.usage.as_dict()})
    n = len(rows)
    ok = [r for r in rows if r["status"] == "ok"]
    first = [r for r in ok if r["rounds"] == 1]
    miss = sum(r["usage"]["cache_miss"] for r in rows)
    hit = sum(r["usage"]["cache_hit"] for r in rows)
    out = sum(r["usage"]["output"] + r["usage"]["reasoning"] for r in rows)
    reasoning = sum(r["usage"]["reasoning"] for r in rows)
    seconds = sum(r["seconds"] for r in rows) or 1.0
    first_rate, ok_rate = len(first) / n, len(ok) / n
    passed = first_rate >= FIRST_TRY_TARGET if role == "verifier" else ok_rate >= 0.8
    report.record(role, passed,
                  summary="%d runs: first-try %.0f%%, valid within feedback %.0f%%, "
                          "avg %.1f turns, %.0f out-tok/s, cache hit %.0f%%"
                          % (n, 100 * first_rate, 100 * ok_rate,
                             sum(r["turns"] for r in rows) / n, out / seconds,
                             100 * hit / max(1, hit + miss)),
                  first_try_rate=round(first_rate, 3), within_feedback_rate=round(ok_rate, 3),
                  reasoning_share=round(reasoning / max(1, out), 3), runs=rows)


# ------------------------------------------------------------------------ decision

def decide(report):
    verifier = report.probes.get("verifier") or {}
    first = verifier.get("first_try_rate", 0.0)
    within = verifier.get("within_feedback_rate", 0.0)
    if first >= FIRST_TRY_TARGET:
        return "GO", "first-try validity %.0f%% meets the %.0f%% bar" % (100 * first,
                                                                          100 * FIRST_TRY_TARGET)
    if within >= FIRST_TRY_TARGET:
        return ("CONDITIONAL-GO",
                "first-try %.0f%% is under the bar, but %.0f%% validate within the existing "
                "two feedback rounds: the named fallback carries it, at extra cost"
                % (100 * first, 100 * within))
    return ("NO-GO",
            "only %.0f%% of verifier records validate even with feedback; consider a Claude "
            "verifier (the adapter is milestone M8) or a smaller submit contract"
            % (100 * within))


def main(argv=None, provider=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True, help="directory for report and cassettes")
    parser.add_argument("--max-usd", type=float, default=2.0)
    parser.add_argument("--verifiers", type=int, default=10)
    parser.add_argument("--hunters", type=int, default=3)
    parser.add_argument("--model", default="deepseek-flash", help="model for raw probes")
    parser.add_argument("--skip-raw", action="store_true",
                        help="only run the pipeline probes (no direct API probes)")
    args = parser.parse_args(argv)

    api_key = os.environ.pop("DEEPSEEK_API_KEY", "")
    if provider is None and not api_key:
        print("DEEPSEEK_API_KEY is required; nothing was sent.", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    report = Report()
    started = time.monotonic()
    print("M1 spike: cap $%.2f, %d verifiers, %d hunters" % (args.max_usd, args.verifiers,
                                                             args.hunters), flush=True)

    live = DeepSeekProvider(api_key) if provider is None else None
    if live is not None and not args.skip_raw:
        print("raw API probes:", flush=True)
        probe_model_name(live, report)
        probe_passback(live, report, args.model)
        probe_reasoning_cap(live, report, args.model)
        probe_json_thinking(live, report, args.model)
        probe_strict_tools(api_key, report, args.model)

    print("pipeline probes:", flush=True)
    recorder = ReplayProvider(os.path.join(args.out, "cassettes"),
                              inner=provider or live, mode="record")
    with tempfile.TemporaryDirectory(prefix="spike-") as workdir:
        parent = probe_pipeline(recorder, report, workdir, args.verifiers, args.hunters,
                                args.max_usd)

    verdict, why = decide(report)
    result = {"verdict": verdict, "reason": why, "probes": report.probes,
              "usd_spent_pipeline": round(parent.meter.spent, 4),
              "usd_by_role": {k: round(v, 4) for k, v in parent.meter.by_role.items()},
              "seconds": round(time.monotonic() - started, 1),
              "cassettes": recorder.misses}
    with open(os.path.join(args.out, "report.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1, sort_keys=True)
    print("\n%s: %s" % (verdict, why))
    print("pipeline spend $%.4f; report and %d cassettes in %s"
          % (parent.meter.spent, recorder.misses, args.out))
    return 0 if verdict != "NO-GO" else 1


if __name__ == "__main__":
    sys.exit(main())
