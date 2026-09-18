"""A stdlib http.server stand-in for the GitHub REST and GraphQL API.

Only the endpoints `prreview.security.github` and `prreview.security.publish` call
exist here. Every request is recorded with its headers so a test can assert both
what was sent and what was never sent - the token in particular. Nothing in this
module opens a socket to anywhere but 127.0.0.1.

Failures are injected per route with `fail_once`, because the behaviour under test
is usually the fallback: a 422 on a review, a 403 on GET /user, a 500 that should
be retried.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

PR_RE = re.compile(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)$")
FILES_RE = re.compile(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)/files$")
REVIEWS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)/reviews$")
PR_COMMENTS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)/comments$")
REPLIES_RE = re.compile(r"^/repos/([^/]+/[^/]+)/pulls/(\d+)/comments/(\d+)/replies$")
ISSUE_COMMENTS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/issues/(\d+)/comments$")
CHECK_RUNS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/check-runs$")
CHECK_RUN_RE = re.compile(r"^/repos/([^/]+/[^/]+)/check-runs/(\d+)$")
REF_CHECKS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/commits/([^/]+)/check-runs$")
CONTENTS_RE = re.compile(r"^/repos/([^/]+/[^/]+)/contents/(.*)$")


class State:
    """Everything the fake serves, and everything it saw."""

    def __init__(self, repo="octo/demo", number=7, head_sha="a" * 40):
        self.repo = repo
        self.number = number
        self.login = "github-actions[bot]"
        self.user_status = 403
        self.head_sha = head_sha
        # Pop one per GET /pulls/{n}: lets a test move the head between two writes.
        self.head_sequence = []
        self.changed_files = None
        self.files = []
        self.review_comments = []
        self.issue_comments = []
        self.check_runs = []
        self.threads = []
        self.present_paths = None       # None means every cited path exists
        self.requests = []
        self.reviews = []
        self.replies = []
        self.minimized = []             # (node_id, classifier)
        self.resolved = []
        self.graphql_calls = []
        self._failures = {}
        self._next_id = 1000

    # -- helpers used by tests

    def fail_once(self, key, status, message="rejected by the fake"):
        self._failures.setdefault(key, []).append((status, message))

    def next_id(self):
        self._next_id += 1
        return self._next_id

    def add_review_comment(self, body, path="src/app.ts", line=10, login=None):
        comment_id = self.next_id()
        comment = {"id": comment_id, "node_id": "PRRC_%d" % comment_id, "body": body,
                   "path": path, "line": line, "side": "RIGHT",
                   "user": {"login": login or self.login}}
        self.review_comments.append(comment)
        return comment

    def add_issue_comment(self, body, login=None):
        comment_id = self.next_id()
        comment = {"id": comment_id, "node_id": "IC_%d" % comment_id, "body": body,
                   "user": {"login": login or self.login}}
        self.issue_comments.append(comment)
        return comment

    def add_thread(self, comment, resolved=False):
        thread = {"id": "PRRT_%d" % self.next_id(), "isResolved": resolved,
                  "isOutdated": False,
                  "comments": {"nodes": [{"id": comment["node_id"],
                                          "databaseId": comment["id"],
                                          "body": comment["body"],
                                          "isMinimized": False,
                                          "author": {"login": comment["user"]["login"]}}]}}
        self.threads.append(thread)
        return thread

    def add_file(self, filename, patch, status="modified"):
        self.files.append({"filename": filename, "status": status, "patch": patch})

    # -- internals

    def take_failure(self, key):
        queue = self._failures.get(key)
        return queue.pop(0) if queue else None

    def minimized_ids(self):
        return [node_id for node_id, _classifier in self.minimized]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass    # a test run must not print the fake's access log

    @property
    def state(self):
        return self.server.state

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            payload = None
        parts = urlsplit(self.path)
        self.state.requests.append({"method": method, "path": parts.path,
                                    "query": parse_qs(parts.query), "payload": payload,
                                    "headers": dict(self.headers.items())})
        try:
            status, body = self._route(method, parts.path, parse_qs(parts.query), payload)
        except Exception as exc:                 # a fake that crashes must say so
            status, body = 500, {"message": "fake error: %s" % exc}
        self._send(status, body)

    def _send(self, status, body):
        data = json.dumps(body).encode("utf-8") if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _route(self, method, path, query, payload):
        state = self.state
        key = "%s %s" % (method, path)
        injected = state.take_failure(key)
        if injected:
            return injected[0], {"message": injected[1]}

        if path == "/noop" and method == "DELETE":
            return 204, None

        if path == "/user" and method == "GET":
            if state.user_status != 200:
                return state.user_status, {"message": "Resource not accessible"}
            return 200, {"login": state.login}

        if path == "/graphql" and method == "POST":
            return self._graphql(payload or {})

        match = PR_RE.match(path)
        if match and method == "GET":
            sha = state.head_sequence.pop(0) if state.head_sequence else state.head_sha
            return 200, {"number": state.number,
                         "head": {"sha": sha},
                         "changed_files": state.changed_files}

        match = FILES_RE.match(path)
        if match and method == "GET":
            page = int((query.get("page") or ["1"])[0])
            size = int((query.get("per_page") or ["100"])[0])
            start = (page - 1) * size
            return 200, state.files[start:start + size]

        match = REVIEWS_RE.match(path)
        if match and method == "POST":
            state.reviews.append(payload)
            return 200, {"id": state.next_id(), "state": "COMMENTED"}

        match = REPLIES_RE.match(path)
        if match and method == "POST":
            state.replies.append({"in_reply_to": int(match.group(3)),
                                  "body": (payload or {}).get("body", "")})
            return 201, {"id": state.next_id()}

        match = PR_COMMENTS_RE.match(path)
        if match and method == "GET":
            page = int((query.get("page") or ["1"])[0])
            size = int((query.get("per_page") or ["100"])[0])
            start = (page - 1) * size
            return 200, state.review_comments[start:start + size]
        if match and method == "POST":
            comment = state.add_review_comment(
                (payload or {}).get("body", ""),
                path=(payload or {}).get("path", ""),
                line=(payload or {}).get("line"))
            comment["subject_type"] = (payload or {}).get("subject_type")
            comment["commit_id"] = (payload or {}).get("commit_id")
            return 201, comment

        match = ISSUE_COMMENTS_RE.match(path)
        if match and method == "GET":
            page = int((query.get("page") or ["1"])[0])
            size = int((query.get("per_page") or ["100"])[0])
            start = (page - 1) * size
            return 200, state.issue_comments[start:start + size]
        if match and method == "POST":
            return 201, state.add_issue_comment((payload or {}).get("body", ""))

        match = CHECK_RUNS_RE.match(path)
        if match and method == "POST":
            run = dict(payload or {})
            run["id"] = state.next_id()
            state.check_runs.append(run)
            return 201, run

        match = CHECK_RUN_RE.match(path)
        if match and method == "PATCH":
            run_id = int(match.group(2))
            for run in state.check_runs:
                if run.get("id") == run_id:
                    run.update(payload or {})
                    return 200, run
            return 404, {"message": "Not Found"}

        match = REF_CHECKS_RE.match(path)
        if match and method == "GET":
            name = (query.get("check_name") or [None])[0]
            runs = [r for r in state.check_runs
                    if r.get("head_sha") == unquote(match.group(2))
                    and (name is None or r.get("name") == name)]
            return 200, {"total_count": len(runs), "check_runs": runs}

        match = CONTENTS_RE.match(path)
        if match and method == "GET":
            target = unquote(match.group(2))
            if state.present_paths is not None and target not in state.present_paths:
                return 404, {"message": "Not Found"}
            return 200, {"path": target, "type": "file"}

        return 404, {"message": "Not Found"}

    def _graphql(self, payload):
        state = self.state
        query = payload.get("query") or ""
        variables = payload.get("variables") or {}
        state.graphql_calls.append({"query": query, "variables": variables})
        if "nodes(ids:" in query:
            known = {c["node_id"]: c for c in state.review_comments + state.issue_comments}
            minimized = set(state.minimized_ids())
            nodes = []
            for node_id in variables.get("ids") or []:
                if node_id in known:
                    nodes.append({"id": node_id, "isMinimized": node_id in minimized})
                else:
                    nodes.append(None)
            return 200, {"data": {"nodes": nodes}}
        if "minimizeComment" in query:
            classifier = "OUTDATED"
            found = re.search(r"classifier:\s*([A-Z_]+)", query)
            if found:
                classifier = found.group(1)
            state.minimized.append((variables.get("id"), classifier))
            return 200, {"data": {"minimizeComment": {"minimizedComment": {"isMinimized": True}}}}
        if "resolveReviewThread" in query:
            state.resolved.append(variables.get("id"))
            return 200, {"data": {"resolveReviewThread": {"thread": {"isResolved": True}}}}
        if "reviewThreads" in query:
            return 200, {"data": {"repository": {"pullRequest": {"reviewThreads": {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": state.threads}}}}}
        return 200, {"errors": [{"message": "the fake does not know this query"}]}


class FakeGitHub:
    """Run the fake on a loopback port for the lifetime of one test."""

    def __init__(self, state=None):
        self.state = state or State()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    @property
    def url(self):
        host, port = self.server.server_address[:2]
        return "http://%s:%d" % (host, port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False
