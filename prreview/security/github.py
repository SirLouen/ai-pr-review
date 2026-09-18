"""Shared GitHub REST and GraphQL client for the security reviewer.

This is `verify_review.py`'s proven client, generalised: one `urllib` request
helper, page-number pagination, a GraphQL call that raises on the errors GitHub
reports inside a 200 response, and the post-then-hide comment pattern that made
re-reviews visible after a push. Everything the publish job needs to reach
GitHub goes through here, so there is one place where the write token lives and
one place that decides what a failure is allowed to say.

Three properties this module is responsible for:

  * The token is never written anywhere. Every message and every log line is
    passed through `_redact` before it leaves the object, so a future edit that
    interpolates a header or a URL into an error cannot leak it.
  * The token never crosses a host boundary. urllib's redirect handler copies
    every header except the content ones, so an ordinary 302 would hand the
    Authorization header to whatever host GitHub names. Cross-host redirects are
    refused here and the caller is given the location to fetch without a token.
  * A 403 or a 404 is a normal answer, not a crash: the caller decides whether a
    missing PR, a revoked scope or a secondary rate limit is fatal.

Retries cover the failures that are not answers - 429, 5xx, a secondary rate
limit, a dropped connection. A 422 is never retried: it means GitHub understood
the request and refused it, which for a review comment is the anchor being
invalid and is a fallback, not an error.
"""
import http.client
import json
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
USER_AGENT = "ai-pr-review-security"
ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"
TIMEOUT_S = 90
RETRIES = 4
BACKOFF_S = 1.0
MAX_BACKOFF_S = 30.0
PAGE_SIZE = 100

# GitHub serves at most 3000 files from the pull request files endpoint however
# large the diff is, and says so nowhere in the response. Past that the review
# surface is short and the run has to disclose it rather than look complete.
MAX_PR_FILES = 3000

ACTIONS_BOT = "github-actions[bot]"

# The GraphQL enum, as a closed set. A classifier is never interpolated from
# anything a model or a bundle produced.
CLASSIFIERS = ("OUTDATED", "RESOLVED", "DUPLICATE", "OFF_TOPIC", "SPAM", "ABUSE")

RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_RETRY_BODY_MARKERS = ("secondary rate limit", "abuse detection", "rate limit exceeded")


class GitHubError(Exception):
    """Base class. Never carries the token, a header or a request body."""


class HTTPError(GitHubError):
    """A status GitHub returned and the caller has to decide about."""

    def __init__(self, status, method, path, detail=""):
        self.status = status
        self.method = method
        self.path = path
        self.detail = detail
        super().__init__("%s %s -> HTTP %s%s"
                         % (method, path, status, (": " + detail) if detail else ""))


class GraphQLError(GitHubError):
    """GitHub reports GraphQL failures inside a 200 response."""


class RedirectBlocked(GitHubError):
    """A redirect left api.github.com. The caller refetches it without the token."""

    def __init__(self, location):
        self.location = location
        super().__init__("refused to follow a redirect to another host")


def split_repo(repo):
    owner, _, name = str(repo).partition("/")
    if not owner or not name or "/" in name:
        raise GitHubError("repository must be owner/name, got %r" % str(repo)[:80])
    return owner, name


def quote_path(path):
    """Percent-encode a repository path for a REST URL.

    A file name may legally contain `#` or `?`, which would otherwise end the path
    component and silently turn a content lookup into a lookup of something else.
    """
    return urllib.parse.quote(str(path), safe="/")


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that would carry the Authorization header off-host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        here = urllib.parse.urlsplit(req.full_url).netloc.lower()
        there = urllib.parse.urlsplit(newurl).netloc.lower()
        if there and there != here:
            raise RedirectBlocked(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHub:
    """One authenticated client. Construct it once per job and share it."""

    def __init__(self, token, api=API, timeout_s=TIMEOUT_S, retries=RETRIES,
                 sleep=time.sleep, opener=None, log=None, user_agent=USER_AGENT):
        self._token = token or ""
        self.api = api.rstrip("/")
        self.timeout_s = timeout_s
        self.retries = retries
        self._sleep = sleep
        self._log = log or (lambda message: print(message, flush=True))
        self.user_agent = user_agent
        self._opener = opener or urllib.request.build_opener(_NoCrossHostRedirect)
        self._login = None
        self.calls = 0

    def __repr__(self):
        return "GitHub(api=%r, token=%s)" % (self.api, "set" if self._token else "unset")

    # ---------------------------------------------------------------- plumbing

    def _redact(self, text):
        """Last line of defence: no message leaves this object carrying the token."""
        text = str(text)
        if self._token and len(self._token) >= 8:
            text = text.replace(self._token, "***")
        return text

    def log(self, message):
        self._log(self._redact(message))

    def _headers(self, payload, accept):
        headers = {"Authorization": "Bearer %s" % self._token,
                   "Accept": accept or ACCEPT,
                   "X-GitHub-Api-Version": API_VERSION,
                   "User-Agent": self.user_agent}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        return headers

    def _backoff(self, attempt, response_headers):
        """Honour Retry-After, then the rate-limit reset, then exponential backoff."""
        for name in ("Retry-After", "retry-after"):
            raw = (response_headers or {}).get(name) if response_headers else None
            if raw:
                try:
                    return min(MAX_BACKOFF_S, max(0.0, float(raw)))
                except (TypeError, ValueError):
                    break
        delay = min(MAX_BACKOFF_S, BACKOFF_S * (2 ** attempt))
        return delay * (0.5 + random.random() / 2)   # jitter: parallel jobs retry apart

    def request(self, path, payload=None, method=None, accept=None):
        """One API call with retries. Returns parsed JSON, or {} for an empty body."""
        url = path if path.startswith("http") else self.api + path
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        verb = method or ("POST" if data is not None else "GET")
        last = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data,
                                         headers=self._headers(payload, accept), method=verb)
            try:
                self.calls += 1
                with self._opener.open(req, timeout=self.timeout_s) as response:
                    body = response.read().decode("utf-8", "replace")
                return json.loads(body) if body.strip() else {}
            except urllib.error.HTTPError as exc:
                detail = _detail(exc)
                retryable = exc.code in RETRY_STATUSES or (
                    exc.code == 403 and _looks_throttled(detail, exc.headers))
                last = HTTPError(exc.code, verb, path, self._redact(detail))
                if not retryable or attempt >= self.retries:
                    raise last
                self._sleep(self._backoff(attempt, exc.headers))
            except RedirectBlocked:
                raise
            except (urllib.error.URLError, http.client.HTTPException,
                    socket.timeout, OSError, ValueError) as exc:
                last = GitHubError("%s %s failed: %s" % (verb, path, self._redact(exc)))
                if attempt >= self.retries:
                    raise last
                self._sleep(self._backoff(attempt, None))
        raise last   # unreachable while retries >= 0, kept so the contract is explicit

    def get(self, path, accept=None):
        return self.request(path, accept=accept)

    def post(self, path, payload):
        return self.request(path, payload, method="POST")

    def patch(self, path, payload):
        return self.request(path, payload, method="PATCH")

    def delete(self, path):
        return self.request(path, method="DELETE")

    def paginated(self, path, cap=None):
        """GET every page of a list endpoint, in the order GitHub returns them."""
        sep = "&" if "?" in path else "?"
        items, page = [], 1
        while True:
            chunk = self.get("%s%sper_page=%d&page=%d" % (path, sep, PAGE_SIZE, page))
            if not isinstance(chunk, list) or not chunk:
                break
            items.extend(chunk)
            if cap is not None and len(items) >= cap:
                return items[:cap]
            if len(chunk) < PAGE_SIZE:
                break
            page += 1
        return items

    # ------------------------------------------------------------ pull request

    def pull_request(self, repo, number):
        return self.get("/repos/%s/pulls/%d" % (repo, int(number)))

    def live_head_sha(self, repo, number):
        """The head SHA GitHub has right now. The freshness gate's only source."""
        return ((self.pull_request(repo, number).get("head") or {}).get("sha") or "")

    def pull_files(self, repo, number, expected=None):
        """Changed files with their patches, and whether the listing is short.

        `expected` is the PR's own `changed_files` count; when it exceeds what the
        endpoint served, files were dropped and the run cannot claim to have seen
        the whole diff.
        """
        files = self.paginated("/repos/%s/pulls/%d/files" % (repo, int(number)),
                               cap=MAX_PR_FILES)
        truncated = len(files) >= MAX_PR_FILES
        if expected is not None and isinstance(expected, int) and expected > len(files):
            truncated = True
        return files, truncated

    def pull_commits(self, repo, number):
        return self.paginated("/repos/%s/pulls/%d/commits" % (repo, int(number)))

    def contents(self, repo, path, ref):
        """GET a file's metadata at a ref. Raises HTTPError(404) when it is absent."""
        return self.get("/repos/%s/contents/%s?ref=%s"
                        % (repo, quote_path(path), urllib.parse.quote(str(ref), safe="")))

    # --------------------------------------------------------------- comments

    def issue_comments(self, repo, number):
        return self.paginated("/repos/%s/issues/%d/comments" % (repo, int(number)))

    def create_issue_comment(self, repo, number, body):
        return self.post("/repos/%s/issues/%d/comments" % (repo, int(number)),
                         {"body": body})

    def review_comments(self, repo, number):
        return self.paginated("/repos/%s/pulls/%d/comments" % (repo, int(number)))

    def create_review(self, repo, number, payload):
        return self.post("/repos/%s/pulls/%d/reviews" % (repo, int(number)), payload)

    def create_review_comment(self, repo, number, payload):
        """POST /pulls/{n}/comments.

        This is the only endpoint that accepts `subject_type: "file"`; inside the
        `comments[]` array of a review it is rejected, so a file-level fallback has
        to be posted one comment at a time.
        """
        return self.post("/repos/%s/pulls/%d/comments" % (repo, int(number)), payload)

    def reply_to_review_comment(self, repo, number, comment_id, body):
        return self.post("/repos/%s/pulls/%d/comments/%d/replies"
                         % (repo, int(number), int(comment_id)), {"body": body})

    # ------------------------------------------------------------- check runs

    def create_check_run(self, repo, payload):
        return self.post("/repos/%s/check-runs" % repo, payload)

    def update_check_run(self, repo, check_run_id, payload):
        return self.patch("/repos/%s/check-runs/%d" % (repo, int(check_run_id)), payload)

    def check_runs_for_ref(self, repo, ref, check_name=None):
        path = "/repos/%s/commits/%s/check-runs" % (repo, urllib.parse.quote(str(ref), safe=""))
        if check_name:
            path += "?check_name=" + urllib.parse.quote(check_name, safe="")
        payload = self.get(path)
        runs = payload.get("check_runs") if isinstance(payload, dict) else None
        return runs or []

    # ---------------------------------------------------------------- identity

    def reviewer_login(self):
        """Login this token posts as.

        GET /user is refused for the Actions GITHUB_TOKEN and for app installation
        tokens; both post as github-actions[bot].
        """
        if self._login is None:
            try:
                self._login = self.get("/user").get("login") or ACTIONS_BOT
            except GitHubError:
                self._login = ACTIONS_BOT
        return self._login

    # ----------------------------------------------------------------- GraphQL

    def graphql(self, query, variables):
        data = self.request("/graphql", {"query": query, "variables": variables})
        if data.get("errors"):
            raise GraphQLError(self._redact(
                "; ".join(str(e.get("message", e)) for e in data["errors"])))
        return data.get("data") or {}

    def minimize(self, node_id, classifier="OUTDATED"):
        if classifier not in CLASSIFIERS:
            raise GitHubError("unknown minimize classifier %r" % str(classifier)[:40])
        # The classifier is a GraphQL enum literal, so it cannot be a variable; it
        # comes from CLASSIFIERS above and never from a bundle.
        mutation = MINIMIZE_MUTATION % classifier
        return self.graphql(mutation, {"id": node_id})

    def unminimize(self, node_id):
        return self.graphql(UNMINIMIZE_MUTATION, {"id": node_id})

    def resolve_review_thread(self, thread_id):
        return self.graphql(RESOLVE_THREAD_MUTATION, {"id": thread_id})

    def minimized_state(self, node_ids):
        """Map node id -> isMinimized for issue comments and review comments.

        Both types implement Minimizable. An id we cannot resolve is reported as
        not minimized so the caller tries and logs the failure, rather than
        silently leaving an outdated comment visible.
        """
        state = {}
        ids = [i for i in node_ids if i]
        for start in range(0, len(ids), 100):        # the nodes query takes 100 ids
            chunk = ids[start:start + 100]
            try:
                nodes = self.graphql(MINIMIZED_QUERY, {"ids": chunk}).get("nodes") or []
            except GitHubError as exc:
                self.log("warning: could not read comment state (%s)" % exc)
                for node_id in chunk:
                    state.setdefault(node_id, False)
                continue
            for node in nodes:
                if node and node.get("id"):
                    state[node["id"]] = bool(node.get("isMinimized"))
            for node_id in chunk:
                state.setdefault(node_id, False)
        return state

    def hide_outdated(self, comments, classifier="OUTDATED"):
        """Minimize earlier comments, skipping those a previous run already hid.

        Never fatal: the new comment is already posted, so a failure here only
        leaves an old one visible. Returns the node ids that were hidden.
        """
        ids = [c["node_id"] for c in comments if isinstance(c, dict) and c.get("node_id")]
        state = self.minimized_state(ids)
        hidden = []
        for node_id in ids:
            if state.get(node_id):
                continue
            try:
                self.minimize(node_id, classifier)
                hidden.append(node_id)
                self.log("hid earlier comment %s as %s" % (node_id, classifier.lower()))
            except GitHubError as exc:
                self.log("warning: could not hide comment %s (%s)" % (node_id, exc))
        return hidden

    def review_threads(self, repo, number, page_cap=20):
        """Every review thread with its comments, flattened for the dedupe pass."""
        owner, name = split_repo(repo)
        threads, cursor = [], None
        for _page in range(page_cap):
            data = self.graphql(REVIEW_THREADS_QUERY,
                                {"owner": owner, "name": name,
                                 "number": int(number), "cursor": cursor})
            block = (((data.get("repository") or {}).get("pullRequest") or {})
                     .get("reviewThreads") or {})
            for node in block.get("nodes") or []:
                if not node:
                    continue
                comments = [c for c in ((node.get("comments") or {}).get("nodes") or []) if c]
                threads.append({"id": node.get("id"),
                                "is_resolved": bool(node.get("isResolved")),
                                "is_outdated": bool(node.get("isOutdated")),
                                "comments": comments})
            info = block.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                break
            cursor = info.get("endCursor")
        return threads


def _detail(exc):
    """A short, safe excerpt of an error body: GitHub's message, never our request."""
    try:
        raw = exc.read().decode("utf-8", "replace")
    except (OSError, AttributeError, ValueError):
        return ""
    try:
        payload = json.loads(raw)
    except ValueError:
        return raw.strip()[:200]
    if isinstance(payload, dict):
        message = str(payload.get("message") or "").strip()
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                extra = str(first.get("message") or first.get("code") or "").strip()
                if extra:
                    message = (message + " (" + extra + ")").strip()
        return message[:200]
    return raw.strip()[:200]


def _looks_throttled(detail, headers):
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in _RETRY_BODY_MARKERS):
        return True
    remaining = (headers or {}).get("X-RateLimit-Remaining") if headers else None
    return str(remaining) == "0"


MINIMIZED_QUERY = """query($ids: [ID!]!) {
  nodes(ids: $ids) {
    ... on IssueComment { id isMinimized }
    ... on PullRequestReviewComment { id isMinimized }
  }
}"""

MINIMIZE_MUTATION = """mutation($id: ID!) {
  minimizeComment(input: {subjectId: $id, classifier: %s}) {
    minimizedComment { isMinimized }
  }
}"""

UNMINIMIZE_MUTATION = """mutation($id: ID!) {
  unminimizeComment(input: {subjectId: $id}) { unminimizedComment { isMinimized } }
}"""

RESOLVE_THREAD_MUTATION = """mutation($id: ID!) {
  resolveReviewThread(input: {threadId: $id}) { thread { isResolved } }
}"""

REVIEW_THREADS_QUERY = """query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 50, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          comments(first: 50) {
            nodes { id databaseId body isMinimized author { login } }
          }
        }
      }
    }
  }
}"""
