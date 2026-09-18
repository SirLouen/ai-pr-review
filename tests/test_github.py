"""Tests for the shared GitHub client.

Every test runs against a loopback `http.server` fake; nothing here touches the
network. Where a test asserts a control works, it also asserts the failure
reproduces once the control is removed - otherwise it would pass against a client
that does nothing at all.
"""
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import github
from prreview.security.github import (ACTIONS_BOT, GitHub, GitHubError, GraphQLError,
                                      HTTPError, MAX_PR_FILES, RedirectBlocked, quote_path,
                                      split_repo)
from tests.fakehub import FakeGitHub, State

TOKEN = "ghs_ThisIsTheWriteTokenAndMustNeverBeLogged"


class ClientTestCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.addCleanup(self.fake.close)
        self.state = self.fake.state
        self.logs = []
        self.slept = []
        self.gh = GitHub(TOKEN, api=self.fake.url, retries=3,
                         sleep=self.slept.append, log=self.logs.append)

    def last_auth(self):
        return self.state.requests[-1]["headers"].get("Authorization")


class TestRequest(ClientTestCase):
    def test_get_sends_the_token_in_a_header_only(self):
        self.gh.pull_request("octo/demo", 7)
        self.assertEqual(self.last_auth(), "Bearer " + TOKEN)
        self.assertNotIn(TOKEN, self.state.requests[-1]["path"])

    def test_empty_body_is_an_empty_dict(self):
        self.assertEqual(self.gh.request("/noop", method="DELETE"), {})

    def test_404_raises_with_no_token_in_the_message(self):
        with self.assertRaises(HTTPError) as caught:
            self.gh.get("/repos/octo/demo/does-not-exist")
        self.assertEqual(caught.exception.status, 404)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_403_is_not_retried(self):
        self.state.fail_once("GET /repos/octo/demo/pulls/7", 403, "Resource not accessible")
        with self.assertRaises(HTTPError) as caught:
            self.gh.pull_request("octo/demo", 7)
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.slept, [])

    def test_secondary_rate_limit_403_is_retried(self):
        self.state.fail_once("GET /repos/octo/demo/pulls/7", 403,
                             "You have exceeded a secondary rate limit")
        payload = self.gh.pull_request("octo/demo", 7)
        self.assertEqual(payload["head"]["sha"], self.state.head_sha)
        self.assertEqual(len(self.slept), 1)

    def test_500_is_retried_then_succeeds(self):
        for _ in range(2):
            self.state.fail_once("GET /repos/octo/demo/pulls/7", 500, "boom")
        self.gh.pull_request("octo/demo", 7)
        self.assertEqual(len(self.slept), 2)

    def test_retries_are_bounded(self):
        for _ in range(10):
            self.state.fail_once("GET /repos/octo/demo/pulls/7", 502, "bad gateway")
        with self.assertRaises(HTTPError):
            self.gh.pull_request("octo/demo", 7)
        self.assertEqual(len(self.slept), 3)      # retries=3 means three sleeps, four tries

    def test_retry_after_header_is_honoured(self):
        # Exercised through _backoff directly: the fake cannot set a header per failure.
        self.assertEqual(self.gh._backoff(0, {"Retry-After": "12"}), 12.0)
        self.assertLessEqual(self.gh._backoff(0, {"Retry-After": "9999"}), github.MAX_BACKOFF_S)
        self.assertGreater(self.gh._backoff(3, None), 0.0)

    def test_422_is_never_retried(self):
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 422, "line not part of diff")
        with self.assertRaises(HTTPError) as caught:
            self.gh.create_review("octo/demo", 7, {"event": "COMMENT"})
        self.assertEqual(caught.exception.status, 422)
        self.assertEqual(self.slept, [])


class TestTokenHygiene(ClientTestCase):
    def test_repr_hides_the_token(self):
        self.assertNotIn(TOKEN, repr(self.gh))
        self.assertIn("token=set", repr(self.gh))

    def test_every_log_line_is_redacted(self):
        self.gh.log("about to use %s for the write" % TOKEN)
        self.assertEqual(self.logs, ["about to use *** for the write"])

    def test_error_bodies_are_redacted(self):
        # A GitHub error body that echoes the token back must not survive into ours.
        self.state.fail_once("GET /repos/octo/demo/pulls/7", 404,
                             "token %s is not valid" % TOKEN)
        with self.assertRaises(HTTPError) as caught:
            self.gh.pull_request("octo/demo", 7)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertIn("***", str(caught.exception))

    def test_redaction_is_the_control(self):
        """Without _redact the same message would carry the token."""
        raw = "token %s is not valid" % TOKEN
        self.assertIn(TOKEN, raw)
        self.assertNotIn(TOKEN, self.gh._redact(raw))

    def test_graphql_errors_are_redacted(self):
        self.assertRaises(GraphQLError, self.gh.graphql, "query { unknown }", {})
        try:
            self.gh.graphql("query { unknown }", {})
        except GraphQLError as exc:
            self.assertNotIn(TOKEN, str(exc))


class TestRedirects(unittest.TestCase):
    """urllib copies every header across a redirect, including Authorization."""

    def test_cross_host_redirect_is_refused(self):
        gh = GitHub(TOKEN, api="https://api.github.test")
        handler = github._NoCrossHostRedirect()
        request = urllib.request.Request("https://api.github.test/repos/o/r/zip")
        with self.assertRaises(RedirectBlocked) as caught:
            handler.redirect_request(request, None, 302, "Found", {},
                                     "https://blob.example.com/x")
        self.assertIn("blob.example.com", caught.exception.location)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_same_host_redirect_is_followed(self):
        handler = github._NoCrossHostRedirect()
        request = urllib.request.Request("https://api.github.test/repos/o/r")
        request.add_header("Authorization", "Bearer x")
        new = handler.redirect_request(request, None, 301, "Moved", {},
                                       "https://api.github.test/repos/o/r2")
        self.assertIsNotNone(new)

    def test_the_stock_handler_would_forward_the_header(self):
        """Control removed: urllib's own handler carries Authorization off-host."""
        handler = urllib.request.HTTPRedirectHandler()
        request = urllib.request.Request("https://api.github.test/repos/o/r/zip")
        request.add_header("Authorization", "Bearer " + TOKEN)
        new = handler.redirect_request(request, None, 302, "Found", {},
                                       "https://blob.example.com/x")
        carried = {k.lower(): v for k, v in new.header_items()}
        self.assertIn("authorization", carried)


class TestPagination(ClientTestCase):
    def test_every_page_is_fetched(self):
        for index in range(250):
            self.state.add_file("src/f%03d.ts" % index, "@@ -0,0 +1 @@\n+x\n")
        files, truncated = self.gh.pull_files("octo/demo", 7)
        self.assertEqual(len(files), 250)
        self.assertFalse(truncated)

    def test_three_thousand_file_cap_is_reported(self):
        for index in range(MAX_PR_FILES + 10):
            self.state.add_file("src/f%05d.ts" % index, "")
        files, truncated = self.gh.pull_files("octo/demo", 7)
        self.assertEqual(len(files), MAX_PR_FILES)
        self.assertTrue(truncated)

    def test_a_short_listing_against_changed_files_is_truncation(self):
        self.state.add_file("src/a.ts", "")
        files, truncated = self.gh.pull_files("octo/demo", 7, expected=9)
        self.assertEqual(len(files), 1)
        self.assertTrue(truncated)

    def test_cap_stops_paging(self):
        for index in range(300):
            self.state.add_file("src/f%03d.ts" % index, "")
        self.assertEqual(len(self.gh.paginated("/repos/octo/demo/pulls/7/files", cap=120)), 120)


class TestIdentity(ClientTestCase):
    def test_forbidden_user_endpoint_falls_back_to_the_bot(self):
        self.state.user_status = 403
        self.assertEqual(self.gh.reviewer_login(), ACTIONS_BOT)

    def test_login_is_cached(self):
        self.state.user_status = 200
        self.state.login = "some-app[bot]"
        self.assertEqual(self.gh.reviewer_login(), "some-app[bot]")
        before = len(self.state.requests)
        self.gh.reviewer_login()
        self.assertEqual(len(self.state.requests), before)


class TestGraphQL(ClientTestCase):
    def test_errors_inside_a_200_raise(self):
        with self.assertRaises(GraphQLError):
            self.gh.graphql("query { nope }", {})

    def test_unknown_classifier_is_refused(self):
        with self.assertRaises(GitHubError):
            self.gh.minimize("IC_1", "DEFINITELY_NOT_A_CLASSIFIER")
        self.assertEqual(self.state.minimized, [])

    def test_minimize_passes_the_enum_literal(self):
        comment = self.state.add_issue_comment("hello")
        self.gh.minimize(comment["node_id"], "RESOLVED")
        self.assertEqual(self.state.minimized, [(comment["node_id"], "RESOLVED")])

    def test_review_comments_are_minimizable_too(self):
        """Both IssueComment and PullRequestReviewComment implement Minimizable."""
        comment = self.state.add_review_comment("lead")
        state = self.gh.minimized_state([comment["node_id"]])
        self.assertEqual(state, {comment["node_id"]: False})

    def test_hide_outdated_skips_already_hidden(self):
        first = self.state.add_issue_comment("one")
        second = self.state.add_issue_comment("two")
        self.state.minimized.append((first["node_id"], "OUTDATED"))
        hidden = self.gh.hide_outdated([first, second])
        self.assertEqual(hidden, [second["node_id"]])

    def test_hide_outdated_never_raises(self):
        for _ in range(8):      # four tries to read state, four to minimize
            self.state.fail_once("POST /graphql", 500, "down")
        comment = self.state.add_issue_comment("one")
        self.assertEqual(self.gh.hide_outdated([comment]), [])
        self.assertTrue(any("could not read comment state" in line for line in self.logs))
        self.assertTrue(any("could not hide comment" in line for line in self.logs))

    def test_review_threads_are_flattened(self):
        comment = self.state.add_review_comment("lead")
        thread = self.state.add_thread(comment)
        threads = self.gh.review_threads("octo/demo", 7)
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["id"], thread["id"])
        self.assertEqual(threads[0]["comments"][0]["id"], comment["node_id"])


class TestHelpers(unittest.TestCase):
    def test_split_repo(self):
        self.assertEqual(split_repo("octo/demo"), ("octo", "demo"))
        self.assertRaises(GitHubError, split_repo, "octo")
        self.assertRaises(GitHubError, split_repo, "octo/demo/extra")

    def test_quote_path_encodes_hash_and_question_mark(self):
        """A legal file name must not be able to truncate a REST URL."""
        self.assertEqual(quote_path("src/a#b?c.ts"), "src/a%23b%3Fc.ts")
        self.assertEqual(quote_path("src/dir/x.ts"), "src/dir/x.ts")
        self.assertIn("%20", quote_path("src/a b.ts"))

    def test_unquoted_path_would_split_the_url(self):
        """Control removed: the raw path ends the URL at the first '#'."""
        raw = "/repos/o/r/contents/" + "src/a#b.ts" + "?ref=deadbeef"
        self.assertEqual(urllib.parse.urlsplit(raw).path, "/repos/o/r/contents/src/a")
        safe = "/repos/o/r/contents/" + quote_path("src/a#b.ts") + "?ref=deadbeef"
        self.assertEqual(urllib.parse.urlsplit(safe).path,
                         "/repos/o/r/contents/src/a%23b.ts")

    def test_detail_extracts_the_message(self):
        class _Fake:
            def read(self):
                return json.dumps({"message": "Validation Failed",
                                   "errors": [{"message": "line must be part of the diff"}]
                                   }).encode()
        self.assertEqual(github._detail(_Fake()),
                         "Validation Failed (line must be part of the diff)")

    def test_looks_throttled(self):
        self.assertTrue(github._looks_throttled("secondary rate limit", None))
        self.assertTrue(github._looks_throttled("", {"X-RateLimit-Remaining": "0"}))
        self.assertFalse(github._looks_throttled("Resource not accessible", {}))


class TestContents(ClientTestCase):
    def test_missing_path_is_a_404(self):
        self.state.present_paths = {"src/app.ts"}
        self.gh.contents("octo/demo", "src/app.ts", "a" * 40)
        with self.assertRaises(HTTPError) as caught:
            self.gh.contents("octo/demo", "src/gone.ts", "a" * 40)
        self.assertEqual(caught.exception.status, 404)

    def test_path_with_a_hash_reaches_the_server_intact(self):
        self.state.present_paths = {"src/a#b.ts"}
        self.gh.contents("octo/demo", "src/a#b.ts", "a" * 40)
        self.assertEqual(self.state.requests[-1]["path"], "/repos/octo/demo/contents/src/a%23b.ts")


class TestCheckRuns(ClientTestCase):
    def test_create_and_complete(self):
        run = self.gh.create_check_run("octo/demo", {"name": "x", "head_sha": "a" * 40,
                                                     "status": "in_progress"})
        self.gh.update_check_run("octo/demo", run["id"],
                                 {"status": "completed", "conclusion": "neutral"})
        self.assertEqual(self.state.check_runs[0]["conclusion"], "neutral")

    def test_lookup_by_ref_and_name(self):
        self.gh.create_check_run("octo/demo", {"name": "x", "head_sha": "a" * 40})
        self.gh.create_check_run("octo/demo", {"name": "y", "head_sha": "a" * 40})
        runs = self.gh.check_runs_for_ref("octo/demo", "a" * 40, check_name="y")
        self.assertEqual([r["name"] for r in runs], ["y"])


if __name__ == "__main__":
    unittest.main()
