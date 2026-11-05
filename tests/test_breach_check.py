"""Unit tests for breach_check. No network: urllib.request.urlopen is mocked."""

import io
import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import breach_check as bc  # noqa: E402

CATALOG = {
    "status": "success",
    "exposedBreaches": [
        {
            "breachID": "Adobe",
            "breachedDate": "2013-10-04T00:00:00",
            "domain": "adobe.com",
            "exposedData": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "exposedRecords": 152445165,
        },
        {
            "breachID": "LinkedIn",
            "breachedDate": "2012-05-05T00:00:00",
            "domain": "linkedin.com",
            "exposedData": ["Email addresses", "Passwords"],
            "exposedRecords": 164611595,
        },
    ],
}


# ---------------------------------------------------------------- helpers

class FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(url, code, body=b"", headers=None):
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    return urllib.error.HTTPError(url, code, "err", msg, io.BytesIO(payload))


class FakeServer:
    """Routes requests by URL. Each route is a list of responses consumed in order
    (the last one repeats). A response is a FakeResponse, an exception, or a callable."""

    def __init__(self, catalog=CATALOG, emails=None):
        if not isinstance(catalog, (Exception, FakeResponse)):
            catalog = FakeResponse(200, catalog)
        self.routes = {"/v1/breaches": [catalog]}
        for email, responses in (emails or {}).items():
            self.routes[f"/v1/check-email/{email}"] = list(responses)
        self.calls = []

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        assert url.startswith("https://"), url
        assert req.get_header("User-agent", "").startswith("breach_check/")
        assert timeout == bc.REQUEST_TIMEOUT
        path = url.split("api.xposedornot.com", 1)[1]
        queue = self.routes.get(path)
        if queue is None:
            raise AssertionError(f"unexpected URL {url}")
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, int):  # bare status -> HTTPError
            raise http_error(url, item)
        if isinstance(item, tuple):  # (status, body, headers) -> HTTPError
            raise http_error(url, *item)
        return item


def found(*names):
    return FakeResponse(200, {"breaches": [list(names)], "email": "x", "status": "success"})


NOT_FOUND_404 = (404, {"Error": "Not found"})
NOT_FOUND_200 = FakeResponse(200, {"Error": "Not found", "email": None})


def make_provider(sleeps=None):
    sleeps = sleeps if sleeps is not None else []
    clock = [0.0]

    def sleep(s):
        sleeps.append(s)
        clock[0] += s

    def now():
        clock[0] += 0.01
        return clock[0]

    return bc.XposedOrNotProvider(sleep=sleep, clock=now)


def run_cli(argv, server, providers=None):
    out, err = io.StringIO(), io.StringIO()
    reg = providers or {"xposedornot": make_provider}
    with mock.patch.object(bc.urllib.request, "urlopen", server), \
            mock.patch.dict(bc.PROVIDERS, reg, clear=True):
        code = bc.run(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- input handling

class TestEmailInput(unittest.TestCase):
    def test_normalize_dedupe_and_validate(self):
        valid, skipped = bc.normalize_emails([
            " Jane.Doe@Example.com ", "jane.doe@example.com", "JANE.DOE@EXAMPLE.COM",
            "jane+news@gmail.com", "not-an-email", "a b@c.com", "x@y", "old@example.net"])
        self.assertEqual(valid, ["jane.doe@example.com", "jane+news@gmail.com", "old@example.net"])
        self.assertEqual([s["input"] for s in skipped], ["not-an-email", "a b@c.com", "x@y"])
        self.assertTrue(all(s["reason"] == "invalid email format" for s in skipped))

    def test_plus_tags_and_dots_kept(self):
        valid, _ = bc.normalize_emails(["j.a.n.e+tag@gmail.com"])
        self.assertEqual(valid, ["j.a.n.e+tag@gmail.com"])

    def test_emails_file_bom_crlf_comments_blanks(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "emails.txt"
            p.write_bytes("﻿a@example.com\r\n# comment\r\n\r\n  b@example.com  \r\n   \r\n"
                          .encode("utf-8"))
            self.assertEqual(bc.read_emails_file(p), ["a@example.com", "b@example.com"])

    def test_slugify(self):
        self.assertEqual(bc.slugify("Jane Doe"), "jane-doe")
        self.assertEqual(bc.slugify("Jöhn  Dœ!"), "john-d")
        self.assertEqual(bc.slugify("张伟"), "report")


# ---------------------------------------------------------------- provider

class TestXposedOrNotProvider(unittest.TestCase):
    def check(self, responses, catalog=CATALOG, email="a@example.com"):
        sleeps = []
        server = FakeServer(catalog, {email: responses})
        prov = make_provider(sleeps)
        with mock.patch.object(bc.urllib.request, "urlopen", server):
            result = prov.check_email(email)
        return result, sleeps, server, prov

    def test_found_enriched_and_deduplicated(self):
        r, _, _, prov = self.check([FakeResponse(200, {
            "breaches": [["adobe", "LinkedIn", "Adobe", "UnknownCo"]], "status": "success"})])
        self.assertEqual(r.status, "found")
        self.assertEqual([b.name for b in r.breaches], ["adobe", "LinkedIn", "UnknownCo"])
        adobe = r.breaches[0]  # case-insensitive catalog match
        self.assertEqual((adobe.domain, adobe.breach_date, adobe.record_count),
                         ("adobe.com", "2013-10-04", 152445165))
        self.assertIn("Passwords", adobe.data_classes)
        unknown = r.breaches[2]  # unmatched name: only name filled
        self.assertEqual(unknown, bc.Breach(name="UnknownCo"))
        self.assertEqual(prov.warnings, [])

    def test_not_found_404(self):
        r, *_ = self.check([NOT_FOUND_404])
        self.assertEqual((r.status, r.breaches, r.error), ("not_found", [], None))

    def test_not_found_200_error_body(self):
        r, *_ = self.check([NOT_FOUND_200])
        self.assertEqual(r.status, "not_found")

    def test_429_with_retry_after(self):
        r, sleeps, *_ = self.check([(429, {}, {"Retry-After": "5"}), found("Adobe")])
        self.assertEqual(r.status, "found")
        self.assertIn(5.0, sleeps)

    def test_429_without_retry_after_backs_off_then_errors(self):
        r, sleeps, server, _ = self.check([429])
        self.assertEqual(r.status, "error")
        self.assertIn("rate limited by xposedornot", r.error)
        backoffs = [s for s in sleeps if s >= 2]
        self.assertEqual(backoffs, [2, 4, 8])
        email_calls = [c for c in server.calls if "check-email" in c]
        self.assertEqual(len(email_calls), 4)  # 1 try + 3 retries

    def test_timeout_retried_once_then_error(self):
        r, sleeps, server, _ = self.check([socket.timeout("timed out")])
        self.assertEqual(r.status, "error")
        self.assertIn("could not reach xposedornot", r.error)
        self.assertEqual(len([c for c in server.calls if "check-email" in c]), 2)

    def test_timeout_then_success(self):
        r, *_ = self.check([urllib.error.URLError("conn refused"), found("Adobe")])
        self.assertEqual(r.status, "found")

    def test_5xx_retried_once_then_error(self):
        r, _, server, _ = self.check([503])
        self.assertEqual(r.status, "error")
        self.assertIn("HTTP 503", r.error)
        self.assertEqual(len([c for c in server.calls if "check-email" in c]), 2)

    def test_malformed_json(self):
        r, *_ = self.check([FakeResponse(200, b"<html>oops</html>")])
        self.assertEqual(r.status, "error")
        self.assertIn("non-JSON", r.error)

    def test_unexpected_shape(self):
        for body in ({"breaches": "nope"}, {"something": 1}, [1, 2], {"breaches": [[1]]}):
            with self.subTest(body=body):
                r, *_ = self.check([FakeResponse(200, body)])
                self.assertEqual(r.status, "error")

    def test_catalog_failure_names_only_with_warning(self):
        r, _, _, prov = self.check([found("Adobe")], catalog=urllib.error.URLError("down"))
        self.assertEqual(r.status, "found")
        self.assertEqual(r.breaches, [bc.Breach(name="Adobe")])
        self.assertEqual(len(prov.warnings), 1)
        self.assertIn("catalog", prov.warnings[0])

    def test_catalog_loaded_once_and_rate_limited(self):
        sleeps = []
        server = FakeServer(CATALOG, {"a@x.com": [NOT_FOUND_404], "b@x.com": [found("Adobe")]})
        prov = make_provider(sleeps)
        with mock.patch.object(bc.urllib.request, "urlopen", server):
            prov.check_email("a@x.com")
            prov.check_email("b@x.com")
        self.assertEqual(sum("/breaches" in c for c in server.calls), 1)
        self.assertEqual(len(server.calls), 3)
        # Two waits between three back-to-back requests, each ~1.1s.
        self.assertEqual(len(sleeps), 2)
        self.assertTrue(all(1.0 < s <= bc.MIN_REQUEST_INTERVAL for s in sleeps))

    def test_only_email_sent_and_https(self):
        _, _, server, _ = self.check([found("Adobe")], email="jane+news@gmail.com")
        self.assertIn("https://api.xposedornot.com/v1/check-email/jane+news@gmail.com", server.calls)


# ---------------------------------------------------------------- CLI / exit codes

class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = str(Path(self.tmp.name) / "report.json")

    def tearDown(self):
        self.tmp.cleanup()

    def load(self):
        return json.loads(Path(self.out).read_text(encoding="utf-8"))

    def test_exit_0_clean(self):
        server = FakeServer(emails={"a@example.com": [NOT_FOUND_404]})
        code, out, _ = run_cli(["--name", "Jane", "--email", "a@example.com", "--output", self.out], server)
        self.assertEqual(code, 0)
        self.assertIn("a@example.com — not found in any known breach", out)
        self.assertIs(self.load()["results"][0]["exposed"], False)

    def test_exit_1_sample_scenario_and_json_shape(self):
        server = FakeServer(emails={
            "jane.doe@example.com": [found("Adobe", "LinkedIn")],
            "old-handle@example.net": [NOT_FOUND_404],
        })
        code, out, err = run_cli([
            "--name", "Jane Doe", "--email", "jane.doe@example.com", "--email", "JANE.DOE@example.com",
            "--email", "old-handle@example.net", "--email", "not-an-email", "--output", self.out], server)
        self.assertEqual(code, 1)
        self.assertIn('warning: skipping invalid email "not-an-email"', err)
        self.assertNotIn("warning", out)
        self.assertIn("Breach exposure report for Jane Doe", out)
        self.assertIn("jane.doe@example.com — FOUND in 2 breaches", out)
        self.assertIn("  • Adobe (adobe.com), 2013-10-04", out)
        self.assertIn("    Exposed: Email addresses, Password hints, Passwords, Usernames", out)
        self.assertIn("Skipped (invalid): not-an-email", out)
        self.assertIn("Summary: 1 of 2 addresses exposed, 2 unique breaches.", out)
        self.assertIn("Most common exposed data: Email addresses (2), Passwords (2)", out)
        self.assertIn("Breach data from XposedOrNot (https://xposedornot.com).", out)
        self.assertEqual(sum("check-email" in c for c in server.calls), 2)  # dup checked once

        report = self.load()
        self.assertEqual(set(report), {"schema_version", "name", "generated_at", "complete",
                                       "providers_used", "warnings", "skipped", "results", "summary"})
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["name"], "Jane Doe")
        self.assertTrue(report["complete"])
        self.assertEqual(report["providers_used"], ["xposedornot"])
        self.assertEqual(report["skipped"], [{"input": "not-an-email", "reason": "invalid email format"}])
        self.assertEqual(report["summary"], {"emails_checked": 2, "emails_exposed": 1,
                                             "unique_breaches": 2, "lookup_errors": 0})
        first = report["results"][0]
        self.assertEqual(set(first), {"email", "exposed", "providers"})
        prov = first["providers"][0]
        self.assertEqual(set(prov), {"provider", "status", "error", "breaches"})
        self.assertEqual(prov["breaches"][0], {
            "name": "Adobe", "title": "Adobe", "domain": "adobe.com", "breach_date": "2013-10-04",
            "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "record_count": 152445165})
        self.assertEqual(report["results"][1]["providers"][0],
                         {"provider": "xposedornot", "status": "not_found", "error": None, "breaches": []})
        if os.name != "nt":
            self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o600)

    def test_exit_2_cases(self):
        server = FakeServer()
        cases = [
            ["--email", "a@example.com"],                          # missing --name
            ["--name", "Jane"],                                    # no email source
            ["--name", "Jane", "--email", "nope"],                 # no valid emails
            ["--name", "Jane", "--emails-file", "/no/such/file.txt"],
            ["--name", "Jane", "--email", "a@example.com", "--provider", "bogus"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                with mock.patch("sys.stderr", io.StringIO()):
                    try:
                        code, *_ = run_cli(argv + ["--output", self.out], server)
                    except SystemExit as exc:  # argparse errors
                        code = exc.code
                self.assertEqual(code, 2)
        self.assertEqual(server.calls, [])
        self.assertFalse(Path(self.out).exists())

    def test_exit_2_no_available_provider(self):
        class Unavailable(DummyProvider):
            def is_available(self):
                return False, "DUMMY_API_KEY is not set"
        code, _, err = run_cli(["--name", "J", "--email", "a@example.com", "--output", self.out],
                               FakeServer(), providers={"dummy": Unavailable})
        self.assertEqual(code, 2)
        self.assertIn("DUMMY_API_KEY is not set", err)

    def test_exit_3_partial_failure_takes_precedence(self):
        server = FakeServer(emails={"a@example.com": [found("Adobe")], "b@example.com": [503]})
        code, out, err = run_cli(["--name", "J", "--email", "a@example.com", "--email", "b@example.com",
                                  "--output", self.out], server)
        self.assertEqual(code, 3)
        self.assertIn("b@example.com — could not be checked", out)
        self.assertIn("xposedornot lookup failed for b@example.com", err)
        report = self.load()
        self.assertIsNone(report["results"][1]["exposed"])
        self.assertEqual(report["summary"]["lookup_errors"], 1)

    def test_exit_3_no_network(self):
        server = FakeServer(catalog=urllib.error.URLError("no network"),
                            emails={"a@example.com": [urllib.error.URLError("no network")]})
        code, out, _ = run_cli(["--name", "J", "--email", "a@example.com", "--output", self.out], server)
        self.assertEqual(code, 3)
        self.assertIn("Every lookup failed", out)

    def test_exit_3_unwritable_output_still_prints(self):
        server = FakeServer(emails={"a@example.com": [NOT_FOUND_404]})
        bad = str(Path(self.tmp.name) / "missing-dir" / "r.json")
        code, out, err = run_cli(["--name", "J", "--email", "a@example.com", "--output", bad], server)
        self.assertEqual(code, 3)
        self.assertIn("could not write report", err)
        self.assertIn("Breach exposure report for J", out)

    def test_ctrl_c_writes_partial_report(self):
        server = FakeServer(emails={"a@example.com": [found("Adobe")],
                                    "b@example.com": [KeyboardInterrupt()]})
        code, *_ = run_cli(["--name", "J", "--email", "a@example.com", "--email", "b@example.com",
                            "--email", "c@example.com", "--output", self.out], server)
        self.assertEqual(code, 3)
        report = self.load()
        self.assertFalse(report["complete"])
        self.assertEqual([r["email"] for r in report["results"]], ["a@example.com"])

    def test_quiet_and_catalog_warning_not_a_failure(self):
        server = FakeServer(catalog=FakeResponse(200, b"garbage"),
                            emails={"a@example.com": [found("Adobe")]})
        code, out, err = run_cli(["--name", "J", "--email", "a@example.com", "--quiet",
                                  "--output", self.out], server)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("catalog", err)
        self.assertEqual(len(self.load()["warnings"]), 1)

    def test_default_output_filename(self):
        server = FakeServer(emails={"a@example.com": [NOT_FOUND_404]})
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            code, out, _ = run_cli(["--name", "Jäne Doe", "--email", "a@example.com"], server)
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0)
        files = list(Path(self.tmp.name).glob("breach_report_jane-doe_*.json"))
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0].name, r"^breach_report_jane-doe_\d{8}\.json$")


# ---------------------------------------------------------------- extensibility

class DummyProvider:
    name = "dummy"

    def is_available(self):
        return True, ""

    def check_email(self, email):
        return bc.ProviderResult(self.name, email, "found",
                                 [bc.Breach(name="DummyLeak", data_classes=["Passwords"])], None)


class TestExtensibility(unittest.TestCase):
    def test_second_provider_only_needs_registry_entry(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = str(Path(d) / "r.json")
            server = FakeServer(emails={"a@example.com": [NOT_FOUND_404]})
            registry = {"xposedornot": make_provider, "dummy": DummyProvider}
            code, out, _ = run_cli(["--name", "J", "--email", "a@example.com", "--output", out_path],
                                   server, providers=registry)
            self.assertEqual(code, 1)
            report = json.loads(Path(out_path).read_text(encoding="utf-8"))
            self.assertEqual(report["providers_used"], ["xposedornot", "dummy"])
            statuses = [p["status"] for p in report["results"][0]["providers"]]
            self.assertEqual(statuses, ["not_found", "found"])
            self.assertIn("DummyLeak", out)

            code, *_ = run_cli(["--name", "J", "--email", "a@example.com", "--provider", "dummy",
                                "--output", out_path], FakeServer(), providers=registry)
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
