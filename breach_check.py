#!/usr/bin/env python3
"""breach_check - check your own email addresses against public breach data.

Standard library only. Python 3.10+. See README.md for usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Literal, Protocol, TextIO

VERSION = "1.0"
USER_AGENT = f"breach_check/{VERSION} (+self-check script)"
REQUEST_TIMEOUT = 15  # seconds
MIN_REQUEST_INTERVAL = 1.1  # seconds between requests to the same provider
MAX_RETRY_AFTER = 60  # longest Retry-After we will sleep through, in seconds
SCHEMA_VERSION = 1

EXIT_CLEAN = 0
EXIT_EXPOSED = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------
# Data model and provider interface
# --------------------------------------------------------------------------

@dataclass
class Breach:
    name: str
    title: str | None = None
    domain: str | None = None
    breach_date: str | None = None  # ISO 8601 date, if known
    data_classes: list[str] = field(default_factory=list)
    record_count: int | None = None


@dataclass
class ProviderResult:
    provider: str
    email: str
    status: Literal["found", "not_found", "error"]
    breaches: list[Breach] = field(default_factory=list)
    error: str | None = None


class BreachProvider(Protocol):
    """Interface every data source implements.

    Optional extras the CLI uses if present:
      ``warnings: list[str]``  - non-fatal problems to add to the report
      ``attribution: str``     - credit line printed under the report
    """

    name: str

    def is_available(self) -> tuple[bool, str]: ...

    def check_email(self, email: str) -> ProviderResult: ...


class LookupFailed(Exception):
    """A request failed after retries; the message is shown to the user."""


# --------------------------------------------------------------------------
# HTTP helper with rate limiting and retries
# --------------------------------------------------------------------------

@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class RateLimitedClient:
    """Sequential HTTPS GETs for a single provider, rate limited and retried."""

    def __init__(self, provider_name: str, *, sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None,
                 min_interval: float = MIN_REQUEST_INTERVAL) -> None:
        self.provider_name = provider_name
        self._sleep = sleep or time.sleep
        self._clock = clock or time.monotonic
        self._min_interval = min_interval
        self._last_request: float | None = None

    def _wait_for_slot(self) -> None:
        if self._last_request is not None:
            elapsed = self._clock() - self._last_request
            if elapsed < self._min_interval:
                self._sleep(self._min_interval - elapsed)
        self._last_request = self._clock()

    def _fetch_once(self, url: str) -> HttpResponse:
        if not url.startswith("https://"):
            raise ValueError("only HTTPS URLs are allowed")
        self._wait_for_slot()
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return HttpResponse(resp.status, resp.read(), dict(resp.headers.items()))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read() or b""
            except Exception:
                body = b""
            headers = dict(exc.headers.items()) if exc.headers else {}
            return HttpResponse(exc.code, body, headers)

    def get(self, url: str, *, what: str) -> HttpResponse:
        """GET ``url``; returns any non-429, non-5xx response.

        Raises LookupFailed with a user-facing message once retries run out.
        """
        rate_retries = 0
        network_retried = False
        while True:
            try:
                resp = self._fetch_once(url)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if not network_retried:
                    network_retried = True
                    self._sleep(2)
                    continue
                raise LookupFailed(
                    f"could not reach {self.provider_name} for {what} ({reason}) "
                    "- check your internet connection and try again") from None

            if resp.status == 429:
                if rate_retries >= 3:
                    raise LookupFailed(
                        f"rate limited by {self.provider_name} for {what} "
                        "- wait an hour or re-run with fewer addresses")
                delay = _parse_retry_after(resp.headers)
                if delay is None:
                    delay = 2 ** (rate_retries + 1)  # 2, 4, 8
                elif delay > MAX_RETRY_AFTER:
                    raise LookupFailed(
                        f"rate limited by {self.provider_name} for {what}; it asked us to wait "
                        f"{int(delay)} seconds - wait that long or re-run with fewer addresses")
                rate_retries += 1
                self._sleep(delay)
                continue

            if 500 <= resp.status < 600:
                if not network_retried:
                    network_retried = True
                    self._sleep(2)
                    continue
                raise LookupFailed(
                    f"{self.provider_name} returned server error HTTP {resp.status} for {what} "
                    "- the service may be down; try again later")
            return resp


def _parse_retry_after(headers: dict[str, str]) -> float | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return max(0.0, float(value.strip()))
            except ValueError:
                return None  # HTTP-date form: fall back to our own backoff
    return None


# --------------------------------------------------------------------------
# XposedOrNot provider
# --------------------------------------------------------------------------

class XposedOrNotProvider:
    """Free XposedOrNot API (no key). See NOTES.md for the verified shapes."""

    name = "xposedornot"
    attribution = "Breach data from XposedOrNot (https://xposedornot.com)."
    base_url = "https://api.xposedornot.com/v1"

    def __init__(self, *, sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.client = RateLimitedClient(self.name, sleep=sleep, clock=clock)
        self.warnings: list[str] = []
        self._catalog: dict[str, Breach] | None = None
        self._catalog_attempted = False

    def is_available(self) -> tuple[bool, str]:
        return True, ""

    # -- catalog -----------------------------------------------------------

    def _load_catalog(self) -> None:
        """Load the breach catalog once per run; failure only adds a warning."""
        if self._catalog_attempted:
            return
        self._catalog_attempted = True
        try:
            resp = self.client.get(f"{self.base_url}/breaches", what="the breach catalog")
            if resp.status != 200:
                raise LookupFailed(f"HTTP {resp.status}")
            self._catalog = parse_xon_catalog(resp.json())
        except (LookupFailed, ValueError, TypeError, KeyError, AttributeError) as exc:
            self._catalog = None
            self.warnings.append(
                f"could not load the {self.name} breach catalog ({exc}); "
                "breaches are listed by name only")

    # -- email check -------------------------------------------------------

    def check_email(self, email: str) -> ProviderResult:
        self._load_catalog()
        url = f"{self.base_url}/check-email/{urllib.parse.quote(email, safe='@+')}"
        try:
            resp = self.client.get(url, what=f"<{email}>")
        except LookupFailed as exc:
            return ProviderResult(self.name, email, "error", [], str(exc))

        try:
            data = resp.json()
        except (ValueError, UnicodeDecodeError):
            return ProviderResult(
                self.name, email, "error", [],
                f"{self.name} sent an unreadable (non-JSON) response, HTTP {resp.status}, "
                f"for <{email}> - try again later")

        if not isinstance(data, dict):
            return self._shape_error(email, resp.status)

        # "Not found" arrives as 404 {"Error": ...} or as 200 {"Error": "Not found"}.
        if "Error" in data and "breaches" not in data and resp.status in (200, 404):
            return ProviderResult(self.name, email, "not_found", [], None)

        if resp.status != 200 or "breaches" not in data:
            return self._shape_error(email, resp.status)

        names = _flatten_breach_names(data["breaches"])
        if names is None:
            return self._shape_error(email, resp.status)
        if not names:
            return ProviderResult(self.name, email, "not_found", [], None)
        return ProviderResult(self.name, email, "found", [self._enrich(n) for n in names], None)

    def _enrich(self, name: str) -> Breach:
        if self._catalog:
            hit = self._catalog.get(name.casefold())
            if hit is not None:
                return Breach(**{**asdict(hit), "name": name})
        return Breach(name=name)

    def _shape_error(self, email: str, status: int) -> ProviderResult:
        return ProviderResult(
            self.name, email, "error", [],
            f"{self.name} returned an unexpected response (HTTP {status}) for <{email}> "
            "- the API may have changed; try again later")


def _flatten_breach_names(raw) -> list[str] | None:
    """Turn [["A", "B"]] (or ["A", "B"]) into a de-duplicated name list.

    Returns None when the shape is not recognised.
    """
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    seen: set[str] = set()

    def add(item) -> bool:
        if isinstance(item, str):
            for part in item.split(";"):
                part = part.strip()
                if part and part.casefold() not in seen:
                    seen.add(part.casefold())
                    out.append(part)
            return True
        if isinstance(item, list):
            return all(add(sub) for sub in item)
        return False

    if not all(add(item) for item in raw):
        return None
    return out


def parse_xon_catalog(data) -> dict[str, Breach]:
    """Parse GET /v1/breaches -> {casefolded breachID: Breach}."""
    if not isinstance(data, dict) or not isinstance(data.get("exposedBreaches"), list):
        raise ValueError("unexpected catalog format")
    catalog: dict[str, Breach] = {}
    for item in data["exposedBreaches"]:
        if not isinstance(item, dict) or not isinstance(item.get("breachID"), str):
            continue
        exposed = item.get("exposedData") or []
        if isinstance(exposed, str):
            exposed = [p.strip() for p in exposed.split(";") if p.strip()]
        records = item.get("exposedRecords")
        catalog[item["breachID"].casefold()] = Breach(
            name=item["breachID"],
            title=item["breachID"],
            domain=item.get("domain") or None,
            breach_date=_to_iso_date(item.get("breachedDate")),
            data_classes=[str(x) for x in exposed if isinstance(x, (str, int))],
            record_count=records if isinstance(records, int) and records > 0 else None,
        )
    return catalog


def _to_iso_date(value) -> str | None:
    if not isinstance(value, str):
        return None
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", value.strip())
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Provider registry - the only place to add a new data source.
# --------------------------------------------------------------------------

PROVIDERS: dict[str, Callable[[], BreachProvider]] = {
    "xposedornot": XposedOrNotProvider,
}


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


def read_emails_file(path: Path) -> list[str]:
    """One address per line; ignores blanks and '#' comments; handles BOM/CRLF."""
    text = Path(path).read_text(encoding="utf-8-sig")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def normalize_emails(raw: list[str]) -> tuple[list[str], list[dict]]:
    """Strip, lowercase, de-duplicate (first seen wins) and validate.

    Returns (valid_emails, skipped) where skipped is [{"input", "reason"}].
    """
    valid: list[str] = []
    skipped: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        email = item.strip().lower()
        if email in seen:
            continue
        seen.add(email)
        if is_valid_email(email):
            valid.append(email)
        else:
            skipped.append({"input": item.strip(), "reason": "invalid email format"})
    return valid, skipped


def slugify(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    return slug or "report"


# --------------------------------------------------------------------------
# Report building
# --------------------------------------------------------------------------

def email_exposed(results: list[ProviderResult]) -> bool | None:
    if any(r.status == "found" for r in results):
        return True
    if any(r.status == "error" for r in results):
        return None
    return False


def build_report(name: str, providers_used: list[str], per_email: list[tuple[str, list[ProviderResult]]],
                 skipped: list[dict], warnings: list[str], complete: bool,
                 now: datetime | None = None) -> dict:
    now = now or datetime.now().astimezone()
    results = []
    unique: set[str] = set()
    exposed_count = 0
    errors = 0
    for email, prs in per_email:
        exposed = email_exposed(prs)
        if exposed:
            exposed_count += 1
        for pr in prs:
            if pr.status == "error":
                errors += 1
            unique.update(b.name.casefold() for b in pr.breaches)
        results.append({
            "email": email,
            "exposed": exposed,
            "providers": [
                {
                    "provider": pr.provider,
                    "status": pr.status,
                    "error": pr.error,
                    "breaches": [asdict(b) for b in pr.breaches],
                }
                for pr in prs
            ],
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "generated_at": now.isoformat(timespec="seconds"),
        "complete": complete,
        "providers_used": providers_used,
        "warnings": list(warnings),
        "skipped": skipped,
        "results": results,
        "summary": {
            "emails_checked": len(results),
            "emails_exposed": exposed_count,
            "unique_breaches": len(unique),
            "lookup_errors": errors,
        },
    }


def render_console(report: dict, output_path: str | None, attributions: list[str]) -> str:
    lines = [f"Breach exposure report for {report['name']}"]
    date = report["generated_at"][:10]
    lines.append(f"Checked {report['summary']['emails_checked']} email address(es) on {date} "
                 f"using: {', '.join(report['providers_used'])}")
    if not report["complete"]:
        lines.append("NOTE: run was interrupted - this report is partial.")
    lines.append("")

    # Most common exposed data, counted once per unique breach.
    breach_classes: dict[str, list[str]] = {}

    for res in report["results"]:
        breaches: dict[str, dict] = {}
        for pr in res["providers"]:
            for b in pr["breaches"]:
                breaches.setdefault(b["name"].casefold(), b)
                breach_classes.setdefault(b["name"].casefold(), b["data_classes"])
        errs = [p for p in res["providers"] if p["status"] == "error"]
        if res["exposed"]:
            lines.append(f"{res['email']} — FOUND in {len(breaches)} breach"
                         f"{'' if len(breaches) == 1 else 'es'}")
            for b in breaches.values():
                head = f"  • {b['title'] or b['name']}"
                if b["domain"]:
                    head += f" ({b['domain']})"
                if b["breach_date"]:
                    head += f", {b['breach_date']}"
                lines.append(head)
                if b["data_classes"]:
                    lines.append(f"    Exposed: {', '.join(b['data_classes'])}")
        elif res["exposed"] is False:
            lines.append(f"{res['email']} — not found in any known breach")
        else:
            lines.append(f"{res['email']} — could not be checked")
        for p in errs:
            lines.append(f"  ! {p['provider']}: {p['error']}")
        lines.append("")

    if report["skipped"]:
        lines.append("Skipped (invalid): " + ", ".join(s["input"] for s in report["skipped"]))
        lines.append("")
    for w in report["warnings"]:
        lines.append(f"Warning: {w}")
    if report["warnings"]:
        lines.append("")

    s = report["summary"]
    summary = (f"Summary: {s['emails_exposed']} of {s['emails_checked']} addresses exposed, "
               f"{s['unique_breaches']} unique breach{'' if s['unique_breaches'] == 1 else 'es'}.")
    if s["lookup_errors"]:
        summary += f" {s['lookup_errors']} lookup(s) failed, so results are incomplete."
    lines.append(summary)
    counts = Counter(c for classes in breach_classes.values() for c in classes)
    if counts:
        top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        lines.append("Most common exposed data: " + ", ".join(f"{k} ({v})" for k, v in top))
    if s["emails_checked"] and s["lookup_errors"] == sum(len(r["providers"]) for r in report["results"]):
        lines.append("Every lookup failed - check your internet connection and try again.")
    if output_path:
        lines.append(f"Full report saved to {output_path}")
    lines.extend(attributions)
    return "\n".join(lines) + "\n"


def write_json(path: Path, report: dict) -> None:
    data = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if os.name == "nt":
        path.write_text(data, encoding="utf-8")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)  # in case the file already existed with wider perms
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)


def exit_code_for(report: dict, write_ok: bool) -> int:
    if not write_ok or not report["complete"] or report["summary"]["lookup_errors"]:
        return EXIT_INCOMPLETE
    return EXIT_EXPOSED if report["summary"]["emails_exposed"] else EXIT_CLEAN


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="breach_check.py",
        description="Check your own email addresses against free public breach data "
                    "(XposedOrNot). The name is only a label for the report.")
    p.add_argument("--name", required=True, help="Person's name; used only as the report label.")
    p.add_argument("--email", action="append", default=[], metavar="ADDR",
                   help="Email address to check (repeatable).")
    p.add_argument("--emails-file", metavar="PATH",
                   help="Text file with one address per line ('#' comments and blank lines ignored).")
    p.add_argument("--output", metavar="PATH",
                   help="JSON report path (default: breach_report_<name>_<YYYYMMDD>.json).")
    p.add_argument("--quiet", action="store_true",
                   help="Don't print the console report; still write JSON and set the exit code.")
    p.add_argument("--provider", action="append", default=[], metavar="NAME",
                   help=f"Data source to use (repeatable; default: all). Available: {', '.join(PROVIDERS)}.")
    return p


def run(argv: list[str] | None = None, *, stdout: TextIO | None = None,
        stderr: TextIO | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    def warn(msg: str) -> None:
        print(f"warning: {msg}", file=stderr)

    def fail(msg: str) -> int:
        print(f"error: {msg}", file=stderr)
        return EXIT_USAGE

    args = build_parser().parse_args(argv)  # exits with 2 on bad arguments

    if not args.name.strip():
        return fail("--name must not be empty")
    raw = list(args.email)
    if args.emails_file:
        try:
            raw.extend(read_emails_file(Path(args.emails_file)))
        except (OSError, UnicodeDecodeError) as exc:
            return fail(f"could not read email file {args.emails_file!r} ({exc}) "
                        "- check the path and that it is a UTF-8 text file")
    if not raw:
        return fail("give at least one address with --email or --emails-file")

    emails, skipped = normalize_emails(raw)
    for s in skipped:
        warn(f'skipping invalid email "{s["input"]}"')
    if not emails:
        return fail("no valid email addresses to check")

    names = list(dict.fromkeys(p.strip().lower() for p in args.provider)) or list(PROVIDERS)
    unknown = [n for n in names if n not in PROVIDERS]
    if unknown:
        return fail(f"unknown provider(s): {', '.join(unknown)}; available: {', '.join(PROVIDERS)}")
    providers: list[BreachProvider] = []
    for n in names:
        prov = PROVIDERS[n]()
        ok, reason = prov.is_available()
        if ok:
            providers.append(prov)
        else:
            warn(f"provider {n} is unavailable and will be skipped ({reason})")
    if not providers:
        return fail("no providers are available")

    per_email: list[tuple[str, list[ProviderResult]]] = []
    complete = True
    extra_warnings: list[str] = []
    try:
        for email in emails:
            results = []
            for prov in providers:
                try:
                    result = prov.check_email(email)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:  # a buggy provider must not stop the run
                    if os.environ.get("BREACH_CHECK_DEBUG") == "1":
                        traceback.print_exc(file=stderr)
                    result = ProviderResult(prov.name, email, "error", [],
                                            f"{prov.name} lookup failed unexpectedly ({exc.__class__.__name__})")
                if result.status == "error":
                    warn(f"{prov.name} lookup failed for {email}: {result.error}")
                results.append(result)
            per_email.append((email, results))
    except KeyboardInterrupt:
        complete = False
        remaining = len(emails) - len(per_email)
        extra_warnings.append(f"interrupted by user; {remaining} address(es) were not checked")
        warn("interrupted - writing a partial report")

    warnings = [w for p in providers for w in getattr(p, "warnings", [])] + extra_warnings
    for w in warnings:
        if w not in extra_warnings:
            warn(w)
    now = datetime.now().astimezone()
    report = build_report(args.name.strip(), [p.name for p in providers], per_email,
                          skipped, warnings, complete, now)

    out = Path(args.output) if args.output else Path(
        f"breach_report_{slugify(args.name)}_{now.strftime('%Y%m%d')}.json")
    write_ok = True
    try:
        write_json(out, report)
    except OSError as exc:
        write_ok = False
        print(f"error: could not write report to {out} ({exc.strerror or exc}) "
              "- choose another path with --output", file=stderr)

    if not args.quiet:
        attributions = [a for p in providers if (a := getattr(p, "attribution", None))]
        stdout.write(render_console(report, str(out) if write_ok else None, attributions))
        stdout.flush()
    return exit_code_for(report, write_ok)


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # avoid crashes on legacy consoles
        except (AttributeError, ValueError):
            pass
    try:
        code = run()
    except KeyboardInterrupt:
        code = EXIT_INCOMPLETE
    except Exception as exc:
        if os.environ.get("BREACH_CHECK_DEBUG") == "1":
            traceback.print_exc()
        else:
            print(f"error: unexpected failure ({exc.__class__.__name__}: {exc}); "
                  "re-run with BREACH_CHECK_DEBUG=1 for details", file=sys.stderr)
        code = EXIT_INCOMPLETE
    sys.exit(code)


if __name__ == "__main__":
    main()
