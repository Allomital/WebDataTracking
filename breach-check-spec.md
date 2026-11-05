# Project Spec: `breach_check` — Breach Exposure Checker

> **For the implementing agent:** Read this whole spec before writing code. Where it says **VERIFY**, check the live API documentation before relying on the detail given here; do not guess response shapes. If something here conflicts with what you find, follow the live docs and note the discrepancy in `NOTES.md`. Do not add features listed under *Out of scope*.

---

## 1. Goal

A command-line script that takes a person's name and one or more email addresses, checks each address against free public data-breach lookup services, and produces a readable console report plus a JSON file listing which breaches each address appears in as well as the breached data if it is accessible.

The name is a **label for the report only**. The script never searches by name and never tries to discover email addresses for a name.

---

## 2. Inputs and outputs

### Inputs

| Input | Form | Required | Notes |
|---|---|---|---|
| Name | `--name "Jane Doe"` | Yes | Free text, used only as the report label. |
| Email(s) | `--email addr` (repeatable) | At least one email from either source | Each flag adds one address. |
| Email file | `--emails-file path.txt` | Optional | One address per line. Blank lines and lines starting with `#` are ignored. Combined with any `--email` flags. |
| Output path | `--output path.json` | Optional | Default: `breach_report_<slug-of-name>_<YYYYMMDD>.json` in the current directory. |
| Quiet mode | `--quiet` | Optional | Suppress the console report; still write JSON and set the exit code. |
| Provider selection | `--provider name` (repeatable) | Optional | Default: all enabled providers. Only `xposedornot` exists in v1. |

### External services (v1)

**XposedOrNot (free tier, no API key)**
- Email check: `GET https://api.xposedornot.com/v1/check-email/{email}` — returns breach **names only** on the free tier.
- Breach catalog: XposedOrNot's free breach-listing endpoint, used to enrich breach names with details (date, domain, exposed data types, record count). **VERIFY** the exact path and field names at https://xposedornot.com/api_doc.
- **VERIFY** the "not found" response (expected to be an HTTP 404 with an error body, not an empty 200) and the exact JSON shape of a hit (breaches are reported to come back as a nested array of names).
- Free-tier rate limit is roughly 1–2 requests/second and 50–100 requests/hour. Respect it.

### Outputs

1. **Console report** (stdout), human-readable; see §5.
2. **JSON report file** at the output path; schema in §5.
3. **Exit code:**

| Code | Meaning |
|---|---|
| 0 | All lookups succeeded; no exposures found |
| 1 | All lookups succeeded; at least one exposure found |
| 2 | Usage or input error (bad arguments, no valid emails, unreadable email file); nothing was checked |
| 3 | One or more lookups failed, so results are incomplete (takes precedence over 0 and 1) |

Diagnostics and warnings go to **stderr**, never stdout.

---

## 3. Language and constraints

- **Python 3.10+, standard library only** (`argparse`, `urllib.request`, `json`, `time`, `re`, `pathlib`, `unittest`, etc.). No `requests`, no third-party breach SDKs. This keeps it a single file anyone can run.
- Must run unchanged on **Windows, macOS and Linux**. Use `pathlib`; open files with `encoding="utf-8"`; don't rely on ANSI colors (fine to add them only when `sys.stdout.isatty()` and not on legacy Windows consoles; plain output is acceptable).
- Layout:
  ```
  breach_check.py        # the script (entry point + providers)
  tests/test_breach_check.py
  README.md              # usage, exit codes, data-source attribution
  NOTES.md               # any API discrepancies found during VERIFY steps
  ```
- **HTTPS only.** Send a descriptive `User-Agent` (e.g. `breach_check/1.0`). Request timeout: 15 seconds.
- **API keys:** v1 uses only free endpoints, so no key is required. Any future provider that needs a key must read it from an environment variable (never a command-line argument, which ends up in shell history), and must never print or log it.
- **Privacy:** never send anything except the email address to a provider. Don't write email addresses to stderr logs beyond what's needed for an error message. When creating the JSON file on macOS/Linux, set permissions to `0o600`.

### Provider interface (required, for adding sources later)

Implement each data source as a class behind a small common interface so new sources (e.g. Have I Been Pwned with a paid key) can be added without touching the CLI or report code:

```python
class BreachProvider(Protocol):
    name: str                      # e.g. "xposedornot"
    def is_available(self) -> tuple[bool, str]: ...
        # (False, reason) if e.g. a required API key env var is missing
    def check_email(self, email: str) -> ProviderResult: ...

@dataclass
class Breach:
    name: str
    title: str | None
    domain: str | None
    breach_date: str | None        # ISO 8601 date, if known
    data_classes: list[str]        # e.g. ["Email addresses", "Passwords"]
    record_count: int | None

@dataclass
class ProviderResult:
    provider: str
    email: str
    status: Literal["found", "not_found", "error"]
    breaches: list[Breach]
    error: str | None
```

Providers are registered in one list/dict in `breach_check.py`. The rest of the code only talks to `BreachProvider`.

---

## 4. Behavior details

### Steps

1. **Parse arguments.** Require `--name` and at least one email source.
2. **Collect and normalize emails:** strip whitespace, lowercase, de-duplicate while preserving first-seen order.
3. **Validate each email** with a pragmatic regex (something `@` something `.` something, no spaces). Invalid addresses are reported as warnings on stderr and listed under `skipped` in the JSON; they are not sent to any provider. If **no** valid emails remain, exit 2.
4. **Select providers.** Unknown `--provider` names → exit 2. Providers whose `is_available()` is false are skipped with a stderr warning; if none are available, exit 2.
5. **Load the breach catalog once per run** (for enrichment). If it fails, continue with names only and add a warning to the report; this alone is **not** a lookup failure.
6. **Check each email against each provider**, sequentially:
   - Rate limit: at least 1.1 seconds between requests to the same provider.
   - On HTTP 429: honor `Retry-After` if present, otherwise back off 2s, 4s, 8s. Max 3 retries, then record `status="error"`.
   - On timeout, connection error or 5xx: retry once after 2s, then record `status="error"`.
   - On the provider's documented "not found" response: `status="not_found"`.
   - On a hit: `status="found"`, with breaches enriched from the catalog where names match (case-insensitive). Unmatched names are kept with only `name` filled.
   - On an unexpected response shape (invalid JSON, missing fields): `status="error"` with a short description. Never crash.
7. **Build the report** (both console and JSON from the same data).
8. **Write the JSON file.** If the path can't be written, print the error to stderr, still print the console report, and exit 3.
9. **Exit** with the code from §2.

### Edge cases

| Case | Expected behavior |
|---|---|
| Same email given twice (different case/spacing) | Checked once. |
| Email with `+tag` (e.g. `jane+news@gmail.com`) | Checked as given. Do not strip tags or dots. |
| Non-ASCII in name | Works; the filename slug falls back to ASCII-safe characters (`jane-doe`, or `report` if nothing is left). |
| Email file has a BOM or Windows line endings | Handled (`utf-8-sig`, `splitlines()`). |
| Breach appears in results more than once | De-duplicated per email. |
| Ctrl-C mid-run | Stop cleanly; write a partial report marked `"complete": false`; exit 3. |
| Output file already exists | Overwrite it (it's a dated report). |
| No network at all | Every lookup errors; report says so plainly; exit 3. |

### Error-handling principles

- One failed lookup never stops the others.
- Every error the user sees says **what failed, for which email and provider, and what to try** (e.g. "rate limited by xposedornot — wait an hour or re-run with fewer addresses").
- No stack traces on stdout/stderr for expected failures; unexpected exceptions may print a traceback only when `BREACH_CHECK_DEBUG=1` is set.

---

## 5. Examples

### Sample input

```
python breach_check.py --name "Jane Doe" --email jane.doe@example.com --email JANE.DOE@example.com --email old-handle@example.net --email not-an-email
```

### Expected console output (illustrative; real breach names depend on live data) (if no password checks or other information has been found)

```
Breach exposure report for Jane Doe
Checked 2 email address(es) on 2026-10-30 using: xposedornot

jane.doe@example.com — FOUND in 2 breaches
  • Adobe (adobe.com), 2013-10-04
    Exposed: Email addresses, Password hints, Passwords, Usernames
  • LinkedIn (linkedin.com), 2012-05-05
    Exposed: Email addresses, Passwords

old-handle@example.net — not found in any known breach

Skipped (invalid): not-an-email

Summary: 1 of 2 addresses exposed, 2 unique breaches.
Most common exposed data: Passwords (2), Email addresses (2)
Full report saved to breach_report_jane-doe_20261030.json
Breach data from XposedOrNot (https://xposedornot.com).
```

stderr would contain: `warning: skipping invalid email "not-an-email"`. Exit code: **1**.

### Expected JSON (if no password checks or other information has been found)

```json
{
  "schema_version": 1,
  "name": "Jane Doe",
  "generated_at": "2026-10-30T10:21:00-07:00",
  "complete": true,
  "providers_used": ["xposedornot"],
  "warnings": [],
  "skipped": [{"input": "not-an-email", "reason": "invalid email format"}],
  "results": [
    {
      "email": "jane.doe@example.com",
      "exposed": true,
      "providers": [
        {
          "provider": "xposedornot",
          "status": "found",
          "error": null,
          "breaches": [
            {
              "name": "Adobe",
              "title": "Adobe",
              "domain": "adobe.com",
              "breach_date": "2013-10-04",
              "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
              "record_count": 152445165
            }
          ]
        }
      ]
    },
    {
      "email": "old-handle@example.net",
      "exposed": false,
      "providers": [
        {"provider": "xposedornot", "status": "not_found", "error": null, "breaches": []}
      ]
    }
  ],
  "summary": {
    "emails_checked": 2,
    "emails_exposed": 1,
    "unique_breaches": 2,
    "lookup_errors": 0
  }
}
```

(The Adobe entry is shown in full; the LinkedIn entry would follow the same shape.) An email's `exposed` is `true` if any provider returned `found`, `false` if all returned `not_found`, and `null` if any errored and none found.

---

## 6. Out of scope (do not build)

- Looking people up by **name**, discovering emails for a name, or any people-search / OSINT features.
- Paid APIs, including Have I Been Pwned account search. The provider interface must make adding it easy, but don't implement it.
- GUI, web UI, scheduling, notifications, emailing reports, databases, caching between runs.
- Third-party Python packages or packaging/installers.

---

## 7. Done means

All of the following are true:

1. `python breach_check.py --help` shows every argument in §2 with a one-line description.
2. Running the §5 sample (with real addresses) prints a report in that format, writes valid JSON matching the §5 schema, and returns the correct exit code.
3. **Unit tests** in `tests/test_breach_check.py` pass with `python -m unittest` and use **no network** (mock `urllib.request.urlopen`). They cover at least:
   - email normalization, de-duplication and validation;
   - email-file parsing (comments, blanks, BOM, CRLF);
   - provider responses: found, not found, 429 with and without `Retry-After`, timeout, 5xx, malformed JSON;
   - catalog enrichment with matched and unmatched breach names, and catalog-load failure;
   - every exit code (0, 1, 2, 3), including partial failure taking precedence;
   - JSON output validates against the §5 shape;
   - adding a dummy second provider requires no changes outside the provider registry.
4. **One live smoke test**, run manually by the user with their own email, completes without errors; record the date and outcome in `NOTES.md`.
5. The script runs on Windows and on macOS or Linux (at minimum, the unit tests pass on both).
6. All **VERIFY** items in §2 were checked against the live docs, and any differences from this spec are written up in `NOTES.md`.
7. `README.md` covers usage, exit codes, the self-use-only intent, and attribution to XposedOrNot as the data source.