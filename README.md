# WebDataTracking

## `breach_check` — Breach Exposure Checker

A single-file Python script that checks **your own** email addresses against free public
data-breach lookups and produces a console report plus a JSON report.

**Self-use only.** Use this to check addresses you own, or that you have explicit permission
to check. The `--name` you give is only a label for the report. The script never searches by
name and never tries to discover email addresses.

### Requirements

Python 3.10+, standard library only. Works on Windows, macOS and Linux.

### Usage

```bash
python breach_check.py --name "Jane Doe" --email jane.doe@example.com --email old-handle@example.net
```

```bash
python breach_check.py --name "Jane Doe" --emails-file my_emails.txt --output report.json
```

| Option | Description |
|---|---|
| `--name NAME` | Required. Label for the report. |
| `--email ADDR` | Address to check; repeatable. |
| `--emails-file PATH` | One address per line; blank lines and `#` comments ignored. Combined with `--email`. |
| `--output PATH` | JSON report path. Default: `breach_report_<slug-of-name>_<YYYYMMDD>.json` in the current directory (overwritten if it exists). |
| `--quiet` | No console report; JSON is still written and the exit code still set. |
| `--provider NAME` | Data source(s) to use; repeatable. Default: all. v1 has only `xposedornot`. |

Addresses are trimmed, lowercased and de-duplicated. `+tags` and dots are kept as given.
Invalid addresses are skipped with a warning on stderr and listed under `skipped` in the JSON.

The free API allows about 25 email checks per hour, so the script waits at least 1.1 s between
requests and backs off when it is rate limited. Check a few addresses at a time.

On macOS/Linux the JSON file is created with `0600` permissions. Set `BREACH_CHECK_DEBUG=1`
to see tracebacks for unexpected errors.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All lookups succeeded; no exposures found |
| 1 | All lookups succeeded; at least one exposure found |
| 2 | Usage or input error; nothing was checked |
| 3 | One or more lookups failed, the run was interrupted, or the report could not be written; results are incomplete |

### Tests

```bash
python -m unittest
```

The tests mock `urllib.request.urlopen` and use no network.

### Adding a data source

Write a class with `name`, `is_available() -> (bool, reason)` and
`check_email(email) -> ProviderResult`, and add it to the `PROVIDERS` registry in
`breach_check.py`. Optional attributes: `warnings` (list of strings added to the report) and
`attribution` (printed under the console report). A provider that needs an API key must read
it from an environment variable and must never print or log it.

### Data source and attribution

Breach data comes from [XposedOrNot](https://xposedornot.com), a free, open breach-lookup
service. Only the email address is sent to it. Please respect its rate limits and terms.
