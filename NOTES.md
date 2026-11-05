# Implementation notes

## VERIFY results (checked 2026-11-05)

The live documentation (https://xposedornot.com/api_doc, https://api.xposedornot.com/docs)
could **not** be reached from the development sandbox, because its network policy blocks
those hosts. The checks below were made against the public README and source code of the API
at https://github.com/XposedOrNot/XposedOrNot-API (master branch: `api/v1/breaches.py`,
`models/responses.py`). Please re-check against the live docs during the smoke test.

### `GET /v1/check-email/{email}`
- **Hit:** HTTP 200, `{"breaches": [["Adobe", "LinkedIn"]], "email": "...", "status": "success"}`.
  This matches the spec: names come in a nested array. The order of names is not stable.
- **Not found: differs from the spec.** The spec expected an HTTP 404 with an error body. The
  source code shows two forms:
  - `{"Error": "Not found"}`, returned without an explicit status code. It looks like HTTP 200.
    This is used when there is no record and also for input it considers an invalid email.
  - HTTP 404 with `{"Error": "Not found" | "No breaches found", "email": ..., "status": "failed"}`.
  The script treats both an HTTP 200 and an HTTP 404 whose JSON body has an `Error` key and no
  `breaches` key as `not_found`. A 404 without a JSON body is treated as an error.
- **429:** includes a `Retry-After` header in seconds and a JSON body with `retry_after` and
  `reset_time`.

### Breach catalog
- **Path:** `GET https://api.xposedornot.com/v1/breaches`. It also takes optional `?domain=`
  and `?breach_id=`, which this script does not use.
- **Shape:** `{"status": "success", "exposedBreaches": [ ... ]}`. Per-breach fields:
  `breachID`, `breachedDate`, `addedDate`, `domain`, `industry`, `logo`, `passwordRisk`,
  `searchable`, `sensitive`, `verified`, `breachType`, `exposedData` (a list of strings),
  `exposedRecords` (int), `exposureDescription`, `referenceURL`.
- **Mapping:** `name`/`title` ← `breachID`; `domain` ← `domain`;
  `breach_date` ← the date part of `breachedDate`; `data_classes` ← `exposedData`;
  `record_count` ← `exposedRecords` (0 is mapped to `null`).
- **Dates:** `breachedDate` is an ISO 8601 *datetime* such as `2013-10-04T00:00:00`, not a date.
  The script keeps only `YYYY-MM-DD`.
- The catalog has no separate display title, so `title` is the same as `breachID`.
- Breach names from check-email are matched to `breachID` case-insensitively.

### Rate limits: tighter than the spec states
The README gives per-IP limits for check-email of **2/second, 25/hour, 100/day**. The catalog
endpoint allows 50/hour. The spec said 50–100/hour. One run uses one catalog request plus one
request per address.

## Implementation decisions
- **Large Retry-After:** the script honors `Retry-After` values up to 60 s. If the server asks
  for a longer wait (for example, after the hourly quota is used up), the lookup is recorded
  as an error straight away, with a message giving the wait time. This avoids hanging for up
  to an hour.
- **Ctrl-C:** addresses already checked go in the partial report (`"complete": false`).
  Addresses that were not reached are counted in a warning and are not listed under `results`.
- **Write failure:** if the report cannot be written, the console report is still printed
  without the "saved to" line, and the exit code is 3, as the spec requires.
- **Optional provider extras:** `warnings` and `attribution` are optional provider attributes
  read with `getattr`. They are not part of the `BreachProvider` protocol, so a minimal
  provider still only needs `name`, `is_available` and `check_email`.
- **Most common exposed data:** counted once per unique breach; shows the top 5, with ties in
  alphabetical order.

## Live smoke test
_Not yet run. The development sandbox cannot reach api.xposedornot.com._ To be run by the user:

```
python breach_check.py --name "<you>" --email <your address>
```

Date: ____  Outcome / exit code: ____  Any differences seen: ____
