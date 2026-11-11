# Rule notes

The canonical, test-enforced table lives in the [README](../README.md#custom-analyzer-rules).
This page records the reasoning behind the rules that are easy to misread.

## Confidence is not severity

- **Severity** answers "how bad if true" (`critical` → `info`).
- **Confidence** answers "how sure is the analyzer" (`high` → `low`).

A `low`-confidence `Warning` (for example `ROUTE_MISSING_AUTH`) never fails the
default `--fail-on=error` gate. A `high`-confidence `Critical` always does.

## Rules that are intentionally conservative

| Rule | Why it is narrow |
|---|---|
| `XSS_ECHO` | Only request-derived values. `echo $title` from a DB row is not reported — that needs a human or a template engine. |
| `SQL_INJECTION` | Recognises DB contexts (`DB::*`, PDO/mysqli-style receivers) and request-derived arguments; bound parameters stay silent. |
| `ROUTE_MISSING_AUTH` | Reads route declarations plus FuelPHP `before()` and Symfony `security.yaml`; auth handled in an unmodelled controller still reports, hence low confidence. |
| `HEADER_INJECTION` | Skips `Location:` so it does not duplicate `OWASP_OPEN_REDIRECT`. |
| `INSECURE_RANDOM` | Only reports when the assignment/function name looks security-related (`token`, `otp`, `salt`, ...). |
| `DEBUG_OUTPUT` | Off by default; CLI scripts dump variables legitimately. |
| `ROGUE_PHP` | Off by default in this build: `public/*.php` is normal outside Laravel. |

## Rules that are opt-in

- `TAINT_*` — `analyzers.security.taint_engine`.
- `MISSING_*` / `TEST_WITHOUT_ASSERT` — `--coverage` or
  `analyzers.test_coverage.unified`.
- Convention rules (`DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`,
  `LARAVEL_PITFALL_*`) — `analyzers.convention.*`.
