# False positives

The custom analyzers are **static heuristics**. They are precise on the labelled
corpus, but they do not replace a security review.

## Triage order

1. Open the reported file and line. Read the finding first.
2. If the code can be made safe (parameter binding, validation, escaping), fix it.
3. If it is a reviewed one-off, add an inline suppression on that line:
   `// rampart-ignore RULE_ID` or `// rampart-ignore-next-line RULE_ID`.
4. Only baseline findings you have actually reviewed.

## Confidence

| Confidence | Meaning | Action |
|---|---|---|
| `high` | Treat as a real bug until proven otherwise | Fix; do not broadly disable |
| `medium` | Usually correct | Check context, then fix or baseline |
| `low` | Heuristic hint | Review when cleaning up; never gate CI on it |

## Common cases

### `XSS_ECHO`

- Reported: request data arrives at `echo`/`print`/`<?= ?>` (direct superglobal,
  `$request->input()`, or a variable assigned from one).
- Not reported: `echo $title` where `$title` never received request data.
- Fix: `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')` or a template engine with
  auto-escaping.

### `SQL_INJECTION`

- Reported: request data concatenated into raw SQL, including PDO `query()` and
  `exec()`, or used as a column name in `orderBy()`/`groupBy()`.
- Not reported: bound parameters (`where('id', $id)`, `prepare()` with `?`).
- Fix: parameter binding; map sort columns through an allow-list.

### `ROUTE_MISSING_AUTH`

- This is low confidence **by design**: it reads route declarations, not
  controller bodies. A route protected inside the controller will still be
  reported.
- Fix the code or confirm the policy, then suppress with
  `--ignore=ROUTE_MISSING_AUTH` if your convention keeps auth in the controller.

### `INSECURE_COOKIE` / `INSECURE_SESSION`

- Reported on explicit insecure flags (`secure=false`, `httponly=0`,
  `session.cookie_httponly=0`) and on cookies declared without the flags.
- Fix: set `Secure`, `HttpOnly`, `SameSite=Lax/Strict`, and enable session
  strict mode.

### `HARDCODED_SECRET`

- Test fixtures under `fixtures/` are excluded by default
  (`analyzers.exclude_paths`). A staging key in `.env` is still reported on
  purpose.
