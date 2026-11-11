# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Tagged `0.x` releases | Best effort |

Rampart PHP is a **static analyzer**. It parses target code and never executes
it. Wrapped tools (`phpcs`, `phpstan`, `phpunit`, `composer audit`, `trivy`)
run in the target project when available.

## Reporting a vulnerability

Do **not** open a public issue for a vulnerability in Rampart PHP itself.

- Use GitHub's private vulnerability reporting on
  [thiennhant95/Rampart-PHP](https://github.com/thiennhant95/Rampart-PHP/security/advisories/new).
- Include the version, a minimal reproduction, the impact, and whether the
  issue affects the tool or a wrapper invocation.
- We aim to acknowledge within 72 hours and to publish a fix/advisory when the
  report is confirmed.

## Scanning untrusted repositories

- The `custom` analyzer only reads and parses source files and does **not**
  execute the target.
- The wrapped checkers execute the target's own binaries when present
  (`vendor/bin/phpunit`, `vendor/bin/phpstan`, ...). Do not run them on a
  repository you do not trust.
- `--fix` is not offered by the standalone binary; `trivy` is downloaded to the
  user cache and never modifies the target.
- Reports may contain file paths and code snippets. Treat HTML/JSON reports of
  private code as confidential.

## Dependencies

`composer audit` runs in CI and on demand. Dependabot opens update PRs for
Composer and GitHub Actions.
