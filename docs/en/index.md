---
layout: default
title: Rampart PHP — English
description: Full English documentation for Rampart PHP.
---

# Rampart PHP — English

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

Standalone quality gate for **plain PHP and any framework** — Slim, CodeIgniter 4,
FuelPHP, Symfony, Phalcon and Laravel. PHP **7.4+** for the tool; the target is
parsed, never executed, so any PHP version can be scanned.

## The Rampart family

| Project | Focus | Repository | Documentation |
|---|---|---|---|
| **Rampart** | Laravel Artisan quality gate | [GitHub](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | Plain PHP + frameworks, PHP 7.4+ | [GitHub](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress plugins/themes | [GitHub](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## Install

```bash
git clone https://github.com/thiennhant95/Rampart-PHP.git
cd Rampart-PHP
composer install
```

No installation into the scanned project is needed. `custom` rules work with
zero target dependencies; the wrapped tools (`phpcs`, `phpstan`, `phpunit`,
`composer audit`) use the target's own `vendor/` when present.

## Quick start

```bash
# Static security scan
php bin/rampart /path/to/project --tier=security --fail-on=none

# All reports
php bin/rampart /path/to/project --format=all --output=reports/rampart

# Review, accept, then gate only new findings
php bin/rampart /path/to/project --fail-on=none
php bin/rampart /path/to/project --baseline-generate
php bin/rampart /path/to/project --ci --baseline-file=baseline.json
```

Exit codes: `0` pass · `1` findings above `--fail-on` · `2` bad invocation ·
`3` internal error.

## Framework support

Detection reads `composer.json` and marker files; use `--framework=` to force it.

| Framework | Detection | Routes / auth analysis |
|---|---|---|
| Plain PHP | fallback | PSR-4-ish dirs, templates, `public/` |
| Slim 4 | `slim/slim` | `routes/*.php`, `->add()/->middleware()` |
| CodeIgniter 4 | `spark` + `app/Config` | `app/Config/Routes.php`, `filter` auth |
| FuelPHP | `fuel/app` | `before()` in the controller + parent chain |
| Symfony | `config/bundles.php` / `src/Kernel.php` | attributes + `config/routes*.yaml` + `security.yaml` |
| Phalcon | `phalcon/cphalcon` or `app/controllers` | `app/config/routes.php`, `beforeExecuteRoute` ACL |
| Laravel | `laravel/framework` | full semantic index (routes, middleware, policies) |

Laravel-only analyzers (BAC/IDOR, mass assignment, CSRF, Blade, migrations,
route validation) run only when Laravel is detected, so other frameworks are
never judged by Eloquent/Blade semantics.

## What it checks

- **Security:** SQLi (including PDO `query()`), command injection, path
  traversal, SSRF, XSS, open redirect, SSTI, XXE, LDAP injection, unsafe
  eval/deserialize, hardcoded secrets, weak hashes/crypto/randomness, cookie
  and session flags, header injection, dangerous functions.
- **OWASP Top 10 2021:** A01, A03, A05, A07, A10 rollups in JSON/HTML/SARIF.
- **Framework routing:** mutating route without visible authorization
  (Slim, CI4, FuelPHP, Symfony, Phalcon).
- **Optional:** taint engine, missing tests (`--coverage`), conventions,
  debug output, forensics (`public/*.php`, obfuscated PHP), ops (permissions,
  EOL).

Full table: [README](https://github.com/thiennhant95/Rampart-PHP#custom-analyzer-rules)
and [rule notes]({{ site.baseurl }}/rules.html).

## Reports

| Format | File | Use |
|---|---|---|
| `console` | stdout | Local terminal |
| `json` | `rampart-report.json` | CI, tooling |
| `html` | `rampart-report.html` | Developer browser |
| `md` | `rampart-report.md` | PR comments |
| `sarif` | `rampart-report.sarif` | GitHub code scanning |

HTML variants: `--no-remediation` (findings only), `--client` (external),
`--all-variants` (all three). See [reports.html]({{ site.baseurl }}/reports.html).

## CI

```yaml
- run: composer install --prefer-dist --no-progress
- run: php bin/rampart . --only=custom --ci --fail-on=error
  working-directory: tools/rampart
```

For GitHub code scanning, add `--format=sarif` and upload
`rampart-report.sarif`. The scanner needs no target `vendor/` for `custom`.

## Baseline and noise control

```bash
php bin/rampart /path --baseline-generate
php bin/rampart /path --ci --baseline-file=baseline.json
php bin/rampart /path --min-severity=error --ignore=ROUTE_MISSING_AUTH
```

Inline suppression: `// rampart-ignore RULE_ID` on the line, or
`// rampart-ignore-next-line RULE_ID`. The legacy `quality-checker-ignore`
spelling is accepted too.

## Performance

The canonical AST is read/parsed once per file per run. `bin/rampart` raises the
CLI memory floor to 512M; the opt-in taint engine may need more on very large
trees (`php -d memory_limit=1G`).

## Development

```bash
composer check   # phpcs + phpstan + phpunit
composer smoke   # build/install archive, run the installed binary
```

The project dogfoods itself; self-scan is 0 findings, including optional rules.

## License

MIT © 2026 Rampart.
