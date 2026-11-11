# Rampart PHP Quality Checker

**Standalone quality gate for plain PHP and any framework** — Slim, CodeIgniter 4,
FuelPHP, Symfony, Laravel. One CLI, no install into the scanned project, no
framework boot.

Rampart wraps `phpcs`, `phpstan`, `phpunit`, `composer audit`, `npm audit` and
`trivy`, and adds 59 custom PHP-Parser rules for security, framework routing,
missing tests and conventions.

## Why standalone

- **No `vendor/` in the target** — audit legacy, read-only or broken projects.
- **No framework boot** — works with a bad `.env`, a missing DB or an old PHP.
- **Same engine everywhere** — plain PHP and every supported framework share the
  analyzers; only the file layout changes.

## Requirements

| Requirement | Version |
|---|---|
| PHP (of the tool) | `>=7.4` (tested on 7.4 and 8.2) |
| PHP (of the target) | any; parsed, not executed |
| Composer | `2.4+` for `composer audit` |

Optional tools (reported as `skipped` when missing): `squizlabs/php_codesniffer`,
`phpstan/phpstan`, `phpunit/phpunit`, `trivy`, `npm`.

## Install

```bash
git clone https://github.com/thiennhant95/rampart-php.git
cd rampart-php
composer install
```

## Quick start

```bash
# Static security scan of any directory
php bin/rampart /path/to/project --tier=security --fail-on=none --format=console

# All reports
php bin/rampart /path/to/project --format=all --output=reports/rampart

# Review without failing, then accept the current state
php bin/rampart /path/to/project --fail-on=none
php bin/rampart /path/to/project --baseline-generate
php bin/rampart /path/to/project --ci --baseline-file=baseline.json
```

Outputs: `rampart-report.html`, `rampart-report.json`, `rampart-report.md`,
`rampart-report.sarif`. The HTML file is self-contained and opens from
`file://`.

## Validation snapshot (2026-11-11)

| Target | Result |
|---|---|
| This package, `src/` + `bin/` self-scan | **0 findings** |
| `slimphp/Slim-Skeleton` | **0 findings** |
| `codeigniter4/appstarter` | **0 findings** |
| `thiennhant95/Rampart` (Laravel-flavoured library) | **1 finding** (PHP 8.1 EOL only) |
| Test suite | `1424 tests, 3433 assertions` on PHP 7.4 **and** 8.2, PHPStan `[OK]`, PHPCS clean |

This is a snapshot, not a live benchmark. Use
[tools/benchmark-projects.php](tools/benchmark-projects.php) on your own
projects (see [docs/tools.md](docs/tools.md)).

## Framework support

Detection reads `composer.json` and marker files; it never executes them. Force
it with `--framework=` when detection is ambiguous.

| Framework | Detection | Route/SAST support |
|---|---|---|
| Plain PHP | fallback | PSR-4-ish dirs, templates, `public/` |
| Slim 4 | `slim/slim` in composer.json | `routes/*.php`, `->add()/->middleware()` auth |
| CodeIgniter 4 | `spark` + `app/Config` | `app/Config/Routes.php`, `filter` auth |
| FuelPHP | `fuel/app` | `fuel/app/config/routes.php` + controller `before()` auth |
| Symfony | `config/bundles.php` or `src/Kernel.php` | `#[Route]` attributes and `config/routes*.yaml`; `security.yaml access_control` |
| Phalcon | `phalcon/cphalcon` or `app/controllers` + `public/index.php` | `app/config/routes.php`; `beforeExecuteRoute`/`beforeDispatch` ACL |
| Laravel | `laravel/framework` | full semantic index (routes, middleware, policies) |

## Options

| Option | Description | Default |
|---|---|---|
| `--format=...` | `console`, `json`, `html`, `md`, `sarif`, `all` | `console` |
| `--only=...` | Checkers to run: `phpcs,phpstan,phpunit,composer_audit,npm_audit,trivy,custom` | `custom` |
| `--exclude=...` | Checkers to skip | — |
| `--tier=...` | `security`, `quality`, `all` | config (`quality`) |
| `--min-confidence=...` | `low`, `medium`, `high` | config (`low`) |
| `--min-severity=...` | `info`, `warning`, `error`, `critical` | config (`info`) |
| `--fail-on=...` | `none`, `info`, `warning`, `error`, `critical` | `error` |
| `--framework=...` | `auto`, `plain`, `slim`, `codeigniter4`, `fuelphp`, `symfony`, `laravel` | `auto` |
| `--path=...` | Restrict the scan to sub-directories (repeatable) | profile defaults |
| `--exclude-path=...` | Skip path globs (repeatable, merged with config) | `*/fixtures/*` |
| `--ignore=...` | Drop rules from the report (comma-separated) | — |
| `--output=...` | Report directory | `reports/rampart` |
| `--no-cache` | Ignore cached results | off |
| `--coverage` | Opt into missing-test checks for this run | off |
| `--no-remediation` | Hide fix guidance in human reports | off |
| `--client` | Simplified external HTML report | off |
| `--all-variants` | Write dev + findings-only + client HTML | off |
| `--baseline-generate` | Write current issues to the baseline | off |
| `--baseline-update` | Rewrite the baseline with all current issues | off |
| `--baseline-file=...` | Baseline path | `baseline.json` at target root |
| `--profile` | Write `profile.json` next to reports | off |
| `--help` | Print usage | — |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Pass — no issue exceeds `--fail-on`. |
| `1` | Issues above the threshold. |
| `2` | Bad invocation or setup. |
| `3` | Runtime error inside the package. |

## Checkers

| Checker | Wrapped command | Notes |
|---|---|---|
| `phpcs` | `vendor/bin/phpcs` | PSR-12 by default; auto-fixes are not offered in standalone. |
| `phpstan` | `vendor/bin/phpstan` | Level 6 by default. |
| `phpunit` | `vendor/bin/phpunit` | JUnit + Clover; low coverage becomes `PHPUNIT_LOW_COVERAGE`. |
| `composer_audit` | `composer audit` | Dependency advisories. |
| `npm_audit` | `npm audit --json` | Skipped without `package.json`/`npm`. |
| `trivy` | `trivy fs` / `trivy config` | Off by default; cached binary. |
| `custom` | PHP-Parser | The 59 rules below. |

## Custom Analyzer Rules

Every row is verified against `src/Result/RuleIds.php` by **RuleDocsTest**, so
this table cannot drift from what the analyzers emit.

Severity is what the rule emits; confidence is the noise rating (`high` is safe
to gate CI on, `low` is a heuristic hint).

Laravel-bound analyzers (access control/IDOR, mass assignment, CSRF/session
hardening, migrations, Blade, route validation) run only when the target is
detected as Laravel. Other frameworks use the generic equivalents
(`ROUTE_MISSING_AUTH`, `XSS_ECHO`, `SQL_INJECTION`, ...), so a Phalcon or Slim
controller is not judged by Eloquent/Blade semantics.

### Security (`analyzers/security`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `SQL_INJECTION` | Critical | high | Tainted input in raw SQL: `DB::*`, PDO/mysqli `query()/exec()`, `whereRaw()`, column injection via `orderBy()`. |
| `UNSAFE_EVAL` | Critical | high | `eval()` / `assert()` / `call_user_func()` with dynamic data. |
| `HARDCODED_SECRET` | Critical | high | API keys, tokens, private-key blocks, hardcoded passwords. |
| `MASS_ASSIGNMENT` | Error/Warning | high/medium | Eloquent mass assignment without `$fillable`/`$guarded`. |
| `UNSAFE_UNSERIALIZE` | Critical | high | `unserialize()` / `yaml_parse()` of untrusted data. |
| `INSECURE_HASH` | Warning | high | `md5()`/`sha1()` for passwords; `rand()`/`mt_rand()`/`uniqid()` for tokens. |
| `INSECURE_COOKIE` | Error/Warning | high | Cookies missing `Secure`/`HttpOnly` (Laravel `cookie()` and plain `setcookie()`). |
| `SESSION_FIXATION` | Warning | medium | Login without session regeneration. |
| `WEAK_PASSWORD_POLICY` | Warning | medium | Weak password rules or a hardcoded master password. |
| `LARAVEL_TAINT` | Error | high | Tainted interpolation into the Laravel query builder. |
| `DISABLED_CSRF_AUTHORIZE_TRUE` | Warning | high | CSRF exemption covering every route. |
| `DISABLED_CSRF_EXCEPTION_STAR` | Warning | high | CSRF middleware removed on a mutating route. |
| `XSS_ECHO` | Error | high/medium | Request-derived value echoed/printed without escaping. |
| `INSECURE_RANDOM` | Warning | medium | `lcg_value()`/`str_shuffle()`/`array_rand()` used for security values. |
| `DANGEROUS_FUNCTION` | Error | medium | `extract()`, one-argument `parse_str()`, `create_function()`, `preg_replace()` with `/e`. |
| `HEADER_INJECTION` | Warning | high/medium | Request data concatenated into `header()`. |
| `LDAP_INJECTION` | Critical | high | Request data used as an LDAP filter or DN. |
| `WEAK_CRYPTO` | Warning | high | DES/RC2/RC4/Blowfish or ECB mode in OpenSSL/mcrypt. |
| `INSECURE_SESSION` | Warning | high | Session cookies with HttpOnly/Secure/strict mode disabled. |
| `DEBUG_OUTPUT` | Warning | low | `var_dump()`/`print_r()`/`phpinfo()` in shipped code (opt-in). |

Opt-in data-flow engine (`analyzers.security.taint_engine`, off by default):

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `TAINT_SQL_INJECTION` | Critical | high | Tainted value reaching a raw SQL sink. |
| `TAINT_COMMAND_INJECTION` | Critical | high | Tainted value reaching an OS command. |
| `TAINT_EVAL` | Critical | high | Tainted value reaching `eval`/`assert`. |
| `TAINT_UNSAFE_SERIALIZE` | Error | high | Tainted value reaching `unserialize`. |

### OWASP (`analyzers/owasp`)

Categories follow OWASP Top 10 **2021**.

| Rule ID | Severity | Confidence | OWASP 2021 | What it detects |
|---|---|---|---|---|
| `OWASP_BROKEN_ACCESS_CONTROL` | Error | medium | A01 Broken Access Control | Mutating action without visible authorization. |
| `OWASP_OWNERSHIP_IDOR` | Error | high/medium | A01 Broken Access Control | Missing object-ownership check on a loaded record. |
| `OWASP_PATH_TRAVERSAL` | Error | high | A01 Path Traversal | User-controlled path in file/include sinks. |
| `OWASP_BLADE_DYNAMIC_INCLUDE` | Info | medium | A01 Path Traversal | Dynamic Blade include target. |
| `OWASP_BLADE_XSS` | Error/Warning | high | A03 Injection (XSS) | Unescaped Blade output. |
| `OWASP_SSTI` | Error | high | A03 Injection (SSTI) | Tainted template name in a render call. |
| `OWASP_COMMAND_INJECTION` | Critical | high | A03 Injection (Command) | User input into `system`/`exec`/`Process`. |
| `OWASP_MISCONFIGURATION` | Warning | high | A05 Security Misconfiguration | Debug on, CORS wildcard, empty secrets. |
| `OWASP_XXE` | Error | high | A05 XXE | XML parsing without an entity guard. |
| `OWASP_OPEN_REDIRECT` | Error | high | A07 Open Redirect | Unvalidated redirect target. |
| `OWASP_SSRF` | Error | high | A10 SSRF | User-controlled URL in a server-side fetch. |

### Laravel (`analyzers/laravel`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `MIGRATION_MISSING_DOWN` | Warning | medium | Migration with no `down()`. |
| `MIGRATION_DESTRUCTIVE_UP` | Warning | medium | Destructive schema change in `up()`. |
| `ROUTE_MISSING_VALIDATION` | Warning | medium | Mutating action without validation. |

### Framework routing (`analyzers/framework`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `ROUTE_MISSING_AUTH` | Warning | low | Slim/CI4/FuelPHP/Symfony/Phalcon mutating route without a visible auth middleware/filter/attribute/`before()`/ACL check. |

### Test coverage (`analyzers/test_coverage`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `MISSING_CONTROLLER_TEST` | Info | low | Controller with no test. |
| `MISSING_SERVICE_TEST` | Info | low | Service with no test. |
| `MISSING_REPOSITORY_TEST` | Info | low | Repository with no test. |
| `MISSING_MODEL_TEST` | Info | low | Model with logic and no test. |
| `MISSING_UNIT_TEST` | Info | low | Class with neither unit nor feature test. |
| `MISSING_FEATURE_COVERAGE` | Info | high | Route with no feature test touching it. |
| `TEST_WITHOUT_ASSERT` | Warning | low | Test method with no assertion. |

All test-coverage rules are opt-in: use `--coverage` or set
`analyzers.test_coverage.unified`.

### Convention (`analyzers/convention`, off by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG` | Warning | medium | `env()` outside `config/`. |
| `LARAVEL_PITFALL_DEBUG` | Warning | medium | `dd()`/`dump()`/`ray()` in shipped code. |
| `LARAVEL_PITFALL_SLEEP_IN_TEST` | Warning | medium | `sleep()` in a test. |
| `DEAD_CODE` | Info | low | Unreferenced method/parameter. |
| `NAMING_CONVENTION` | Info | low | Naming that deviates from conventions. |
| `TODO_FIXME` | Info | low | Leftover TODO/FIXME/HACK markers. |

### Frontend (`analyzers/frontend`, on by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `JS_SYNTAX_ERROR` | Warning | medium | Unbalanced JS/TS/Vue tokens or strings. |
| `CSS_SYNTAX_ERROR` | Warning/Info | medium/low | Unbalanced CSS/SCSS/Less blocks. |
| `BLADE_STACK_MISMATCH` | Error/Warning/Info | high/medium/low | Orphan/empty `@push`/`@stack`, unclosed `@push`. |

### Ops (`analyzers/ops`, on by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `PERMS_TOO_OPEN` | Warning | medium | World-writable files/directories. |
| `EOL_COMPONENT` | Warning | medium | End-of-life PHP/Laravel line. |

### Forensics (`analyzers/security`, on by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `ROGUE_PHP` | Critical | high | Unexpected PHP file in `public/` (opt-in for non-Laravel). |
| `OBFUSCATED_PHP` | Critical | medium | Obfuscated backdoor patterns. |

### Confidence & Tiering

Every issue carries a confidence: `high` is safe to gate CI on, `medium` is a
reliable warning, `low` is a heuristic hint. `--min-confidence` filters what is
reported; `--tier=security` only fails the gate on high-confidence security
findings; `--min-severity` hides light findings from reports without changing
the gate.

## Baseline

A baseline is a JSON list of signatures (`md5(rule|file|line|message)`):

```bash
php bin/rampart /path/to/project --baseline-generate
php bin/rampart /path/to/project --ci --baseline-file=baseline.json
```

Commit `baseline.json` to share the starting point; only new findings fail.

## False positives

The analyzers are static heuristics. Read the file/line first, fix the code when
possible, and baseline only reviewed findings. Use inline suppression for a
single reviewed line:

```php
$value = file_get_contents($url); // rampart-ignore OWASP_SSRF
```

## Development

```bash
composer install
composer check   # phpcs + phpstan + phpunit
composer smoke   # build + install the archive, run the installed binary
```

The package dogfoods itself: `bin/rampart` is run over `src/` in CI. The labelled
precision corpus lives in `tests/Unit/AnalyzerMetricsTest.php`; the plain-PHP
rules have their own TP/FP tests in `tests/Unit/GenericSecurityAnalyzersTest.php`.
See [docs/tools.md](docs/tools.md) for the benchmark and external-precision
scripts.

## License

MIT.
