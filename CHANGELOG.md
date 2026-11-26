# Changelog

All notable changes to Rampart PHP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.3] - 2026-11-25

### Fixed

- `INSECURE_HASH` now flags `random_int()` with a tiny literal range in a
  token/OTP context (e.g. `random_int(0, 9)`), while large OTP ranges stay
  silent.
- `INSECURE_HASH` recognises `hash_hmac()` with weak algorithms and
  non-cryptographic checksums (`crc32`, `crc32b`, `adler32`) in credential
  context.

## [0.2.2] - 2026-11-25

### Fixed

- Security and OWASP analyzers skip test paths by default, so fixture files
  are not reported as production sinks.
- `OWASP_SSRF` no longer flags paths rooted at `__DIR__`/`__FILE__`/`dirname()`.
- `call_user_func` callables guarded by `is_callable()` or
  `instanceof \Closure` in the same function are treated as internally
  registered.

### Changed

- README now documents project status, supported versions and scope.

## [0.2.1] - 2026-11-25

### Fixed

- `UNSAFE_UNSERIALIZE` now matches function names case-insensitively, resolves
  simple `$f = 'unserialize'; $f(...)` indirection, and follows
  `call_user_func('unserialize', ...)` wrappers.
- `UNSAFE_EVAL` resolves simple variable function names and flags
  `call_user_func('assert', $code)` targets instead of skipping the literal
  callable.
- Malformed PHP no longer drops the whole file: the parser recovers the AST
  around syntax errors, so valid sinks elsewhere in the file are still checked.
- `OBFUSCATED_PHP` reports the matched source line and covers decode-family
  calls (`base85_decode`, `str_rot*`, `*_decode`) and malformed `eval[...]`.
- `WEAK_PASSWORD_POLICY` checks both ternary branches, resolves literal
  concatenation/variables, and reports an unverifiable dynamic rule beside a
  valid literal one instead of silently trusting it.

## [0.2.0] - 2026-11-20

### Added

- `MISSING_COMPOSER` and `INVALID_CONSTRAINT`: a Composer-managed project
  (installed `vendor/`, lock file, or a Composer console binary) with no
  `composer.json`, or a manifest that is unparseable / carries a non-string
  `php` or `laravel/framework` constraint.
- Shared `PhpPayloadPatterns` detector backing `OBFUSCATED_PHP` and the
  rogue-file grading (PHP 7.4-compatible, string/comment stripping).

### Changed

- `ROGUE_PHP` grades by content: obfuscation/code-execution evidence →
  Critical with `metadata.matched_pattern`; an otherwise benign misplaced file
  → Warning. The rule stays opt-in.
- `PERMS_TOO_OPEN` compares permission bits instead of a hardcoded octal list:
  other-write → Critical, group-write → Warning; file/dir-specific fix hints;
  `.env` at the usual 644 is silent; `storage/framework` and `storage/logs` are
  whitelisted.
- `EOL_COMPONENT` reports lines older than the tracked map with a generic
  "older than X" message, and stays silent for open ranges (`>=`) and any
  supported line.

### Fixed

- Console output no longer claims `✔ All checks passed.` when checkers reported findings within the `--fail-on` threshold — it now says so explicitly.

## [0.1.1] - 2026-11-13

### Added

- Real standalone security-scan screenshot in the README and the EN/JA/VI docs pages.

## [0.1.0] - 2026-11-11

### Added

- Standalone `bin/rampart` entry point: scans any directory without installing
  into the target and without booting a framework.
- 59 rules: generic security/OWASP rules, framework routing, test coverage,
  conventions, frontend, ops and forensics.
- Framework detection and layouts for plain PHP, Slim 4, CodeIgniter 4,
  FuelPHP, Symfony, Phalcon and Laravel.
- Framework-specific route authorization:
  - Slim `->add()/->middleware()`, including group closures.
  - CodeIgniter 4 `filter` auth.
  - FuelPHP controller `before()` and parent chain.
  - Symfony attributes, YAML routes and `security.yaml access_control`.
  - Phalcon `beforeExecuteRoute`/`beforeDispatch` ACL and parent chain.
- Laravel-only analyzers are gated behind Laravel detection so Eloquent/Blade
  semantics never produce false positives on other frameworks.
- PHP 7.4 runtime support: value-object replacements for enums, Symfony 5.4,
  PHPUnit 9.6, PHPStan 1.12, Rector-based downgrade.
- Reports: console, JSON, HTML (developer, findings-only, client), Markdown and
  SARIF 2.1.0. JSON/SARIF include the detected framework.
- Baseline, inline suppression (`rampart-ignore`, legacy
  `quality-checker-ignore`), result cache and taint engine (opt-in).
- Labelled corpus (500 cases, 98 holdout), CVE recall (30/30), external
  precision and inter-rater tools.
- GitHub Actions matrix (PHP 7.4–8.3, Linux/Windows), self-scan dogfood and
  archive smoke test.
- Multilingual documentation site (English, 日本語, Tiếng Việt).

### Fixed

- Dogfood pass: branding cleanup, framework metadata in reports, `issue()`
  naming false positive, static PHPUnit assertions, dead-code false positives
  on abstract/protected helpers.
- CLI memory floor raised to 512M so the taint engine no longer aborts with
  PHP's default 128M on a few hundred files.

[Unreleased]: https://github.com/thiennhant95/Rampart-PHP/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/thiennhant95/Rampart-PHP/releases/tag/v0.1.0
