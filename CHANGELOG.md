# Changelog

All notable changes to Rampart PHP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
