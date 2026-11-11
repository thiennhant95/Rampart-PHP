---
layout: default
title: Rampart PHP
description: Standalone quality gate for plain PHP and any framework.
---

# Rampart PHP

**One command. Plain PHP or any framework. No install in the target.**

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

Rampart PHP wraps `phpcs`, `phpstan`, `phpunit`, `composer audit`, `npm audit`
and `trivy`, and adds **59 PHP-Parser rules** for security, framework routing,
missing tests and conventions. It parses the target; it never boots it.

```bash
git clone https://github.com/thiennhant95/Rampart-PHP.git
cd Rampart-PHP && composer install
php bin/rampart /path/to/project --tier=security --fail-on=none
```

## The Rampart family

| Project | Focus | Repository | Documentation |
|---|---|---|---|
| **Rampart** | Laravel quality gate: Artisan command, 50 rules, Laravel semantics | [thiennhant95/Rampart](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | Plain PHP + Slim, CodeIgniter 4, FuelPHP, Symfony, Phalcon, Laravel; PHP 7.4+ | [thiennhant95/Rampart-PHP](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress plugins and themes: WPCS, capability, nonce, escaping, `$wpdb` | [thiennhant95/Rampart-Wordpress](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## Start here

- [English documentation]({{ site.baseurl }}/en/) — install, frameworks, rules, reports, CI.
- [日本語ドキュメント]({{ site.baseurl }}/ja/)
- [Tài liệu tiếng Việt]({{ site.baseurl }}/vi/)

## Repository guides

- [Framework support](frameworks.html) — detection, layouts, route auth.
- [Rule notes](rules.html) — confidence, Laravel-only gating, conservative rules.
- [False positives](false-positives.html) — triage and inline suppression.
- [Reports](reports.html) — console, JSON, HTML, Markdown, SARIF.
- [Tools](tools.html) — benchmark, external precision, smoke test.

MIT © 2026 Rampart.
