# Contributing to Rampart PHP

Thanks for helping. This project is a static quality gate for PHP 7.4+ and any
framework; changes must keep both the tool and the scanned targets compatible.

## Development setup

```bash
git clone https://github.com/thiennhant95/Rampart-PHP.git
cd Rampart-PHP
composer install
composer check   # phpcs + phpstan + phpunit
composer smoke   # archive -> install -> run the installed binary
```

The tool dogfoods itself:

```bash
php bin/rampart . --path=src --path=bin --only=custom --fail-on=warning --no-cache
```

## Adding or changing a rule

1. Add the rule id to `src/Result/RuleIds.php::all()`.
2. Implement the analyzer under `src/Analyzers/` and register it in
   `src/Analyzers/AnalyzerRegistry.php` with its config key.
3. Add a remediation entry in `src/Remediation/RuleRemediation.php`.
4. Add **true-positive and false-positive** cases to the appropriate test:
   - `tests/Unit/AnalyzerMetricsTest.php` for the labelled corpus, or
   - a focused test next to it (e.g. `GenericSecurityAnalyzersTest.php`).
5. Document the rule in the `README.md` rule tables. `RuleDocsTest` fails if a
   rule is undocumented or a documented id does not exist.
6. Add the config default and a note to `docs/rules.md` when the rule is
   framework-specific or conservative.

## Quality bar

- `composer check` must be green on PHP 7.4 **and** PHP 8.2.
- New analyzers must not raise false positives on this repository's self-scan
  (including `--coverage` and convention rules when touched).
- Keep diagnostics actionable: severity, confidence and a fix sample.
- Framework-specific rules belong behind the detected profile. Laravel rules
  must not fire on Slim, CI4, FuelPHP, Symfony or Phalcon.

## Commit and PR

- One logical change per commit; write a concise message.
- Use the pull request template and link the issue it fixes.
- Do not commit `vendor/`, `composer.lock`, reports or generated archives;
  they are gitignored.

## License

By contributing you agree that your work is licensed under the MIT License.
