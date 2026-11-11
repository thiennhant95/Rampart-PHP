# Rampart PHP — Agent Skill

Use this skill to run a quality gate on plain PHP or any supported framework
without installing anything into the target.

## Commands

```bash
# Security-only standalone scan
php bin/rampart /path/to/project --tier=security --fail-on=none

# All reports
php bin/rampart /path/to/project --format=all --output=reports/rampart

# Force a framework when detection is ambiguous
php bin/rampart /path/to/project --framework=slim --only=custom

# Review, accept, then gate only new findings
php bin/rampart /path/to/project --fail-on=none
php bin/rampart /path/to/project --baseline-generate
php bin/rampart /path/to/project --ci --baseline-file=baseline.json
```

## Outputs

- `rampart-report.html` — self-contained, searchable, dark mode
- `rampart-report.json` — machine-readable
- `rampart-report.md` — Markdown with a mermaid pie
- `rampart-report.sarif` — GitHub code scanning

## Gate

Exit `0` passed, `1` findings above threshold, `2` bad invocation, `3` internal
error. Use `--fail-on=none` to review without failing.

## Notes

- PHP 7.4+ to run the tool; the target is parsed, not executed.
- `custom` works without the target's `vendor/`; `phpcs`/`phpstan`/`phpunit`
  need it.
- `--ignore=RULE` drops a noisy rule from the report.
