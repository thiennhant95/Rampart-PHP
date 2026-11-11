# Documentation

Start with the [README](../README.md): install, quick start, every CLI option
and the complete rule reference.

## Guides

| Document | Read it when |
|---|---|
| [frameworks.md](frameworks.md) | You need to know how detection and framework-specific route analysis work. |
| [rules.md](rules.md) | You want the rule-by-rule detection notes and confidence rationale. |
| [false-positives.md](false-positives.md) | A finding looks wrong and you need to choose between fixing, suppressing and baselining. |
| [reports.md](reports.md) | You need the developer, findings-only or client HTML file. |
| [tools.md](tools.md) | You want to benchmark projects, sample findings or run the smoke test. |

## Source of truth

| Thing | File |
|---|---|
| Rule ids | `src/Result/RuleIds.php` |
| Analyzer registration | `src/Analyzers/AnalyzerRegistry.php` |
| Framework layouts | `src/Framework/FrameworkProfile.php` |
| Defaults | `config/rampart.php` |
| Precision corpus | `tests/Unit/AnalyzerMetricsTest.php` and `tests/Unit/GenericSecurityAnalyzersTest.php` |
| Framework routing tests | `tests/Unit/RouteAuthAnalyzerTest.php` |
