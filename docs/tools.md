# Tools

These scripts are development aids, not runtime dependencies.

## Benchmark your projects

```bash
php tools/benchmark-projects.php manifest.json
php tools/benchmark-projects.php manifest.json --baseline=bench.json
php tools/benchmark-projects.php manifest.json --diff=bench.json
```

Manifest:

```json
{
  "defaults": { "tier": "security", "min_confidence": "low" },
  "targets": [
    { "name": "shop", "path": "C:/src/shop" },
    { "name": "legacy", "path": "C:/src/legacy", "min_confidence": "medium" },
    { "name": "skip", "path": "C:/src/old", "enabled": false }
  ]
}
```

Each target is scanned with `--only=custom`, `--fail-on=none` and `--no-cache`.
The output is a per-rule count and share, plus a `--diff` view after an upgrade.
The manifest stays local; no project list ships with the package.

## External precision

```bash
php bin/rampart /path/to/project --only=custom --tier=security \
    --fail-on=none --format=json --output=/tmp/out
php tools/sample-findings.php /tmp/out/rampart-report.json \
    --n=100 --seed=42 --out=sample.csv
# label the `verdict` column in sample.csv with TP/FP, then:
php tools/inter-rater.php reviewer1.csv reviewer2.csv
```

Per-rule precision is `TP / (TP + FP)`; the target for high-confidence rules is
≥ 0.85. Inter-rater kappa should be ≥ 0.9.

## Smoke test

```bash
composer smoke
```

Builds `composer archive`, asserts the runtime subset (and no `tests/`,
`tools/`, `.github/`, `vendor/`), installs the archive into a temp directory,
and runs the installed `bin/rampart` against a vulnerable fixture. It needs a
committed `.git` tree (Composer archive) and `tar`.
