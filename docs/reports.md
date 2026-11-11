# Reports

One scan can write five formats and three HTML presentations.

| Format | File | Use |
|---|---|---|
| `console` | stdout | Local terminal |
| `json` | `rampart-report.json` | CI, dashboards, tooling |
| `html` | `rampart-report.html` | Developer browser view |
| `md` | `rampart-report.md` | PR comments, docs |
| `sarif` | `rampart-report.sarif` | GitHub code scanning |

## HTML variants

| Reader | Flag | File |
|---|---|---|
| Fix the issues | default | `rampart-report.html` |
| Review without fix boxes | `--no-remediation` | `rampart-report-findings.html` |
| External / client summary | `--client` | `rampart-report-client.html` |
| Archive every presentation | `--all-variants` | all three |

The HTML file is self-contained (inline CSS/JS) and works from `file://`.
Set `html.repo_url` in the config to turn file links into GitHub blob links;
otherwise they use `vscode://`.
