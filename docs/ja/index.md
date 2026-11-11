---
layout: default
title: Rampart PHP — 日本語
description: Rampart PHP の日本語ドキュメント。
---

# Rampart PHP — 日本語

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

**プレーン PHP とあらゆるフレームワーク**向けのスタンドアロン品質ゲート —
Slim、CodeIgniter 4、FuelPHP、Symfony、Phalcon、Laravel に対応。ツール自体は
PHP **7.4+** で動作し、対象コードは実行せず解析のみ行います。

## Rampart ファミリー

| プロジェクト | 対象 | リポジトリ | ドキュメント |
|---|---|---|---|
| **Rampart** | Laravel Artisan 品質ゲート | [GitHub](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | プレーン PHP + 各フレームワーク、PHP 7.4+ | [GitHub](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress プラグイン/テーマ | [GitHub](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## インストール

```bash
git clone https://github.com/thiennhant95/Rampart-PHP.git
cd Rampart-PHP
composer install
```

対象プロジェクトへのインストールは不要です。`custom` ルールは対象の依存関係
なしで動作します。`phpcs`/`phpstan`/`phpunit`/`composer audit` は、対象に
`vendor/` がある場合のみそのツールを使用します。

## クイックスタート

```bash
# セキュリティスキャン
php bin/rampart /path/to/project --tier=security --fail-on=none

# 全レポート出力
php bin/rampart /path/to/project --format=all --output=reports/rampart

# 現状確認 → ベースライン化 → 新規のみ失敗
php bin/rampart /path/to/project --fail-on=none
php bin/rampart /path/to/project --baseline-generate
php bin/rampart /path/to/project --ci --baseline-file=baseline.json
```

終了コード: `0` 合格 · `1` しきい値超過 · `2` 不正な引数 · `3` 内部エラー。

## 対応フレームワーク

検出は `composer.json` とマーカーファイルで行います。`--framework=` で強制可能。

| フレームワーク | 検出 | ルート / 認可解析 |
|---|---|---|
| プレーン PHP | フォールバック | ディレクトリ、テンプレート、`public/` |
| Slim 4 | `slim/slim` | `routes/*.php`、`->add()/->middleware()` |
| CodeIgniter 4 | `spark` + `app/Config` | `Routes.php`、`filter` 認可 |
| FuelPHP | `fuel/app` | コントローラの `before()` と親クラス |
| Symfony | `config/bundles.php` / `src/Kernel.php` | 属性 + YAML ルート + `security.yaml` |
| Phalcon | `phalcon/cphalcon` / `app/controllers` | `routes.php`、`beforeExecuteRoute` ACL |
| Laravel | `laravel/framework` | ルート・ミドルウェア・ポリシーの完全解析 |

Laravel 専用ルール（BAC/IDOR、マスアサインメント、CSRF、Blade、マイグレーション、
ルートバリデーション）は Laravel 検出時のみ実行されます。

## 検査内容

- **セキュリティ:** SQLi（PDO `query()` 含む）、コマンドインジェクション、パストラバーサル、
  SSRF、XSS、オープンリダイレクト、SSTI、XXE、LDAP インジェクション、eval/デシリアライズ、
  ハードコード秘密情報、弱いハッシュ/暗号/乱数、Cookie/セッション、ヘッダーインジェクション。
- **OWASP Top 10 2021:** A01/A03/A05/A07/A10 を JSON/HTML/SARIF に集計。
- **ルート認可:** 状態変更ルートに認可が見えない場合（Slim/CI4/FuelPHP/Symfony/Phalcon）。
- **オプション:** テイントエンジン、テスト不足（`--coverage`）、規約、デバッグ出力、
  フォレンジック、権限/EOL。

完全な一覧: [README](https://github.com/thiennhant95/Rampart-PHP#custom-analyzer-rules)

## レポート

| 形式 | ファイル | 用途 |
|---|---|---|
| `console` | 標準出力 | ターミナル |
| `json` | `rampart-report.json` | CI、ツール連携 |
| `html` | `rampart-report.html` | 開発者向け |
| `md` | `rampart-report.md` | PR コメント |
| `sarif` | `rampart-report.sarif` | GitHub コードスキャン |

HTML は `--no-remediation`（修正ガイドなし）、`--client`（外部向け）、
`--all-variants`（3 種類）に対応。

## CI

```yaml
- run: composer install --prefer-dist --no-progress
- run: php bin/rampart . --only=custom --ci --fail-on=error
  working-directory: tools/rampart
```

`--format=sarif` で `rampart-report.sarif` を生成し、GitHub コードスキャンに
アップロードできます。`custom` は対象の `vendor/` を必要としません。

## ベースラインとノイズ制御

```bash
php bin/rampart /path --baseline-generate
php bin/rampart /path --ci --baseline-file=baseline.json
php bin/rampart /path --min-severity=error --ignore=ROUTE_MISSING_AUTH
```

インライン抑制: `// rampart-ignore RULE_ID` または
`// rampart-ignore-next-line RULE_ID`。旧 `quality-checker-ignore` も使用可能。

## パフォーマンス

AST は 1 ファイルにつき 1 回だけ読み込み・解析します。`bin/rampart` は CLI の
メモリ下限を 512M に引き上げます。テイントエンジンは大規模ツリーでさらに
メモリを必要とする場合があります（`php -d memory_limit=1G`）。

## 開発

```bash
composer check   # phpcs + phpstan + phpunit
composer smoke   # アーカイブをビルド・インストールして実行
```

本プロジェクト自身をスキャンしており、オプションルールを含めて 0 findings です。

## ライセンス

MIT © 2026 Rampart.
