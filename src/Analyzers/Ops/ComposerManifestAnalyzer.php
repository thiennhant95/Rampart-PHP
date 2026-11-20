<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Ops;

use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;
use Rampart\Php\Scanning\ScanContextAware;
use Rampart\Php\Scanning\ScanContextTrait;

/**
 * Missing or unparseable `composer.json`.
 *
 * Deliberately separate from EOL_COMPONENT: "the manifest is absent / broken"
 * is a different problem from "the pinned version is unsupported", and
 * conflating them made EOL_COMPONENT fire on every sub-directory a runner
 * happened to point at.
 *
 * This package is framework-agnostic and Composer is optional for plain PHP,
 * so a missing manifest is only reported when there is positive evidence the
 * project is Composer-managed (an installed `vendor/`, a lock file, or a
 * Composer-provided console binary). A stray `src/` folder never reports.
 * An *existing but broken* manifest is always a finding.
 *
 * PHP 7.4 compatible.
 */
final class ComposerManifestAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE_MISSING = 'MISSING_COMPOSER';

    private const RULE_INVALID = 'INVALID_CONSTRAINT';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }

        $composer = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composer)) {
            if (!$this->looksComposerManaged($root)) {
                return [];
            }

            return [new Issue(
                self::RULE_MISSING,
                'composer.json is missing from a Composer-managed project — dependencies are not reproducible.',
                $composer,
                1,
                Severity::$Warning,
                'custom',
                ['path' => $composer, 'reason' => 'missing_composer'],
                Confidence::$High
            )];
        }

        $code = $this->sharedSource($composer);
        if ($code === '') {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json is empty or unreadable — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::$Error,
                'custom',
                ['path' => $composer, 'reason' => 'unreadable'],
                Confidence::$High
            )];
        }

        $data = json_decode($code, true);
        if (!is_array($data)) {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json is not valid JSON — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::$Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_json'],
                Confidence::$High
            )];
        }

        $requires = $data['require'] ?? null;
        if ($requires !== null && !is_array($requires)) {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json "require" is not an object — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::$Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_require'],
                Confidence::$High
            )];
        }

        if (!is_array($requires)) {
            return [];
        }

        $issues = [];
        foreach (['php', 'laravel/framework'] as $package) {
            if (!array_key_exists($package, $requires)) {
                continue;
            }
            $constraint = $requires[$package];
            if (is_string($constraint) && trim($constraint) !== '') {
                continue;
            }
            $issues[] = new Issue(
                self::RULE_INVALID,
                sprintf('composer.json constraint for %s is not a version string.', $package),
                $composer,
                1,
                Severity::$Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_constraint', 'package' => $package],
                Confidence::$High
            );
        }

        return $issues;
    }

    /**
     * Positive evidence that a project uses Composer. Prefer artifacts over
     * layout: a plain-PHP project may legitimately have `src/` + `public/`
     * and never touch Composer.
     */
    private function looksComposerManaged(string $root): bool
    {
        return is_dir($root . DIRECTORY_SEPARATOR . 'vendor')
            || is_file($root . DIRECTORY_SEPARATOR . 'composer.lock')
            || is_file($root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'console')
            || is_file($root . DIRECTORY_SEPARATOR . 'artisan');
    }
}
