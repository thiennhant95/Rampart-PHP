<?php

declare(strict_types=1);

namespace Rampart\Php\Runner;

use Rampart\Php\Checkers\AnalyzerChecker;
use Rampart\Php\Checkers\CheckerInterface;
use Rampart\Php\Checkers\ComposerAuditChecker;
use Rampart\Php\Checkers\NpmAuditChecker;
use Rampart\Php\Checkers\PhpcsChecker;
use Rampart\Php\Checkers\PhpstanChecker;
use Rampart\Php\Checkers\PhpunitChecker;
use Rampart\Php\Checkers\TrivyChecker;
use Rampart\Php\Result\CheckResult;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;
use Rampart\Php\Tools\ToolInstaller;

final class CheckRunner
{
    private CheckContext $ctx;

    public function __construct(CheckContext $ctx)
    {
        $this->ctx = $ctx;

        // Detect the layout once per run. `framework` in config (or
        // --framework=) forces a profile; otherwise composer.json + markers
        // decide. A wrong guess only affects framework-specific rules.
        $forced = (string) ($ctx->config['framework'] ?? '');
        $ctx->frameworkProfile = (new \Rampart\Php\Framework\FrameworkDetector())
            ->detect($ctx->basePath, $forced === 'auto' ? null : $forced);
    }

    /**
     * @return CheckerInterface[]
     */
    public function buildCheckers(): array
    {
        $checkers = [
            new PhpcsChecker(),
            new PhpstanChecker(),
            new PhpunitChecker(),
            new ComposerAuditChecker(),
            new NpmAuditChecker(),
            new TrivyChecker(),
            new AnalyzerChecker(),
        ];

        $only = $this->ctx->only;
        $exclude = $this->ctx->exclude;

        if (count($only) === 0 && count($exclude) === 0) {
            return $checkers;
        }

        return array_values(array_filter($checkers, function (CheckerInterface $checker) use ($only, $exclude): bool {
            if (count($only) > 0 && !in_array($checker->name(), $only, true)) {
                return false;
            }

            return !in_array($checker->name(), $exclude, true);
        }));
    }

    /**
     * Run all checkers sequentially (cache-aware).
     *
     * @param CheckerInterface[] $checkers
     * @return CheckResult[]
     */
    public function run(array $checkers): array
    {
        $cache = new ResultCache($this->ctx);
        $results = [];

        $cacheConfig = $this->ctx->config['cache'] ?? [];
        if (!is_array($cacheConfig)) {
            $cacheConfig = [];
        }
        $enabled = (bool) ($cacheConfig['enabled'] ?? true);
        $ttl = (int) ($cacheConfig['ttl'] ?? 3600);
        if ($ttl <= 0) {
            $ttl = 3600;
        }

        foreach ($checkers as $checker) {
            if (!$checker->isAvailable($this->ctx)) {
                $skipped = $this->tryProvision($checker);
                $results[] = $skipped;
                continue;
            }

            $cacheKey = $cache->key($checker->name(), $this->ctx->paths, $checker->config());

            if (!$this->ctx->noCache && $enabled) {
                $cached = $cache->get($cacheKey);
                if (is_array($cached)) {
                    $results[] = CheckResult::fromArray($cached);
                    continue;
                }
            }

            $result = $checker->run($this->ctx);
            if ($enabled) {
                $cache->put($cacheKey, $result->toArray(), $ttl);
            }
            $results[] = $result;
        }

        return $this->withoutLowSeverity($this->withoutIgnoredRules($results));
    }

    /**
     * Drop issues below the min-severity floor (context flag, else config
     * `min_severity`, else `info`). Applied after caching so the cache stays
     * valid, and after the ignore filter. The gate (`shouldFail`) keeps using
     * `--fail-on` independently: hiding warnings never un-fails a build, and
     * showing info never fails one.
     *
     * Unknown values fall back to `info` (show everything) rather than
     * hiding findings on a typo.
     *
     * @param CheckResult[] $results
     * @return CheckResult[]
     */
    private function withoutLowSeverity(array $results): array
    {
        $raw = $this->ctx->minSeverity !== '' ? $this->ctx->minSeverity : (string) ($this->ctx->config['min_severity'] ?? 'info');
        $floor = (($tryFrom = Severity::tryFrom(strtolower($raw))) ? $tryFrom->intValue() : null) ?? Severity::$Info->intValue();
        if ($floor <= Severity::$Info->intValue()) {
            return $results;
        }

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            $kept = [];
            foreach ($result->issues as $issue) {
                if ($issue instanceof Issue && $issue->severity->intValue() < $floor) {
                    continue;
                }
                $kept[] = $issue;
            }
            if (count($kept) !== count($result->issues)) {
                $result->issues = $kept;
                if ($result->issues === []) {
                    $result->status = 'passed';
                }
            }
        }

        return $results;
    }

    /**
     * Drop issues whose rule is listed in quality_gate.ignore (config or
     * --ignore=). Applied after caching so the cache stays valid.
     *
     * @param CheckResult[] $results
     * @return CheckResult[]
     */
    private function withoutIgnoredRules(array $results): array
    {
        $gate = $this->ctx->config['quality_gate'] ?? [];
        $ignore = is_array($gate) ? ($gate['ignore'] ?? []) : [];
        if (!is_array($ignore)) {
            $ignore = [];
        }
        $ignored = [];
        foreach ($ignore as $rule) {
            $rule = strtoupper(trim((string) $rule));
            if ($rule !== '') {
                $ignored[$rule] = true;
            }
        }
        if ($ignored === []) {
            return $results;
        }

        foreach ($results as $result) {
            $kept = [];
            foreach ($result->issues as $issue) {
                if ($issue instanceof Issue && isset($ignored[strtoupper($issue->rule)])) {
                    continue;
                }
                $kept[] = $issue;
            }
            if (count($kept) !== count($result->issues)) {
                $result->issues = $kept;
                if ($result->issues === []) {
                    $result->status = 'passed';
                }
            }
        }

        return $results;
    }

    /**
     * Try to self-provision a missing tool; if it becomes available, run the
     * checker for real. Otherwise return a 'skipped' result with an install hint.
     */
    private function tryProvision(CheckerInterface $checker): CheckResult
    {
        $installer = new ToolInstaller($this->ctx);

        if ($installer->canInstall($checker->name())) {
            $installed = $installer->install($checker->name());
            if ($installed && $checker->isAvailable($this->ctx)) {
                return $checker->run($this->ctx);
            }

            return new CheckResult(
                $checker->name(),
                'skipped',
                0.0,
                [],
                null,
                sprintf(
                    '%s — tool is missing and could not be auto-installed. Install manually: %s',
                    $checker->description(),
                    $installer->hint($checker->name())
                )
            );
        }

        return new CheckResult(
            $checker->name(),
            'skipped',
            0.0,
            [],
            null,
            sprintf('%s — tool not available in this project.', $checker->description())
        );
    }

    /**
     * @param CheckResult[] $results
     */
    public function shouldFail(array $results): bool
    {
        if (strtolower($this->ctx->failOn) === 'none') {
            return false;
        }

        $threshold = Severity::fromString($this->ctx->failOn)->intValue();
        $minConfidence = Confidence::fromString($this->ctx->minConfidence)->intValue();

        foreach ($results as $result) {
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }

                // Only high-confidence issues can fail the gate at the 'security' tier.
                if (
                    $this->ctx->tier === 'security'
                    && $issue->source !== 'composer_audit'
                    && $issue->confidence->intValue() < Confidence::$High->intValue()
                ) {
                    continue;
                }

                if ($issue->confidence->intValue() < $minConfidence) {
                    continue;
                }

                if ($issue->severity->intValue() >= $threshold) {
                    return true;
                }
            }
        }

        return false;
    }
}
