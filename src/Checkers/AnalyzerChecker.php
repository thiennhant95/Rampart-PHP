<?php

declare(strict_types=1);

namespace Rampart\Php\Checkers;

use Rampart\Php\Analyzers\AnalyzerRegistry;
use Rampart\Php\Analyzers\Deduplicator;
use Rampart\Php\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspOwnershipAnalyzer;
use Rampart\Php\Analyzers\Security\Taint\TaintEngine;
use Rampart\Php\Profiling\Profiler;
use Rampart\Php\Result\CheckResult;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;
use Rampart\Php\Runner\CheckContext;
use Rampart\Php\Scanning\PathExcluder;
use Rampart\Php\Scanning\ScanContext;
use Rampart\Php\Scanning\ScanContextAware;
use Rampart\Php\Framework\Framework;
use Rampart\Php\Framework\FrameworkProfile;
use Rampart\Php\Semantic\OwnershipShadow;
use Rampart\Php\Suppression\InlineSuppressor;

/**
 * Runs the 50 custom rules against a target using the detected framework
 * profile. Replaces the Laravel-shaped CustomAnalyzerChecker: file collection
 * is driven by FrameworkProfile instead of hardcoded `app/` + `resources/`.
 */
class AnalyzerChecker implements CheckerInterface
{
    public function name(): string
    {
        return 'custom';
    }

    public function description(): string
    {
        return 'Custom analyzers: security (OWASP + taint), framework routing, missing tests, conventions.';
    }

    public function config(): array
    {
        return ['enabled' => true];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        $config = $ctx->config['analyzers'] ?? [];

        return (bool) ($config['enabled'] ?? true);
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        Profiler::enableFromEnvironment();
        if ($ctx->profile) {
            Profiler::setEnabled(true);
        }

        $profile = $ctx->frameworkProfile ?? FrameworkProfile::for(Framework::$PLAIN);

        Profiler::begin('discovery');
        [$phpFiles, $oversized, $excluded] = $this->collectPhpFiles($ctx, $profile);
        [$routeFiles, $routeOversized] = $this->collectRouteFiles($ctx, $profile);
        [$viewFiles, $viewOversized] = $this->collectViewFiles($ctx, $profile);
        [$jsFiles, $jsOversized] = $this->collectFrontend($ctx, $profile, ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue']);
        [$cssFiles, $cssOversized] = $this->collectFrontend($ctx, $profile, ['css', 'scss', 'sass', 'less']);
        $oversized += $routeOversized + $viewOversized + $jsOversized + $cssOversized;

        $files = array_values(array_unique(array_merge(
            $phpFiles,
            $routeFiles,
            $viewFiles,
            $jsFiles,
            $cssFiles,
            $this->collectEnvFiles($ctx)
        )));
        Profiler::end('discovery');

        $scan = new ScanContext();
        $scan->setBasePath($ctx->basePath);

        $issues = [];
        OwnershipShadow::reset();
        $parkGc = getenv('VV_NO_GC_PARK') !== '1';
        if ($parkGc) {
            gc_disable();
        }
        try {
            foreach (AnalyzerRegistry::build($ctx->config['analyzers'] ?? [], $profile) as $entry) {
                if (!$entry['enabled']) {
                    continue;
                }
                $analyzer = $entry['analyzer'];
                if ($analyzer instanceof ScanContextAware) {
                    $analyzer->setScanContext($scan);
                }
                Profiler::countFilesVisited(
                    (string) (new \ReflectionClass($analyzer))->getShortName(),
                    count($files)
                );
                $issues = array_merge($issues, $this->runAnalyzer($analyzer, $files));
            }
        } finally {
            if ($parkGc) {
                gc_enable();
            }
        }

        if ((bool) ($ctx->config['analyzers']['security']['taint_engine'] ?? false)) {
            $issues = array_merge($issues, $this->runTaintEngine($files));
        }

        $issues = (new Deduplicator())->dedupeList($issues);
        $issues = $this->reconcileOwnership($issues);
        $issues = $this->applySeverityOverrides($issues, $ctx);

        $suppressed = 0;
        if ((bool) ($ctx->config['analyzers']['inline_suppression'] ?? true)) {
            $suppressor = new InlineSuppressor();
            $issues = $suppressor->filter($issues);
            $suppressed = $suppressor->countSuppressed();
        }

        $minConfidence = Confidence::fromString(
            $ctx->minConfidence !== ''
                ? $ctx->minConfidence
                : (string) ($ctx->config['min_confidence'] ?? 'low')
        );
        $issues = array_values(array_filter(
            $issues,
            static fn (Issue $issue): bool => $issue->confidence->intValue() >= $minConfidence->intValue()
        ));

        $status = 'passed';
        foreach ($issues as $issue) {
            if ($issue->severity === Severity::$Error || $issue->severity === Severity::$Critical) {
                $status = 'failed';
                break;
            }
            $status = 'warning';
        }

        $summary = sprintf(
            '%s analysers found %d issue(s) across %d file(s).',
            $profile->label,
            count($issues),
            count($files)
        );
        if ($suppressed > 0) {
            $summary .= sprintf(' %d suppressed via inline ignore.', $suppressed);
        }
        if ($oversized > 0) {
            $summary .= sprintf(' %d oversized file(s) skipped.', $oversized);
        }
        if ($excluded > 0) {
            $summary .= sprintf(' %d file(s) excluded by analyzers.exclude_paths.', $excluded);
        }

        return new CheckResult($this->name(), $status, microtime(true) - $start, $issues, null, $summary);
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function runAnalyzer(object $analyzer, array $files): array
    {
        $issues = [];
        foreach ($analyzer->analyze($files) as $issue) {
            if ($issue instanceof Issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function runTaintEngine(array $files): array
    {
        $issues = [];
        foreach ((new TaintEngine())->analyze($files) as $raw) {
            if (is_array($raw)) {
                $issues[] = Issue::fromArray($raw);
            }
        }

        return $issues;
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function reconcileOwnership(array $issues): array
    {
        $decisions = OwnershipShadow::all();
        if ($decisions === []) {
            return $issues;
        }

        $byAction = [];
        foreach ($decisions as $decision) {
            $byAction[$this->ownershipIdentity($decision->file, $decision->controller, $decision->method)] = $decision;
        }

        $bacIndex = [];
        foreach ($issues as $i => $issue) {
            if ($issue->rule !== OwaspAccessControlAnalyzer::RULE) {
                continue;
            }
            $controller = (string) ($issue->metadata['controller'] ?? '');
            $action = (string) ($issue->metadata['action'] ?? ($issue->metadata['method'] ?? ''));
            if ($controller !== '' && $action !== '') {
                $bacIndex[$this->ownershipIdentity((string) $issue->file, $controller, $action)] = $i;
            }
        }

        $drop = [];
        foreach ($issues as $i => $issue) {
            if ($issue->rule !== OwaspOwnershipAnalyzer::RULE) {
                continue;
            }
            $controller = (string) ($issue->metadata['controller'] ?? '');
            $action = (string) ($issue->metadata['action'] ?? '');
            $key = $this->ownershipIdentity((string) $issue->file, $controller, $action);
            if (isset($bacIndex[$key])) {
                $issues[$bacIndex[$key]]->metadata['access_control']['ownership'] =
                    $issue->metadata['access_control']['ownership'] ?? [];
                $issues[$bacIndex[$key]]->metadata['access_control']['ownership_merged'] = true;
                $drop[$i] = true;
            }
        }
        if ($drop !== []) {
            $issues = array_values(array_filter(
                $issues,
                static fn (Issue $issue, int $i): bool => !isset($drop[$i]),
                ARRAY_FILTER_USE_BOTH
            ));
        }

        return array_values($issues);
    }

    private function ownershipIdentity(string $file, string $controller, string $action): string
    {
        return strtolower($file . '|' . ltrim($controller, '\\') . '@' . $action);
    }

    /**
     * @param list<Issue> $issues
     * @return list<Issue>
     */
    private function applySeverityOverrides(array $issues, CheckContext $ctx): array
    {
        $overrides = $ctx->config['analyzers']['severity_overrides'] ?? [];
        if (!is_array($overrides) || $overrides === []) {
            return $issues;
        }

        $map = [];
        foreach ($overrides as $rule => $severity) {
            if (!is_string($rule) || !is_string($severity)) {
                continue;
            }
            if (Severity::tryFrom(strtolower($severity)) === null) {
                continue;
            }
            $map[strtoupper($rule)] = Severity::fromString($severity);
        }

        foreach ($issues as $issue) {
            $override = $map[strtoupper($issue->rule)] ?? null;
            if ($override !== null) {
                $issue->severity = $override;
            }
        }

        return $issues;
    }

    /**
     * @return array{list<string>, int, int} [files, oversized, excluded]
     */
    private function collectPhpFiles(CheckContext $ctx, \Rampart\Php\Framework\FrameworkProfile $profile): array
    {
        $files = [];
        $oversized = 0;
        $excluded = 0;
        $maxBytes = $this->maxFileBytes($ctx);
        $excluder = PathExcluder::fromConfig($ctx->config);
        $skipDirs = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git'];

        $roots = $ctx->paths;
        if ($roots === []) {
            $roots = $profile->existingScanPaths($ctx->basePath);
        }

        foreach ($roots as $path) {
            $abs = $ctx->resolvePath($path);
            if (is_file($abs)) {
                if (strtolower((string) pathinfo($abs, PATHINFO_EXTENSION)) === 'php') {
                    $files[] = $abs;
                }
                continue;
            }
            if (!is_dir($abs)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($abs, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                if (strtolower($file->getExtension()) !== 'php') {
                    continue;
                }
                $pathname = str_replace('\\', '/', $file->getPathname());
                if (!$excluder->isEmpty() && $excluder->excludes($pathname)) {
                    ++$excluded;
                    continue;
                }
                if ($maxBytes > 0 && $file->getSize() > $maxBytes) {
                    ++$oversized;
                    continue;
                }
                foreach ($skipDirs as $skipDir) {
                    if (strpos($pathname, '/' . $skipDir . '/') !== false) {
                        continue 2;
                    }
                }
                $files[] = $file->getPathname();
            }
        }

        return [array_values(array_unique($files)), $oversized, $excluded];
    }

    /**
     * @return array{list<string>, int}
     */
    private function collectRouteFiles(CheckContext $ctx, \Rampart\Php\Framework\FrameworkProfile $profile): array
    {
        $files = [];
        $oversized = 0;
        $maxBytes = $this->maxFileBytes($ctx);
        $excluder = PathExcluder::fromConfig($ctx->config);

        foreach ($profile->existingRouteFiles($ctx->basePath) as $abs) {
            $normalized = str_replace('\\', '/', $abs);
            if (!$excluder->excludes($normalized)) {
                if ($maxBytes > 0 && is_file($abs) && filesize($abs) > $maxBytes) {
                    ++$oversized;
                    continue;
                }
                $files[] = $abs;
            }
        }

        return [array_values(array_unique($files)), $oversized];
    }

    /**
     * @return array{list<string>, int}
     */
    private function collectViewFiles(CheckContext $ctx, \Rampart\Php\Framework\FrameworkProfile $profile): array
    {
        $files = [];
        $oversized = 0;
        $maxBytes = $this->maxFileBytes($ctx);
        $excluder = PathExcluder::fromConfig($ctx->config);

        foreach ($profile->existingViewDirs($ctx->basePath) as $dir) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                $lower = strtolower($file->getFilename());
                if (substr_compare($lower, '.blade.php', -strlen('.blade.php')) !== 0) {
                    continue;
                }
                if ($maxBytes > 0 && $file->getSize() > $maxBytes) {
                    ++$oversized;
                    continue;
                }
                $pathname = str_replace('\\', '/', $file->getPathname());
                if ($excluder->excludes($pathname)) {
                    continue;
                }
                $files[] = $file->getPathname();
            }
        }

        return [array_values(array_unique($files)), $oversized];
    }

    /**
     * @param list<string> $extensions
     * @return array{list<string>, int}
     */
    private function collectFrontend(CheckContext $ctx, \Rampart\Php\Framework\FrameworkProfile $profile, array $extensions): array
    {
        $files = [];
        $oversized = 0;
        $maxBytes = $this->maxFileBytes($ctx);
        $excluder = PathExcluder::fromConfig($ctx->config);

        $roots = array_merge(['resources'], $profile->publicDirs);
        foreach ($roots as $relative) {
            $abs = $ctx->resolvePath($relative);
            if (!is_dir($abs)) {
                continue;
            }
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($abs, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }
                if (!in_array(strtolower($file->getExtension()), $extensions, true)) {
                    continue;
                }
                if ($maxBytes > 0 && $file->getSize() > $maxBytes) {
                    ++$oversized;
                    continue;
                }
                $pathname = str_replace('\\', '/', $file->getPathname());
                $lower = strtolower($pathname);
                if (
                    strpos($lower, '.min.') !== false
                    || strpos($lower, '/vendor/') !== false
                    || strpos($lower, '/node_modules/') !== false
                    || $excluder->excludes($pathname)
                ) {
                    continue;
                }
                $files[] = $file->getPathname();
            }
        }

        return [array_values(array_unique($files)), $oversized];
    }

    /**
     * @return list<string>
     */
    private function collectEnvFiles(CheckContext $ctx): array
    {
        $files = [];
        $excluder = PathExcluder::fromConfig($ctx->config);
        foreach (['.env', '.env.example'] as $name) {
            $abs = $ctx->resolvePath($name);
            if (!is_file($abs)) {
                continue;
            }
            $normalized = str_replace('\\', '/', $abs);
            if (strpos($normalized, '/vendor/') !== false || strpos($normalized, '/node_modules/') !== false) {
                continue;
            }
            if (!$excluder->excludes($normalized)) {
                $files[] = $abs;
            }
        }

        return $files;
    }

    /**
     * Compatibility helpers used by the collector tests. They take the
     * framework profile from the context (or fall back to plain PHP).
     *
     * @return array{list<string>, int}
     */
    protected function collectJsFiles(CheckContext $ctx): array
    {
        return $this->collectFrontend($ctx, $this->profileFor($ctx), ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue']);
    }

    /**
     * @return array{list<string>, int}
     */
    protected function collectCssFiles(CheckContext $ctx): array
    {
        return $this->collectFrontend($ctx, $this->profileFor($ctx), ['css', 'scss', 'sass', 'less']);
    }

    /**
     * @return array{list<string>, int}
     */
    protected function collectBladeFiles(CheckContext $ctx): array
    {
        return $this->collectViewFiles($ctx, $this->profileFor($ctx));
    }

    private function profileFor(CheckContext $ctx): FrameworkProfile
    {
        return $ctx->frameworkProfile ?? FrameworkProfile::for(Framework::$PLAIN);
    }

    private function maxFileBytes(CheckContext $ctx): int
    {
        $kb = (int) ($ctx->config['analyzers']['max_file_kb'] ?? 1024);

        return $kb <= 0 ? 0 : $kb * 1024;
    }
}
