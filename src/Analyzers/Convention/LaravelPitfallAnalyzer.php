<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Convention;

use PhpParser\Node;
use Rampart\Php\Analysis\CountingNodeFinder;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;
use Rampart\Php\Profiling\Profiler;
use Rampart\Php\Scanning\ScanContextAware;
use Rampart\Php\Scanning\ScanContextTrait;

final class LaravelPitfallAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE_ENV_OUTSIDE_CONFIG = 'LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG';
    private const RULE_DEBUG = 'LARAVEL_PITFALL_DEBUG';
    private const RULE_SLEEP_IN_TEST = 'LARAVEL_PITFALL_SLEEP_IN_TEST';

    private const DEBUG_FUNCTIONS = ['dd', 'dump', 'var_dump', 'print_r'];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();
        $normalized = str_replace('\\', '/', $file);
        $isConfig = str_contains($normalized, '/config/');
        $isTest = $this->isTestFile($file);

        foreach ($finder->findInstanceOf($ast, Node\Expr\FuncCall::class) as $call) {
            $name = $call->name instanceof Node\Name ? $call->name->toString() : null;
            if ($name === null) {
                continue;
            }

            if ($name === 'env' && !$isConfig) {
                $issues[] = new Issue(
                    self::RULE_ENV_OUTSIDE_CONFIG,
                    'env() should only be called from config files; use config() helper elsewhere.',
                    $file,
                    $call->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['function' => 'env'],
                    Confidence::Medium
                );
            }

            if (in_array(strtolower($name), self::DEBUG_FUNCTIONS, true) && !$isTest) {
                $issues[] = new Issue(
                    self::RULE_DEBUG,
                    sprintf('Debug call %s() left in code.', $name),
                    $file,
                    $call->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['function' => $name],
                    Confidence::Medium
                );
            }

            if ($name === 'sleep' && $isTest) {
                $issues[] = new Issue(
                    self::RULE_SLEEP_IN_TEST,
                    'sleep() should not be used in tests; prefer mocking time (e.g. Carbon::setTestNow).',
                    $file,
                    $call->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['function' => 'sleep'],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    private function isTestFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_contains($normalized, '/tests/') || str_starts_with($normalized, 'tests/');
    }
}
