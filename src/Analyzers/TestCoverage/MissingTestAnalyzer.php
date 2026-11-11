<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\TestCoverage;

use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\RuleIds;
use Rampart\Php\Result\Severity;

final class MissingTestAnalyzer extends AbstractAnalyzer
{
    private const RULE_MODEL = RuleIds::MISSING_MODEL_TEST;
    private const RULE_SERVICE = RuleIds::MISSING_SERVICE_TEST;
    /**
     * @var list<string>
     */
    private array $scopes = ['services', 'models'];

    /**
     * @param list<string> $scopes e.g. ['services', 'repositories'] or ['models']
     */
    public function __construct(array $scopes = ['services', 'models'])
    {
        $this->scopes = $scopes;
    }

    public function analyze(array $files): array
    {
        $testNames = $this->collectTestNames($files);
        $issues = [];

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }

            $scope = $this->scopeOf($file);
            if ($scope === null) {
                continue;
            }

            $classBase = $this->classBaseName($file);
            if ($classBase === null) {
                continue;
            }

            $rule = $this->ruleFor($scope);
            $testClassBase = $classBase . 'Test';

            if (isset($testNames[$testClassBase])) {
                continue;
            }

            if ($scope === 'models' && !$this->modelHasCustomLogic($file)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                $rule,
                sprintf(
                    'No directly associated test detected for %s (%s). Expected a test named %s.php.',
                    $classBase,
                    $scope,
                    $testClassBase
                ),
                $file,
                1,
                Severity::$Info,
                ['class' => $classBase, 'scope' => $scope, 'expected_test' => $testClassBase],
                Confidence::$Low
            );
        }

        return $issues;
    }

    private function scopeOf(string $file): ?string
    {
        $normalized = str_replace('\\', '/', $file);

        foreach ($this->scopes as $scope) {
            $needle = '/app/' . ucfirst($scope) . '/';
            if (strpos($normalized, $needle) !== false) {
                return strtolower($scope);
            }
        }

        return null;
    }

    private function ruleFor(string $scope): string
    {
        switch ($scope) {
            case 'models':
                return self::RULE_MODEL;
            case 'repositories':
                return self::RULE_SERVICE;
            default:
                return self::RULE_SERVICE;
        }
    }

    private function classBaseName(string $file): ?string
    {
        $basename = pathinfo($file, PATHINFO_FILENAME);
        if ($basename === '' || $basename === '.') {
            return null;
        }

        $basename = preg_replace('/Controller$/', '', $basename) ?? $basename;
        $basename = preg_replace('/Service$/', '', $basename) ?? $basename;
        $basename = preg_replace('/Repository$/', '', $basename) ?? $basename;

        return $basename;
    }

    private function modelHasCustomLogic(string $file): bool
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return false;
        }

        $methods = $this->finder()->findInstanceOf($ast, \PhpParser\Node\Stmt\ClassMethod::class);

        return count($methods) >= 3;
    }

    /**
     * @param list<string> $files
     * @return array<string, true>
     */
    private function collectTestNames(array $files): array
    {
        $names = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $normalized = str_replace('\\', '/', $file);
            if (strpos($normalized, '/tests/') === false && strncmp($normalized, 'tests/', strlen('tests/')) !== 0) {
                continue;
            }

            $names[pathinfo($file, PATHINFO_FILENAME)] = true;
        }

        return $names;
    }
}
