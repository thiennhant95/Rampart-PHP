<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\TestCoverage;

use PhpParser\Node;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\RuleIds;
use Rampart\Php\Result\Severity;

/**
 * Detect source classes that have no corresponding test.
 *
 * Classifies source files by kind (controller, service, repository, model) and
 * checks whether a matching test exists in the scanned `$files` set — in either
 * `tests/Unit` or `tests/Feature`, and under either the exact mirrored namespace
 * or a flat `*Test.php` convention. Uses the passed `$files` (not the working
 * directory), so it works regardless of the project layout.
 *
 * Heuristic — confidence is low; the check is intentionally conservative to
 * avoid flagging framework/base classes (abstract, enums, interfaces, traits).
 */
final class TestCoverageAnalyzer extends AbstractAnalyzer
{
    private const RULE_CONTROLLER = RuleIds::MISSING_CONTROLLER_TEST;
    private const RULE_SERVICE = RuleIds::MISSING_SERVICE_TEST;
    private const RULE_REPOSITORY = RuleIds::MISSING_REPOSITORY_TEST;
    private const RULE_MODEL = RuleIds::MISSING_MODEL_TEST;
    private const RULE_OTHER = RuleIds::MISSING_UNIT_TEST;

    private const RULES = [
        'controller' => self::RULE_CONTROLLER,
        'service' => self::RULE_SERVICE,
        'repository' => self::RULE_REPOSITORY,
        'model' => self::RULE_MODEL,
        'other' => self::RULE_OTHER,
    ];

    /**
     * @param list<string> $files
     * @return Issue[]
     */
    public function analyze(array $files): array
    {
        $tests = $this->indexTests($files);
        $issues = [];

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isTestFile($file)) {
                continue;
            }

            foreach ($this->analyzeFile($file, $tests) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @param array<string, array{namespace: string, class: string}> $tests
     * @return Issue[]
     */
    private function analyzeFile(string $file, array $tests): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);

        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                continue;
            }

            [$namespace, $className] = $this->classIdentity($ast, $class);

            $kind = $this->classKind($className);
            if ($kind === null) {
                // Class name doesn't match a known pattern; check if it extends
                // Eloquent\Model (a model) or has a namespace hinting a model.
                $kind = $this->classKindFromExtends($class) ?? $this->classKindFromNamespace($namespace);
            }
            if ($kind === null) {
                continue; // not a class type we track (helper/enum/interface/etc.)
            }

            if ($this->hasTest($namespace, $className, $tests)) {
                continue;
            }

            // Models with no custom logic are rarely unit-tested; skip them to
            // reduce noise unless they carry >= 3 methods.
            if ($kind === 'model' && !$this->classHasLogic($class)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULES[$kind],
                sprintf(
                    'No %s test found for %s\\%s.',
                    $kind,
                    $namespace,
                    $className
                ),
                $file,
                $class->getStartLine(),
                Severity::$Warning,
                ['class' => $className, 'namespace' => $namespace, 'kind' => $kind],
                Confidence::$Low
            );
        }

        return $issues;
    }

    private function classKind(string $name): ?string
    {
        if (substr_compare($name, 'Controller', -strlen('Controller')) === 0) {
            return 'controller';
        }
        if (substr_compare($name, 'Service', -strlen('Service')) === 0) {
            return 'service';
        }
        if (substr_compare($name, 'Repository', -strlen('Repository')) === 0) {
            return 'repository';
        }

        return null;
    }

    private function classKindFromExtends(Node\Stmt\Class_ $class): ?string
    {
        $extends = $class->extends;
        if ($extends !== null && $extends instanceof Node\Name) {
            $name = $extends->toString();
            if (substr_compare($name, 'Model', -strlen('Model')) === 0) {
                return 'model';
            }
        }

        return null;
    }

    private function classKindFromNamespace(string $namespace): ?string
    {
        if (strpos($namespace, '\\Models\\') !== false || substr_compare($namespace, '\\Models', -strlen('\\Models')) === 0) {
            return 'model';
        }

        return null;
    }

    private function classHasLogic(Node\Stmt\Class_ $class): bool
    {
        $methods = array_filter($class->getMethods(), static fn (Node\Stmt\ClassMethod $m): bool => !$m->isMagic());

        return count($methods) >= 3;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function classIdentity(array $ast, Node\Stmt\Class_ $class): array
    {
        $namespace = '';
        $namespaces = $this->finder()->findInstanceOf($ast, Node\Stmt\Namespace_::class);
        foreach ($namespaces as $ns) {
            if ($ns instanceof Node\Stmt\Namespace_ && $ns->name !== null) {
                $namespace = $ns->name->toString();
                break;
            }
        }

        return [$namespace, $class->name->toString()];
    }

    /**
     * Index all test files by both their namespace\class and plain basename.
     *
     * @param list<string> $files
     * @return array<string, array{namespace: string, class: string, file: string}>
     */
    private function indexTests(array $files): array
    {
        $tests = [];
        foreach ($files as $file) {
            if (!$this->supports($file) || !$this->isTestFile($file)) {
                continue;
            }

            $ast = $this->sharedAst($file);
            if ($ast === null) {
                continue;
            }

            $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);
            foreach ($classes as $class) {
                if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                    continue;
                }
                [$namespace, $className] = $this->classIdentity($ast, $class);

                $key = ltrim($namespace . '\\' . $className, '\\');
                $tests[$key] = ['namespace' => $namespace, 'class' => $className, 'file' => $file];

                // Also index by plain class name for flat test layouts.
                $tests[$className] = ['namespace' => $namespace, 'class' => $className, 'file' => $file];
            }
        }

        return $tests;
    }

    /**
     * @param array<string, array{namespace: string, class: string}> $tests
     */
    private function hasTest(string $namespace, string $className, array $tests): bool
    {
        $testClass = $className . 'Test';

        // Same namespace, class + Test suffix.
        $fq = ltrim($namespace . '\\' . $testClass, '\\');
        if (isset($tests[$fq])) {
            return true;
        }

        // Flat layout: plain basename.
        if (isset($tests[$testClass])) {
            return true;
        }

        // Common alternative: same base name without suffix (e.g. UserTest for model User).
        if (isset($tests[$className])) {
            // Only consider it a hit if that test class maps to a Test-suffixed name elsewhere.
            $candidate = $tests[$className];
            if (substr_compare($candidate['class'], 'Test', -strlen('Test')) === 0 || substr_compare($candidate['class'], 'TestCase', -strlen('TestCase')) === 0) {
                return true;
            }
        }

        return false;
    }

    private function isTestFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return strpos($normalized, '/tests/') !== false || strncmp($normalized, 'tests/', strlen('tests/')) === 0;
    }
}
