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

final class NamingConventionAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'NAMING_CONVENTION';

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

        foreach ($finder->findInstanceOf($ast, Node\Stmt\Class_::class) as $class) {
            $className = $class->name ? $class->name->toString() : null;
            if ($className === null) {
                continue;
            }

            if (strpos($normalized, '/Controllers/') !== false && substr_compare($className, 'Controller', -strlen('Controller')) !== 0) {
                $issues[] = $this->issue($file, $class, sprintf('Controller class "%s" must end with "Controller".', $className));
            }
            if (strpos($normalized, '/Services/') !== false && substr_compare($className, 'Service', -strlen('Service')) !== 0) {
                $issues[] = $this->issue($file, $class, sprintf('Service class "%s" must end with "Service".', $className));
            }
            if (strpos($normalized, '/Repositories/') !== false && substr_compare($className, 'Repository', -strlen('Repository')) !== 0) {
                $issues[] = $this->issue($file, $class, sprintf('Repository class "%s" must end with "Repository".', $className));
            }

            if ($this->psr4Mismatch($file, $className, $normalized)) {
                $issues[] = $this->issue($file, $class, sprintf('Class "%s" does not match its PSR-4 file location.', $className));
            }

            foreach ($class->getMethods() as $method) {
                if ($method->isMagic()) {
                    continue;
                }
                $methodName = $method->name instanceof Node\Identifier ? $method->name->toString() : '';
                $methodName = lcfirst($methodName);

                // `issue()` starts with "is" but is not a predicate; require a
                // camelCase segment after the prefix (`isFoo`, `hasBar`).
                if (
                    preg_match('/^(is|has|can|should)[A-Z]/', $methodName, $prefixMatch) === 1
                    && !$this->declaredReturnBool($method)
                ) {
                    $issues[] = $this->issue(
                        $file,
                        $method,
                        sprintf(
                            'Method "%s()" starts with "%s" and should declare a bool return type.',
                            $methodName,
                            $prefixMatch[1]
                        )
                    );
                }
            }
        }

        return $issues;
    }

    private function declaredReturnBool(Node\Stmt\ClassMethod $method): bool
    {
        $type = $method->returnType;
        if ($type instanceof Node\Identifier && strtolower($type->toString()) === 'bool') {
            return true;
        }
        if ($type instanceof Node\NullableType && $type->type instanceof Node\Identifier && strtolower($type->type->toString()) === 'bool') {
            return true;
        }

        return false;
    }

    private function psr4Mismatch(string $file, string $className, string $normalized): bool
    {
        $expected = str_replace('\\', '/', $className) . '.php';
        $relative = $this->relativePath($normalized);

        if ($relative === null) {
            return false;
        }

        $lastSegment = strtolower($relative);
        $expectedLast = strtolower(substr($expected, strrpos($expected, '/') + 1));

        return $lastSegment === $expectedLast;
    }

    private function relativePath(string $normalized): ?string
    {
        $root = $this->appRoot();
        if ($root === null) {
            return null;
        }

        $rootNormalized = str_replace('\\', '/', rtrim($root, '/')) . '/';
        if (strncmp($normalized, $rootNormalized, strlen($rootNormalized)) !== 0) {
            return null;
        }

        return substr($normalized, strlen($rootNormalized));
    }

    private function issue(string $file, Node $node, string $message): Issue
    {
        return new Issue(
            self::RULE,
            $message,
            $file,
            $node->getStartLine(),
            Severity::$Info,
            'custom',
            [],
            Confidence::$Low
        );
    }

    private function appRoot(): ?string
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return null;
        }

        return is_dir($root . '/app') ? $root : null;
    }
}
