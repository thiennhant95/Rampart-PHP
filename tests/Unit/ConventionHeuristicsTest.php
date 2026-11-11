<?php

declare(strict_types=1);

namespace Rampart\Php\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\Php\Analyzers\Convention\DeadCodeAnalyzer;
use Rampart\Php\Analyzers\Convention\NamingConventionAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\TestWithoutAssertAnalyzer;

/**
 * Regression tests for the false positives found while dogfooding the optional
 * convention/coverage rules on this repository.
 */
final class ConventionHeuristicsTest extends TestCase
{
    /**
     * @param array<string, string> $files
     * @return list<string>
     */
    private function rules(object $analyzer, array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rampart-conv-' . uniqid('', true);
        $paths = [];
        foreach ($files as $relative => $code) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $code);
            $paths[] = $path;
        }

        $rules = [];
        foreach ($analyzer->analyze($paths) as $issue) {
            $rules[] = $issue->rule;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);

        return $rules;
    }

    public function testIssueMethodIsNotMistakenForABooleanPredicate(): void
    {
        $rules = $this->rules(new NamingConventionAnalyzer(), [
            'src/Foo.php' => <<<'PHP'
<?php
class Foo
{
    public function issue(): string
    {
        return 'x';
    }

    public function isReady()
    {
        return true;
    }
}
PHP,
        ]);

        self::assertSame(1, count($rules));
        self::assertContains('NAMING_CONVENTION', $rules);
    }

    public function testStaticAssertionsCountAsAssertions(): void
    {
        $rules = $this->rules(new TestWithoutAssertAnalyzer(), [
            'tests/FooTest.php' => <<<'PHP'
<?php
class FooTest extends TestCase
{
    public function test_static_assert()
    {
        self::assertSame(1, 1);
    }
}
PHP,
        ]);

        self::assertSame([], $rules);
    }

    public function testTestWithoutAnyAssertionIsStillReported(): void
    {
        $rules = $this->rules(new TestWithoutAssertAnalyzer(), [
            'tests/FooTest.php' => <<<'PHP'
<?php
class FooTest extends TestCase
{
    public function test_none()
    {
        $value = 1;
    }
}
PHP,
        ]);

        self::assertContains('TEST_WITHOUT_ASSERT', $rules);
    }

    public function testProtectedHelpersAndAbstractClassesAreNotDeadCode(): void
    {
        $rules = $this->rules(new DeadCodeAnalyzer(), [
            'src/Foo.php' => <<<'PHP'
<?php
class Foo
{
    protected function helper()
    {
    }

    private function unusedPrivate()
    {
    }
}
PHP,
            'src/Base.php' => <<<'PHP'
<?php
abstract class Base
{
    private function unusedInAbstract()
    {
    }
}
PHP,
        ]);

        self::assertSame(['DEAD_CODE'], $rules);
    }
}
