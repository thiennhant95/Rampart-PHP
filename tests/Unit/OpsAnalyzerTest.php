<?php

declare(strict_types=1);

namespace Rampart\Php\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\Php\Analyzers\Frontend\JsSyntaxAnalyzer;
use Rampart\Php\Analyzers\Ops\ComposerManifestAnalyzer;
use Rampart\Php\Analyzers\Ops\EolAnalyzer;
use Rampart\Php\Analyzers\Ops\PermsAnalyzer;
use Rampart\Php\Scanning\ScanContext;

final class OpsAnalyzerTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-ops-' . uniqid('', true);
        @mkdir($this->tmp, 0777, true);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->tmp, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $item) {
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($this->tmp);
        }
    }

    /** @param array<string, string> $require */
    private function eolWith(array $require): EolAnalyzer
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', json_encode(['require' => $require]));
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    private function permsWith(string $root): PermsAnalyzer
    {
        $analyzer = new PermsAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($root);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    private function composer(): ComposerManifestAnalyzer
    {
        $analyzer = new ComposerManifestAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    public function testEolFiresOnLaravel11(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^11.0', 'php' => '^8.3'])->analyze([]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);
        self::assertContains('EOL_COMPONENT', $rules);
        self::assertCount(1, $issues);
    }

    public function testEolSilentOnLaravel12And13(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^12.0'])->analyze([]));
        self::assertSame([], $this->eolWith(['laravel/framework' => '^13.0'])->analyze([]));
    }

    public function testEolSilentWhenAnySupportedMajorAllowed(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^11.0|^12.0'])->analyze([]));
    }

    public function testEolFiresOnPhp81Pin(): void
    {
        $issues = $this->eolWith(['php' => '^8.1'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('EOL_COMPONENT', $issues[0]->rule);
    }

    public function testEolSilentOnPhp82AndOpenRange(): void
    {
        self::assertSame([], $this->eolWith(['php' => '^8.2'])->analyze([]));
        self::assertSame([], $this->eolWith(['php' => '>=8.1'])->analyze([]));
    }

    public function testEolSilentWithoutComposerJson(): void
    {
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testEolSilentOnInvalidJson(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', '{not json');
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testEolReportsLaravelBelowTrackedMapWithGenericMessage(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^8.0'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertStringContainsString('older than 9.x', $issues[0]->message);
        self::assertTrue($issues[0]->metadata['below_supported']);
    }

    public function testEolReportsPhpBelowTrackedMapWithGenericMessage(): void
    {
        $issues = $this->eolWith(['php' => '^7.4'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertStringContainsString('older than 8.0', $issues[0]->message);
        self::assertTrue($issues[0]->metadata['below_supported']);
    }

    public function testEolSilentOnOpenRangeThatAllowsSupportedLines(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '>=9.0'])->analyze([]));
    }

    public function testPermsClassifyWorldWriteIsCritical(): void
    {
        $result = PermsAnalyzer::classify(0777);
        self::assertNotNull($result);
        self::assertSame('other_write', $result['reason']);
        self::assertSame('world-writable', $result['scope']);
    }

    public function testPermsClassifyGroupWriteIsWarning(): void
    {
        $result = PermsAnalyzer::classify(0775);
        self::assertNotNull($result);
        self::assertSame('group_write', $result['reason']);
    }

    public function testPermsClassifySafeModesSilent(): void
    {
        self::assertNull(PermsAnalyzer::classify(0644));
        self::assertNull(PermsAnalyzer::classify(0755));
    }

    public function testComposerMissingFiresWhenVendorPresent(): void
    {
        @mkdir($this->tmp . DIRECTORY_SEPARATOR . 'vendor', 0777, true);
        $issues = $this->composer()->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('MISSING_COMPOSER', $issues[0]->rule);
    }

    public function testComposerMissingSilentOnPlainDirectory(): void
    {
        @mkdir($this->tmp . DIRECTORY_SEPARATOR . 'src', 0777, true);
        self::assertSame([], $this->composer()->analyze([]));
    }

    public function testComposerInvalidJsonIsError(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', '{not json');
        $issues = $this->composer()->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('INVALID_CONSTRAINT', $issues[0]->rule);
    }

    public function testComposerNonStringConstraintIsError(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', json_encode(['require' => ['php' => 8]]));
        $issues = $this->composer()->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('INVALID_CONSTRAINT', $issues[0]->rule);
    }

    public function testComposerValidManifestSilent(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', json_encode(['require' => ['php' => '^8.3']]));
        self::assertSame([], $this->composer()->analyze([]));
    }

    public function testPermsSilentWhenNoSensitivePaths(): void
    {
        self::assertSame([], $this->permsWith($this->tmp)->analyze([]));
    }

    public function testPermsSkipsTestbenchSkeleton(): void
    {
        $fake = $this->tmp . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'orchestra'
            . DIRECTORY_SEPARATOR . 'testbench-core' . DIRECTORY_SEPARATOR . 'laravel';
        @mkdir($fake, 0777, true);
        self::assertSame([], $this->permsWith($fake)->analyze([]));
    }

    public function testJsCollectorParityMinifiedExcluded(): void
    {
        // collectJsFiles() mirrors supports(): minified bundles never scan.
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/js/app.min.js'));
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/build/assets/app-abc123.min.js'));
        self::assertTrue((new JsSyntaxAnalyzer())->supports('resources/js/app.js'));
    }
}
