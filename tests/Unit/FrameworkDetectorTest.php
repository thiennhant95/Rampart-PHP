<?php

declare(strict_types=1);

namespace Rampart\Php\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\Php\Framework\Framework;
use Rampart\Php\Framework\FrameworkDetector;

final class FrameworkDetectorTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rampart-fw-' . uniqid('', true);
        @mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($this->dir);
    }

    /**
     * @param array<string, string> $require
     */
    private function composer(array $require): void
    {
        file_put_contents(
            $this->dir . DIRECTORY_SEPARATOR . 'composer.json',
            json_encode(['require' => $require], JSON_PRETTY_PRINT)
        );
    }

    public function testPlainPhpIsTheFallback(): void
    {
        $profile = (new FrameworkDetector())->detect($this->dir);

        self::assertSame(Framework::PLAIN, $profile->framework);
        self::assertContains('src', $profile->scanPaths);
    }

    public function testSlimFromComposer(): void
    {
        $this->composer(['slim/slim' => '^4.0']);

        self::assertSame(Framework::SLIM, (new FrameworkDetector())->detect($this->dir)->framework);
    }

    public function testCodeIgniterFromMarkers(): void
    {
        touch($this->dir . DIRECTORY_SEPARATOR . 'spark');
        @mkdir($this->dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Config', 0777, true);

        self::assertSame(Framework::CODEIGNITER4, (new FrameworkDetector())->detect($this->dir)->framework);
    }

    public function testFuelPhpFromDirectory(): void
    {
        @mkdir($this->dir . DIRECTORY_SEPARATOR . 'fuel' . DIRECTORY_SEPARATOR . 'app', 0777, true);

        self::assertSame(Framework::FUELPHP, (new FrameworkDetector())->detect($this->dir)->framework);
    }

    public function testSymfonyFromMarkers(): void
    {
        @mkdir($this->dir . DIRECTORY_SEPARATOR . 'config', 0777, true);
        file_put_contents($this->dir . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'bundles.php', '<?php return [];');

        self::assertSame(Framework::SYMFONY, (new FrameworkDetector())->detect($this->dir)->framework);
    }

    public function testLaravelFromComposer(): void
    {
        $this->composer(['laravel/framework' => '^11.0']);

        self::assertSame(Framework::LARAVEL, (new FrameworkDetector())->detect($this->dir)->framework);
    }

    public function testOverrideWins(): void
    {
        $this->composer(['laravel/framework' => '^11.0']);

        self::assertSame(Framework::PLAIN, (new FrameworkDetector())->detect($this->dir, 'plain')->framework);
    }
}
