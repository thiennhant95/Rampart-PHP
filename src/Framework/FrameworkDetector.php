<?php

declare(strict_types=1);

namespace Rampart\Php\Framework;

/**
 * Detects the framework without executing any of its code.
 *
 * Order: explicit override → composer.json packages → marker files → plain PHP.
 * A wrong guess only costs precision on framework-specific rules; generic
 * security analyzers are layout-independent.
 */
final class FrameworkDetector
{
    /** @var array<string, list<string>> package => frameworks */
    private const PACKAGES = [
        'slim/slim' => ['slim'],
        'slim/psr7' => ['slim'],
        'codeigniter4/framework' => ['codeigniter4'],
        'codeigniter4/appstarter' => ['codeigniter4'],
        'fuel/fuel' => ['fuelphp'],
        'fuelphp/fuel' => ['fuelphp'],
        'symfony/framework-bundle' => ['symfony'],
        'symfony/symfony' => ['symfony'],
        'laravel/framework' => ['laravel'],
    ];

    public function detect(string $basePath, ?string $override = null): FrameworkProfile
    {
        if ($override !== null && $override !== '') {
            $framework = Framework::tryFromName($override);
            if ($framework !== null) {
                return FrameworkProfile::for($framework);
            }
        }

        $detected = $this->fromComposer($basePath) ?? $this->fromMarkers($basePath);

        return FrameworkProfile::for($detected ?? Framework::PLAIN);
    }

    private function fromComposer(string $basePath): ?Framework
    {
        $file = rtrim($basePath, '/\\') . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($file)) {
            return null;
        }
        $raw = file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        $packages = [];
        foreach (['require', 'require-dev'] as $section) {
            $list = $decoded[$section] ?? [];
            if (is_array($list)) {
                foreach (array_keys($list) as $package) {
                    $packages[strtolower((string) $package)] = true;
                }
            }
        }

        foreach (self::PACKAGES as $package => $frameworks) {
            if (isset($packages[$package])) {
                return Framework::tryFromName($frameworks[0]);
            }
        }

        return null;
    }

    private function fromMarkers(string $basePath): ?Framework
    {
        $base = rtrim($basePath, '/\\');

        if (is_file($base . '/spark') && is_dir($base . '/app/Config')) {
            return Framework::CODEIGNITER4;
        }
        if (is_dir($base . '/fuel/app')) {
            return Framework::FUELPHP;
        }
        if (is_file($base . '/config/bundles.php') || is_file($base . '/src/Kernel.php')) {
            return Framework::SYMFONY;
        }
        if (is_dir($base . '/routes') && is_dir($base . '/app/Http')) {
            return Framework::LARAVEL;
        }
        if (is_file($base . '/public/index.php') && is_dir($base . '/src')) {
            // Local file under the operator-supplied target root, never request data.
            // rampart-ignore-next-line OWASP_PATH_TRAVERSAL,OWASP_SSRF
            $index = (string) file_get_contents($base . '/public/index.php');
            if (stripos($index, 'Slim') !== false) {
                return Framework::SLIM;
            }
        }

        return null;
    }
}
