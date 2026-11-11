<?php

declare(strict_types=1);

namespace Rampart\Php\Framework;

/**
 * Layout facts for one framework. Analyzers consume this instead of hardcoding
 * Laravel's directory names, which is what made the original engine unusable
 * on plain PHP projects.
 *
 * `scanPaths` drives the file collector. `routeFiles` and `viewDirs` are
 * relative to the project root and are collected separately so only
 * route-aware / template-aware analyzers consume them.
 */
final class FrameworkProfile
{
    /**
     * @readonly
     */
    public Framework $framework;
    /**
     * @readonly
     */
    public string $label;
    /**
     * @var list<string>
     * @readonly
     */
    public array $scanPaths;
    /**
     * @var list<string>
     * @readonly
     */
    public array $routeFiles = [];
    /**
     * @var list<string>
     * @readonly
     */
    public array $routeGlobs = [];
    /**
     * @var list<string>
     * @readonly
     */
    public array $viewDirs = [];
    /**
     * @var list<string>
     * @readonly
     */
    public array $testDirs = ['tests'];
    /**
     * @var list<string>
     * @readonly
     */
    public array $publicDirs = ['public'];
    /**
     * @param list<string> $scanPaths
     * @param list<string> $routeFiles
     * @param list<string> $routeGlobs
     * @param list<string> $viewDirs
     * @param list<string> $testDirs
     * @param list<string> $publicDirs
     */
    public function __construct(Framework $framework, string $label, array $scanPaths, array $routeFiles = [], array $routeGlobs = [], array $viewDirs = [], array $testDirs = ['tests'], array $publicDirs = ['public'])
    {
        $this->framework = $framework;
        $this->label = $label;
        $this->scanPaths = $scanPaths;
        $this->routeFiles = $routeFiles;
        $this->routeGlobs = $routeGlobs;
        $this->viewDirs = $viewDirs;
        $this->testDirs = $testDirs;
        $this->publicDirs = $publicDirs;
    }
    public static function for(Framework $framework): self
    {
        switch ($framework) {
            case Framework::$PLAIN:
                return new self($framework, 'Plain PHP', ['src', 'app', 'lib', 'includes', 'inc', 'public', 'tests'], [], [], ['templates', 'views', 'public/views', 'resources/views'], ['tests', 'test'], ['public', 'public_html', 'web', 'htdocs']);
            case Framework::$SLIM:
                return new self($framework, 'Slim', ['src', 'app', 'routes', 'config', 'tests'], ['routes/routes.php', 'routes/web.php', 'routes/api.php', 'public/index.php'], ['routes/*.php', 'config/routes*.php'], ['templates', 'views', 'resources/views'], ['tests'], ['public']);
            case Framework::$CODEIGNITER4:
                return new self($framework, 'CodeIgniter 4', ['app', 'tests'], ['app/Config/Routes.php'], ['app/Config/Routes/*.php', 'app/Config/*Routes*.php'], ['app/Views'], ['tests'], ['public']);
            case Framework::$FUELPHP:
                return new self($framework, 'FuelPHP', ['fuel/app', 'fuel/core'], ['fuel/app/config/routes.php'], ['fuel/app/config/*routes*.php'], ['fuel/app/views'], ['fuel/app/tests', 'tests'], ['public']);
            case Framework::$SYMFONY:
                return new self($framework, 'Symfony', ['src', 'config', 'templates', 'tests'], ['config/routes.php', 'config/routes.yaml', 'config/routes.yml'], ['config/routes/*.yaml', 'config/routes/*.yml', 'config/routes/*.php'], ['templates', 'views'], ['tests'], ['public']);
            case Framework::$LARAVEL:
                return new self($framework, 'Laravel', ['app', 'routes', 'database', 'config', 'tests'], ['routes/web.php', 'routes/api.php', 'routes/console.php'], ['routes/*.php'], ['resources/views'], ['tests'], ['public']);
            case Framework::$PHALCON:
                return new self($framework, 'Phalcon', ['app', 'src', 'config', 'tests'], ['app/config/routes.php', 'app/config/router.php', 'config/routes.php', 'public/index.php'], ['app/config/*routes*.php', 'app/config/*router*.php', 'config/*routes*.php'], ['app/views', 'views'], ['tests'], ['public']);
            default:
                return self::for(Framework::$PLAIN);
        }
    }

    /**
     * Existing scan paths under the project root, in profile order.
     *
     * @return list<string>
     */
    public function existingScanPaths(string $basePath): array
    {
        return array_values(array_filter(
            $this->scanPaths,
            static fn (string $path): bool => is_dir($basePath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $path))
        ));
    }

    /**
     * Existing route files, expanded from explicit files and globs.
     *
     * @return list<string> absolute paths
     */
    public function existingRouteFiles(string $basePath): array
    {
        $found = [];
        foreach ($this->routeFiles as $relative) {
            $absolute = $basePath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            if (is_file($absolute)) {
                $found[] = $absolute;
            }
        }
        foreach ($this->routeGlobs as $glob) {
            $pattern = $basePath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $glob);
            foreach (glob($pattern) ?: [] as $absolute) {
                if (is_file($absolute)) {
                    $found[] = $absolute;
                }
            }
        }

        return array_values(array_unique($found));
    }

    /**
     * Existing view directories.
     *
     * @return list<string> absolute paths
     */
    public function existingViewDirs(string $basePath): array
    {
        $found = [];
        foreach ($this->viewDirs as $relative) {
            $absolute = $basePath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            if (is_dir($absolute)) {
                $found[] = $absolute;
            }
        }

        return array_values(array_unique($found));
    }

    /**
     * Existing test directories.
     *
     * @return list<string> absolute paths
     */
    public function existingTestDirs(string $basePath): array
    {
        $found = [];
        foreach ($this->testDirs as $relative) {
            $absolute = $basePath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            if (is_dir($absolute)) {
                $found[] = $absolute;
            }
        }

        return array_values(array_unique($found));
    }

    /**
     * Whether a path is inside one of the test directories.
     */
    public function isTestPath(string $path, string $basePath): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $path));
        $base = strtolower(str_replace('\\', '/', rtrim($basePath, '/\\')));
        foreach ($this->testDirs as $relative) {
            $needle = $base . '/' . strtolower(trim(str_replace('\\', '/', $relative), '/')) . '/';
            if (strncmp($normalized, $needle, strlen($needle)) === 0) {
                return true;
            }
        }

        return false;
    }
}
