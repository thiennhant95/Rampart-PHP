<?php

/**
 * End-to-end check of the distributed artifact.
 *
 * Builds `composer archive` (tar), verifies the runtime subset is present and
 * the development tree is not, installs the archive into a throwaway
 * directory, then runs the installed `bin/rampart` against a deliberately
 * vulnerable fixture.
 *
 * Usage: composer smoke (or: php tools/smoke-install.php)
 */

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use Symfony\Component\Process\Process;

$root = dirname(__DIR__);
$workspace = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rampart-smoke-' . uniqid('', true);
$failures = [];
$checks = 0;

$say = static function (string $message) use (&$checks): void {
    ++$checks;
    echo '  ' . $message . PHP_EOL;
};

$fail = static function (string $message) use (&$failures): void {
    $failures[] = $message;
    echo '  FAIL  ' . $message . PHP_EOL;
};

/**
 * @param list<string> $command
 * @return array{int, string, string}
 */
$run = static function (array $command, string $cwd, int $timeout = 600): array {
    $process = new Process($command, $cwd);
    $process->setTimeout((float) $timeout);
    $process->run();

    return [
        $process->getExitCode() ?? -1,
        $process->getOutput(),
        $process->getErrorOutput(),
    ];
};

$cleanup = static function (string $directory): void {
    if (!is_dir($directory)) {
        return;
    }
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($directory);
};

$composer = null;
foreach (['composer', 'composer.bat', 'composer.phar'] as $candidate) {
    $path = trim((string) shell_exec(PHP_OS_FAMILY === 'Windows' ? 'where ' . $candidate . ' 2>NUL' : 'command -v ' . $candidate . ' 2>/dev/null'));
    if ($path !== '') {
        $composer = $candidate;
        break;
    }
}
if ($composer === null) {
    fwrite(STDERR, 'composer not found on PATH' . PHP_EOL);
    exit(2);
}

// `tar` ships with Linux/macOS and Windows 10+ (bsdtar). The archive is tar,
// not zip, so no ext-zip requirement is added to the package.
[$tarCode] = $run(['tar', '--version'], $root, 30);
if ($tarCode !== 0) {
    fwrite(STDERR, 'tar not found; cannot verify the archive' . PHP_EOL);
    exit(2);
}

mkdir($workspace, 0777, true);
$distDir = $workspace . DIRECTORY_SEPARATOR . 'dist';
mkdir($distDir, 0777, true);

try {
    echo '1. Building the distribution archive' . PHP_EOL;
    [$code, $stdout, $stderr] = $run(
        [$composer, 'archive', '--format=tar', '--dir=' . $distDir],
        $root
    );
    if ($code !== 0) {
        $fail('composer archive failed: ' . trim($stderr . $stdout));
    }

    $archives = glob($distDir . DIRECTORY_SEPARATOR . '*.tar') ?: [];
    if ($archives === []) {
        $fail('no archive was produced');
    } else {
        $archive = $archives[0];
        $say('archive: ' . basename($archive) . ' (' . round(filesize($archive) / 1024) . ' KB)');

        [$listCode, $listOut, $listErr] = $run(['tar', '-tf', $archive], $workspace);
        $names = array_values(array_filter(array_map(
            static fn (string $name): string => str_replace('\\', '/', trim($name)),
            preg_split('/\R/', $listOut) ?: []
        ), static fn (string $name): bool => $name !== ''));
        if ($listCode !== 0) {
            $fail('cannot list the archive: ' . trim($listErr));
        } else {
            foreach (['composer.json', 'bin/rampart', 'config/rampart.php', 'src/bootstrap.php', 'README.md'] as $required) {
                if (!in_array($required, $names, true)) {
                    $fail('archive is missing ' . $required);
                }
            }
            foreach (['tests/', 'tools/', '.github/', 'vendor/', 'phpunit.xml.dist'] as $forbidden) {
                foreach ($names as $name) {
                    if (strncmp($name, $forbidden, strlen($forbidden)) === 0) {
                        $fail('archive ships development path ' . $forbidden);
                        break;
                    }
                }
            }
            $say('archive contents checked (' . count($names) . ' entries)');

            $extract = $workspace . DIRECTORY_SEPARATOR . 'extract';
            mkdir($extract, 0777, true);
            [$extractCode, , $extractErr] = $run(['tar', '-xf', $archive, '-C', $extract], $workspace);
            if ($extractCode !== 0) {
                $fail('cannot extract the archive: ' . trim($extractErr));
            } else {
                echo '2. Installing the archive' . PHP_EOL;
                [$code, $stdout, $stderr] = $run(
                    [$composer, 'install', '--no-dev', '--no-interaction', '--no-progress', '--prefer-dist'],
                    $extract
                );
                if ($code !== 0) {
                    $fail('composer install in the archive failed: ' . trim(substr($stderr . $stdout, -400)));
                } elseif (!is_file($extract . '/vendor/autoload.php')) {
                    $fail('archive install produced no autoloader');
                } else {
                    $say('archive installed');

                    echo '3. Running the installed binary' . PHP_EOL;
                    $app = $workspace . DIRECTORY_SEPARATOR . 'app';
                    mkdir($app . '/src', 0777, true);
                    file_put_contents(
                        $app . '/src/view.php',
                        "<?php\necho \$_GET['name'];\nexec(\$_POST['cmd']);\n"
                    );
                    $out = $workspace . DIRECTORY_SEPARATOR . 'out';
                    [$code, $stdout, $stderr] = $run(
                        [
                            PHP_BINARY,
                            $extract . '/bin/rampart',
                            $app,
                            '--only=custom',
                            '--format=json',
                            '--fail-on=none',
                            '--no-cache',
                            '--output=' . $out,
                        ],
                        $extract
                    );
                    $report = $out . DIRECTORY_SEPARATOR . 'rampart-report.json';
                    if ($code !== 0) {
                        $fail('installed binary exited ' . $code . ': ' . trim($stderr));
                    } elseif (!is_file($report)) {
                        $fail('installed binary wrote no JSON report');
                    } else {
                        $payload = json_decode((string) file_get_contents($report), true);
                        $total = is_array($payload) ? (int) ($payload['summary']['total_issues'] ?? 0) : 0;
                        if ($total < 2) {
                            $fail('installed binary found ' . $total . ' issue(s); expected at least 2');
                        } else {
                            $say('installed binary found ' . $total . ' issue(s)');
                        }
                    }
                }
            }
        }
    }
} finally {
    $cleanup($workspace);
}

echo PHP_EOL;
if ($failures !== []) {
    echo 'SMOKE FAILED (' . count($failures) . ' failure(s), ' . $checks . ' check(s))' . PHP_EOL;
    exit(1);
}

echo 'SMOKE OK (' . $checks . ' check(s))' . PHP_EOL;
exit(0);
