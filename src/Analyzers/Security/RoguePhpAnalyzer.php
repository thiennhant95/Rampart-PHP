<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;
use Rampart\Php\Scanning\ScanContextAware;
use Rampart\Php\Scanning\ScanContextTrait;

final class RoguePhpAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'ROGUE_PHP';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $public = $root . DIRECTORY_SEPARATOR . 'public';
        if (!is_dir($public)) {
            return [];
        }
        $issues = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($public, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }
            $name = $file->getFilename();
            if ($name === 'index.php') {
                continue;
            }
            $issues[] = new Issue(
                self::RULE,
                sprintf('Rogue PHP file in public/: %s — only index.php should be there.', $file->getPathname()),
                $file->getPathname(),
                1,
                Severity::$Critical,
                'custom',
                ['file' => $file->getFilename()],
                Confidence::$High
            );
        }

        return $issues;
    }
}
