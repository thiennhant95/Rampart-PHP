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
            $path = $file->getPathname();
            // An unexpected PHP file under public/ is always a finding, but
            // only content matching the OBFUSCATED_PHP/UNSAFE_EVAL evidence is
            // a probable webshell. A merely misplaced file stays a Warning so
            // the convention violation is not lost.
            $payload = PhpPayloadPatterns::dangerous($this->sharedSource($path));
            $metadata = [
                'file' => $name,
                'reason' => 'unexpected_php_in_public',
                'classification' => $payload !== null ? 'dangerous' : 'benign',
            ];
            if ($payload !== null) {
                $metadata['matched_pattern'] = $payload['label'];
            }
            $issues[] = new Issue(
                self::RULE,
                sprintf('Rogue PHP file in public/: %s — only index.php should be there.', $path),
                $path,
                1,
                $payload !== null ? Severity::$Critical : Severity::$Warning,
                'custom',
                $metadata,
                $payload !== null ? Confidence::$High : Confidence::$Medium
            );
        }

        return $issues;
    }
}
