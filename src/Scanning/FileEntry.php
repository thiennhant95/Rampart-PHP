<?php

declare(strict_types=1);

namespace Rampart\Php\Scanning;

/**
 * One cached file: source text plus parse outcome. States:
 * NOT_LOADED → LOADED (source read, not parsed) → PARSED, or
 * PARSE_FAILED (cached — a malformed file must not be re-parsed
 * once per analyzer).
 */
final class FileEntry
{
    public const NOT_LOADED = 'not-loaded';

    public const LOADED = 'loaded';

    public const PARSED = 'parsed';

    public const PARSE_FAILED = 'parse-failed';

    /** @var list<\PhpParser\Node>|null */
    public ?array $ast = null;
    /**
     * @readonly
     */
    public string $path;
    public string $source = '';
    public string $state = self::NOT_LOADED;
    public function __construct(string $path, string $source = '', string $state = self::NOT_LOADED)
    {
        $this->path = $path;
        $this->source = $source;
        $this->state = $state;
    }
}
