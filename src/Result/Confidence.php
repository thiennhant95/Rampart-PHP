<?php

declare(strict_types=1);

namespace Rampart\Php\Result;

/**
 * Confidence value object (PHP 7.4 compatible replacement for the enum).
 *
 * Call sites use `Confidence::$High` etc.; `fromString()` and `tryFrom()`
 * preserve the enum API the rest of the engine expects.
 */
final class Confidence
{
    public static Confidence $Low;

    public static Confidence $Medium;

    public static Confidence $High;

    /** @var string */
    public string $value;

    private int $level;

    private function __construct(string $value, int $level)
    {
        $this->value = $value;
        $this->level = $level;
    }

    public static function init(): void
    {
        self::$Low = new self('low', 1);
        self::$Medium = new self('medium', 2);
        self::$High = new self('high', 3);
    }

    public function intValue(): int
    {
        return $this->level;
    }

    public static function fromString(string $value): self
    {
        return self::tryFrom($value) ?? self::$Low;
    }

    public static function tryFrom(string $value): ?self
    {
        switch (strtolower($value)) {
            case 'low':
                return self::$Low;
            case 'medium':
                return self::$Medium;
            case 'high':
                return self::$High;
        }

        return null;
    }
}
