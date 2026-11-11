<?php

declare(strict_types=1);

namespace Rampart\Php\Result;

/**
 * Severity value object.
 *
 * PHP 8.1 enums are not parseable on PHP 7.4, so this is the same concept as a
 * final class with singleton values and a string `value` property. Call sites
 * use `Severity::$Error` (object identity) exactly where they used
 * `Severity::$Error` before.
 */
final class Severity
{
    public static Severity $Info;

    public static Severity $Warning;

    public static Severity $Error;

    public static Severity $Critical;

    /** @var string */
    public string $value;

    private int $rank;

    private function __construct(string $value, int $rank)
    {
        $this->value = $value;
        $this->rank = $rank;
    }

    public static function init(): void
    {
        self::$Info = new self('info', 1);
        self::$Warning = new self('warning', 2);
        self::$Error = new self('error', 3);
        self::$Critical = new self('critical', 4);
    }

    public function intValue(): int
    {
        return $this->rank;
    }

    public static function fromString(string $value): self
    {
        return self::tryFrom($value) ?? self::$Error;
    }

    public static function tryFrom(string $value): ?self
    {
        switch (strtolower($value)) {
            case 'info':
                return self::$Info;
            case 'warning':
                return self::$Warning;
            case 'error':
                return self::$Error;
            case 'critical':
                return self::$Critical;
        }

        return null;
    }
}
