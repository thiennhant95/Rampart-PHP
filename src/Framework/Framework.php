<?php

declare(strict_types=1);

namespace Rampart\Php\Framework;

/**
 * Framework value object (PHP 7.4 compatible replacement for the enum).
 *
 * Detection never boots the framework: it reads composer.json and a handful of
 * marker files. `PLAIN` is the fallback and is a first-class target.
 */
final class Framework
{
    public static Framework $PLAIN;

    public static Framework $SLIM;

    public static Framework $CODEIGNITER4;

    public static Framework $FUELPHP;

    public static Framework $SYMFONY;

    public static Framework $LARAVEL;

    public static Framework $PHALCON;

    /** @var string */
    public string $value;

    private function __construct(string $value)
    {
        $this->value = $value;
    }

    public static function init(): void
    {
        self::$PLAIN = new self('plain');
        self::$SLIM = new self('slim');
        self::$CODEIGNITER4 = new self('codeigniter4');
        self::$FUELPHP = new self('fuelphp');
        self::$SYMFONY = new self('symfony');
        self::$LARAVEL = new self('laravel');
        self::$PHALCON = new self('phalcon');
    }

    public static function tryFrom(string $value): ?self
    {
        switch (strtolower(trim($value))) {
            case 'plain':
                return self::$PLAIN;
            case 'slim':
                return self::$SLIM;
            case 'codeigniter4':
                return self::$CODEIGNITER4;
            case 'fuelphp':
                return self::$FUELPHP;
            case 'symfony':
                return self::$SYMFONY;
            case 'laravel':
                return self::$LARAVEL;
            case 'phalcon':
                return self::$PHALCON;
        }

        return null;
    }

    public static function tryFromName(string $name): ?self
    {
        return self::tryFrom($name);
    }
}
