<?php

declare(strict_types=1);

namespace Rampart\Php\Framework;

/**
 * Frameworks the standalone scanner knows how to lay out. Detection never
 * boots the framework: it reads composer.json and a handful of marker files.
 * `PLAIN` is the fallback and is a first-class target, not an error state.
 */
enum Framework: string
{
    case PLAIN = 'plain';
    case SLIM = 'slim';
    case CODEIGNITER4 = 'codeigniter4';
    case FUELPHP = 'fuelphp';
    case SYMFONY = 'symfony';
    case LARAVEL = 'laravel';

    public static function tryFromName(string $name): ?self
    {
        return self::tryFrom(strtolower(trim($name)));
    }
}
