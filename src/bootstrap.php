<?php

declare(strict_types=1);

use Rampart\Php\Framework\Framework;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Severity;

// PHP 7.4 has no enums and no `new` in constant expressions, so the singleton
// values are created once here. Composer autoloads this file before any class
// that reads Severity::$Error / Confidence::$High / Framework::$PLAIN.
Severity::init();
Confidence::init();
Framework::init();
