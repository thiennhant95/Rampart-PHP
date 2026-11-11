<?php

declare(strict_types=1);

namespace Rampart\Php\Checkers;

use Rampart\Php\Result\CheckResult;
use Rampart\Php\Runner\CheckContext;

interface CheckerInterface
{
    public function name(): string;

    public function description(): string;

    public function isAvailable(CheckContext $ctx): bool;

    public function run(CheckContext $ctx): CheckResult;

    public function config(): array;
}
