<?php

declare(strict_types=1);

namespace Rampart\Php\Reporters;

use Rampart\Php\Result\CheckResult;
use Rampart\Php\Runner\CheckContext;

interface ReporterInterface
{
    /**
     * @param CheckResult[] $results
     */
    public function render(array $results, CheckContext $ctx): void;
}
