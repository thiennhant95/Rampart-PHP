<?php

declare(strict_types=1);

namespace Rampart\Php\Checkers;

use Rampart\Php\Framework\Framework;
use Rampart\Php\Framework\FrameworkProfile;
use Rampart\Php\Result\CheckResult;
use Rampart\Php\Runner\CheckContext;

/**
 * Backwards-compatible name for the analyzer runner.
 *
 * The engine used to be Laravel-shaped and this class hardcoded `app/` +
 * `resources/views`. It is now a thin subclass of AnalyzerChecker that fills
 * in a plain-PHP profile when a caller (or an older test) did not detect one.
 * New code should use AnalyzerChecker directly.
 */
final class CustomAnalyzerChecker extends AnalyzerChecker
{
    public function run(CheckContext $ctx): CheckResult
    {
        if ($ctx->frameworkProfile === null) {
            $ctx->frameworkProfile = FrameworkProfile::for(Framework::PLAIN);
        }

        return parent::run($ctx);
    }
}
