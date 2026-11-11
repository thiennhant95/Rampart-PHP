<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * Dangerous language constructs that are almost always a design smell:
 *
 * - `extract()` — turns arbitrary array keys into local variables.
 * - `parse_str($str)` — same, into the current/global scope.
 * - `create_function()` — removed in PHP 8; string body is eval.
 * - `preg_replace()` with the `/e` modifier — evaluates the replacement.
 *
 * Severity is Error but confidence Medium: each call is confirmed, but whether
 * the data is attacker-controlled needs a human.
 */
final class DangerousFunctionAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'DANGEROUS_FUNCTION';

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file) || $this->isTestPath($file)) {
                continue;
            }
            $ast = $this->sharedAst($file);
            if ($ast === null) {
                continue;
            }
            foreach ($this->finder()->findInstanceOf($ast, Expr\FuncCall::class) as $call) {
                if (!$call instanceof Expr\FuncCall || !$call->name instanceof Node\Name) {
                    continue;
                }
                $name = strtolower($call->name->getLast());
                switch ($name) {
                    case 'extract':
                        $reason = 'extract() imports arbitrary array keys into local scope; prefer explicit assignments.';
                        break;
                    case 'parse_str':
                        $reason = count($call->args) === 1
                            ? 'parse_str() without a result array writes into the current scope; pass a second argument.'
                            : null;
                        break;
                    case 'create_function':
                        $reason = 'create_function() builds code from a string (removed in PHP 8); use a closure.';
                        break;
                    case 'preg_replace':
                    case 'mb_ereg_replace':
                        $reason = $this->hasEvalModifier($call->args[0] ?? null)
                            ? 'preg_replace() with the /e modifier evaluates the replacement as PHP; use preg_replace_callback().'
                            : null;
                        break;
                    default:
                        $reason = null;
                        break;
                }
                if ($reason === null) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    $reason,
                    $file,
                    $call->getStartLine(),
                    Severity::$Error,
                    ['function' => $name],
                    Confidence::$Medium
                );
            }
        }

        return $issues;
    }

    private function hasEvalModifier(?Node $arg): bool
    {
        if (!$arg instanceof Node\Arg || !$arg->value instanceof Node\Scalar\String_) {
            return false;
        }
        $pattern = $arg->value->value;
        if ($pattern === '') {
            return false;
        }
        $delimiter = $pattern[0];
        $last = strrpos($pattern, $delimiter);
        if ($last === false || $last === 0) {
            return false;
        }
        $modifiers = substr($pattern, $last + 1);

        return strpos($modifiers, 'e') !== false;
    }
}
