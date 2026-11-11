<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Analyzers\Security\Concerns\RequestTaint;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * HTTP response header / cookie injection (CWE-113/CWE-1004).
 *
 * `header()`, `setcookie()` and `setrawcookie()` reject CRLF in modern PHP, but
 * concatenating request data into them still lets an attacker set cookies or
 * split a header on older runtimes and through intermediate proxies. This rule
 * reports request-derived arguments; `Location:` is left to OWASP Open Redirect
 * so the same line does not produce two findings.
 */
final class HeaderInjectionAnalyzer extends AbstractAnalyzer
{
    use RequestTaint;

    private const RULE = 'HEADER_INJECTION';

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
            $requestVars = $this->requestVariables($ast);

            foreach ($this->finder()->findInstanceOf($ast, Expr\FuncCall::class) as $call) {
                if (!$call instanceof Expr\FuncCall || !$call->name instanceof Node\Name) {
                    continue;
                }
                $name = strtolower($call->name->getLast());
                if ($name !== 'header') {
                    continue;
                }

                $argument = $call->args[0]->value ?? null;
                if (!$argument instanceof Expr || !$this->isRequestExpression($argument, $requestVars)) {
                    continue;
                }
                if ($name === 'header' && $this->isLocationHeader($argument)) {
                    continue;
                }
                $direct = $this->isDirectRequest($argument);

                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf(
                        'Request-derived value reaches %s(); sanitize CR/LF and validate the value before sending it.',
                        $name
                    ),
                    $file,
                    $call->getStartLine(),
                    Severity::Warning,
                    ['sink' => $name],
                    $direct ? Confidence::High : Confidence::Medium
                );
            }
        }

        return $issues;
    }

    private function isLocationHeader(Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_ && stripos($expr->value, 'location:') === 0) {
            return true;
        }
        if ($expr instanceof Expr\BinaryOp\Concat && $expr->left instanceof Node\Scalar\String_) {
            return stripos($expr->left->value, 'location:') === 0;
        }

        return false;
    }

    private function isDirectRequest(Expr $expr): bool
    {
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, $this->requestSuperglobals, true);
        }
        if ($expr instanceof Expr\ArrayDimFetch) {
            return $this->isDirectRequest($expr->var);
        }

        return false;
    }
}
