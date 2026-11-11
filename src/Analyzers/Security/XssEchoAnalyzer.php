<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Analyzers\Security\Concerns\RequestTaint;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * Reflected/stored XSS in plain PHP templates.
 *
 * Sinks: `echo`, `print`, and `<?= ... ?>` (which the parser represents as
 * Echo_). Only request-derived values are reported: a direct superglobal or
 * `$request->input(...)` is high confidence; a local variable assigned from
 * one is medium. `echo $title` where `$title` is a DB value stays silent —
 * that is exactly the noise trade-off the Laravel Blade analyzer also makes.
 */
final class XssEchoAnalyzer extends AbstractAnalyzer
{
    use RequestTaint;

    private const RULE = 'XSS_ECHO';

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
            $seenLines = [];

            foreach ($this->finder()->findInstanceOf($ast, Stmt\Echo_::class) as $node) {
                if (!$node instanceof Stmt\Echo_) {
                    continue;
                }
                foreach ($node->exprs as $expr) {
                    if (!$this->isRequestExpression($expr, $requestVars)) {
                        continue;
                    }
                    $line = $expr->getStartLine();
                    if (isset($seenLines[$line])) {
                        continue;
                    }
                    $seenLines[$line] = true;
                    $issues[] = $this->issue($file, $line, $expr, $requestVars);
                }
            }

            $prints = $this->finder()->findInstanceOf($ast, Expr\Print_::class);
            foreach ($prints as $print) {
                if (!$print instanceof Expr\Print_) {
                    continue;
                }
                if (!$this->isRequestExpression($print->expr, $requestVars)) {
                    continue;
                }
                $line = $print->getStartLine();
                if (isset($seenLines[$line])) {
                    continue;
                }
                $seenLines[$line] = true;
                $issues[] = $this->issue($file, $line, $print->expr, $requestVars);
            }
        }

        return $issues;
    }

    /**
     * @param array<string, true> $requestVars
     */
    private function issue(string $file, int $line, Expr $expr, array $requestVars): Issue
    {
        $direct = $this->isDirect($expr);

        return $this->makeIssue(
            self::RULE,
            'Request-derived value is echoed without escaping (XSS). Use htmlspecialchars($value, ENT_QUOTES, \'UTF-8\') or an escaping template engine.',
            $file,
            $line,
            Severity::Error,
            ['sink' => $direct ? 'request' : 'variable'],
            $direct ? Confidence::High : Confidence::Medium
        );
    }

    private function isDirect(Expr $expr): bool
    {
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, $this->requestSuperglobals, true);
        }
        if ($expr instanceof Expr\ArrayDimFetch) {
            return $this->isDirect($expr->var);
        }
        if ($expr instanceof Expr\FuncCall) {
            $name = $this->functionNameOf($expr);

            return $name === 'request' || $name === 'filter_input';
        }

        return false;
    }
}
