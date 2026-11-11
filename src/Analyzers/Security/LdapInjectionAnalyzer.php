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
 * LDAP injection (CWE-90).
 *
 * The filter (search/list/read/compare) and the DN (add/delete/modify/rename)
 * are both query syntax, not bound values. Request-derived data there is
 * reported as Critical/high; escaping helpers (`ldap_escape`) are not tracked,
 * so a reviewer may still see a finding when the call is already safe.
 */
final class LdapInjectionAnalyzer extends AbstractAnalyzer
{
    use RequestTaint;

    private const RULE = 'LDAP_INJECTION';

    /** Filter position per function (0-based argv). */
    private const FILTER_POSITION = [
        'ldap_search' => 2,
        'ldap_list' => 2,
        'ldap_read' => 2,
        'ldap_compare' => 3,
        'ldap_exop' => 2,
    ];

    /** DN position per function. */
    private const DN_POSITION = [
        'ldap_add' => 1,
        'ldap_delete' => 1,
        'ldap_modify' => 1,
        'ldap_mod_add' => 1,
        'ldap_mod_del' => 1,
        'ldap_mod_replace' => 1,
        'ldap_rename' => 1,
    ];

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
                $position = self::FILTER_POSITION[$name] ?? self::DN_POSITION[$name] ?? null;
                if ($position === null) {
                    continue;
                }
                $argument = $call->args[$position]->value ?? null;
                if (!$argument instanceof Expr || !$this->isRequestExpression($argument, $requestVars)) {
                    continue;
                }

                $kind = isset(self::FILTER_POSITION[$name]) ? 'filter' : 'DN';

                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf(
                        'Request-derived value is used as an LDAP %s in %s(). Escape it with ldap_escape() and build the query from a fixed template.',
                        $kind,
                        $name
                    ),
                    $file,
                    $call->getStartLine(),
                    Severity::$Critical,
                    ['function' => $name, 'part' => $kind],
                    Confidence::$High
                );
            }
        }

        return $issues;
    }
}
