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
 * Debug output left in shipped code.
 *
 * `var_dump()`, `print_r()`, `phpinfo()` and friends leak paths, SQL, tokens
 * and configuration to the response. Low confidence / off by default: in a
 * CLI script this is often intentional, so it is a hint, not a gate.
 */
final class DebugOutputAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'DEBUG_OUTPUT';

    /** @var list<string> */
    private const FUNCTIONS = [
        'var_dump', 'print_r', 'var_export', 'debug_zval_dump', 'phpinfo', 'dd', 'dump', 'ray',
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
            foreach ($this->finder()->findInstanceOf($ast, Expr\FuncCall::class) as $call) {
                if (!$call instanceof Expr\FuncCall || !$call->name instanceof Node\Name) {
                    continue;
                }
                $name = strtolower($call->name->getLast());
                if (!in_array($name, self::FUNCTIONS, true)) {
                    continue;
                }
                // print_r/var_export with return=true are used to build strings.
                if (in_array($name, ['print_r', 'var_export'], true)) {
                    $return = $call->args[1]->value ?? null;
                    if ($return instanceof Expr\ConstFetch && strtolower($return->name->toString()) === 'true') {
                        continue;
                    }
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf('Debug function %s() is present in shipped code; remove it or gate it behind an explicit debug flag.', $name),
                    $file,
                    $call->getStartLine(),
                    Severity::$Warning,
                    ['function' => $name],
                    Confidence::$Low
                );
            }
        }

        return $issues;
    }
}
