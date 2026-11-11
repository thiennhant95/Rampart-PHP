<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\FunctionLike;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * Predictable randomness used for security values.
 *
 * `mt_rand()` / `rand()` / `uniqid()` are not cryptographically secure. To stay
 * quiet on cosmetic use (`rand(1, 6)` for a die roll), a finding requires a
 * security-looking target: the assignment name or the enclosing function name
 * must contain token/password/otp/nonce/salt/secret/key/csrf/reset/verify.
 */
final class InsecureRandomAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'INSECURE_RANDOM';

    /**
     * `rand`/`mt_rand`/`uniqid` are covered by INSECURE_HASH (same rule the
     * Laravel target uses). This rule adds the weaker helpers that one does
     * not: `lcg_value` (LCG), `str_shuffle` (Mersenne Twister), `array_rand`.
     *
     * @var list<string>
     */
    private const FUNCTIONS = ['lcg_value', 'str_shuffle', 'array_rand'];

    private const HINTS = [
        'token', 'password', 'passwd', 'otp', 'nonce', 'salt', 'secret', 'key',
        'csrf', 'xsrf', 'reset', 'verify', 'verification', 'activation', 'invite',
        'remember', 'session', 'captcha', 'code',
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
                $context = $this->contextName($call);
                if (!$this->hasSecurityHint($context)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf(
                        '%s() is predictable; use random_bytes()/random_int() for security-sensitive values.',
                        $name
                    ),
                    $file,
                    $call->getStartLine(),
                    Severity::$Warning,
                    ['function' => $name, 'context' => $context],
                    Confidence::$Medium
                );
            }
        }

        return $issues;
    }

    private function contextName(Node $node): string
    {
        $names = [];
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if ($parent instanceof Expr\Assign && $parent->var instanceof Expr\Variable && is_string($parent->var->name)) {
                $names[] = strtolower($parent->var->name);
            }
            if ($parent instanceof FunctionLike) {
                $functionName = $parent->name ?? null;
                if ($functionName instanceof Node\Identifier) {
                    $names[] = strtolower($functionName->toString());
                }
                break;
            }
            $current = $parent;
        }

        return implode(' ', $names);
    }

    private function hasSecurityHint(string $context): bool
    {
        foreach (self::HINTS as $hint) {
            if (strpos($context, $hint) !== false) {
                return true;
            }
        }

        return false;
    }
}
