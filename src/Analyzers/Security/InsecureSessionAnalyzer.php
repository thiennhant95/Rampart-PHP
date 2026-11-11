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
 * Session cookie flags disabled in code.
 *
 * A plain-PHP app often configures sessions with `ini_set()` or
 * `session_set_cookie_params()`. Turning off HttpOnly / Secure / strict mode
 * weakens every session on the site, so it is reported even without tainted
 * data. Defaults that are merely absent are not reported (php.ini may set
 * them correctly).
 */
final class InsecureSessionAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'INSECURE_SESSION';

    /** @var array<string, string> ini key => what it protects */
    private const INSECURE_INI = [
        'session.cookie_httponly' => 'HttpOnly (blocks JavaScript access to the session cookie)',
        'session.cookie_secure' => 'Secure (blocks sending the cookie over HTTP)',
        'session.use_strict_mode' => 'strict mode (blocks attacker-chosen session IDs)',
        'session.use_only_cookies' => 'cookies-only mode (blocks session IDs in URLs)',
    ];

    private const COOKIE_PARAM_KEYS = ['secure', 'httponly', 'samesite'];

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
                if ($name === 'ini_set') {
                    $key = $call->args[0]->value ?? null;
                    $value = $call->args[1]->value ?? null;
                    if ($key instanceof Node\Scalar\String_ && isset(self::INSECURE_INI[$key->value])) {
                        if ($this->isFalsey($value)) {
                            $issues[] = $this->issue($file, $call, $key->value, self::INSECURE_INI[$key->value]);
                        }
                    }
                    continue;
                }
                if ($name === 'session_set_cookie_params') {
                    $issue = $this->cookieParamsIssue($file, $call);
                    if ($issue !== null) {
                        $issues[] = $issue;
                    }
                }
            }
        }

        return $issues;
    }

    private function cookieParamsIssue(string $file, Expr\FuncCall $call): ?Issue
    {
        $first = $call->args[0]->value ?? null;
        if ($first instanceof Expr\Array_) {
            foreach ($first->items as $item) {
                if (!$item instanceof Node\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                    continue;
                }
                $key = strtolower($item->key->value);
                if (!in_array($key, self::COOKIE_PARAM_KEYS, true)) {
                    continue;
                }
                if ($key === 'samesite' && $item->value instanceof Node\Scalar\String_ && strtolower($item->value->value) === 'none') {
                    continue;
                }
                if ($this->isFalsey($item->value) && $key !== 'samesite') {
                    return $this->issue($file, $call, 'session cookie ' . $key, 'the ' . $key . ' flag');
                }
            }

            return null;
        }

        // Positional form: lifetime, path, domain, secure, httponly.
        $secure = $call->args[3]->value ?? null;
        $httpOnly = $call->args[4]->value ?? null;
        if ($this->isFalsey($secure)) {
            return $this->issue($file, $call, 'session cookie secure', 'the Secure flag');
        }
        if ($this->isFalsey($httpOnly)) {
            return $this->issue($file, $call, 'session cookie httponly', 'the HttpOnly flag');
        }

        return null;
    }

    private function isFalsey(?Node $node): bool
    {
        if ($node instanceof Node\Scalar\String_) {
            return in_array(strtolower($node->value), ['0', '', 'false', 'off', 'no'], true);
        }
        if ($node instanceof Node\Scalar\Int_) {
            return $node->value === 0;
        }
        if ($node instanceof Expr\ConstFetch) {
            $name = strtolower($node->name->toString());

            return in_array($name, ['false', 'null'], true);
        }

        return false;
    }

    private function issue(string $file, Expr\FuncCall $call, string $setting, string $protects): Issue
    {
        return $this->makeIssue(
            self::RULE,
            sprintf('Session setting "%s" is disabled, removing %s.', $setting, $protects),
            $file,
            $call->getStartLine(),
            Severity::$Warning,
            ['setting' => $setting],
            Confidence::$High
        );
    }
}
