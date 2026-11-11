<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security\Concerns;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\FunctionLike;

/**
 * Shared request-taint helpers for the generic (framework-agnostic) rules.
 *
 * This is deliberately narrower than Taint\TaintEngine: it only answers
 * "could this expression be request input?" inside one file, following simple
 * assignments. Everything else stays untainted, which keeps the plain-PHP
 * rules quiet on ordinary variables (`echo $title` is not XSS by itself).
 */
trait RequestTaint
{
    /**
     * Superglobals that carry user input in plain PHP / any framework.
     *
     * @var list<string>
     */
    private array $requestSuperglobals = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER'];

    /**
     * @param list<Node> $nodes
     * @return array<string, true> variable names assigned request input
     */
    protected function requestVariables(array $nodes): array
    {
        $tainted = [];
        $assigns = $this->finder()->findInstanceOf($nodes, Expr\Assign::class);
        $changed = true;
        while ($changed) {
            $changed = false;
            foreach ($assigns as $assign) {
                if (!$assign instanceof Expr\Assign || !$assign->var instanceof Expr\Variable) {
                    continue;
                }
                $name = $assign->var->name;
                if (!is_string($name) || isset($tainted[$name])) {
                    continue;
                }
                if ($this->isRequestExpression($assign->expr, $tainted)) {
                    $tainted[$name] = true;
                    $changed = true;
                }
            }
        }

        return $tainted;
    }

    /**
     * @param array<string, true> $requestVars
     */
    protected function isRequestExpression(Expr $expr, array $requestVars = []): bool
    {
        if ($expr instanceof Expr\Variable) {
            $name = $expr->name;
            if (!is_string($name)) {
                return false;
            }

            return in_array($name, $this->requestSuperglobals, true) || isset($requestVars[$name]);
        }

        if ($expr instanceof Expr\ArrayDimFetch) {
            return $this->isRequestExpression($expr->var, $requestVars);
        }

        if ($expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch) {
            if ($expr->name instanceof Node\Identifier && $this->isRequestReceiver($expr->var, $requestVars)) {
                return true;
            }

            return $this->isRequestExpression($expr->var, $requestVars);
        }

        if ($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall) {
            $method = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            // Boolean predicates (`isAJAX()`, `hasHeader()`) never render user
            // data; treating them as tainted flagged CI4's debug error view.
            if ($method !== null && preg_match('/^(is|has|can|should|was|does)/i', $method) === 1) {
                return false;
            }
            if ($this->isRequestReceiver($expr->var, $requestVars)) {
                return true;
            }

            return $this->isRequestExpression($expr->var, $requestVars);
        }

        if ($expr instanceof Expr\FuncCall) {
            $name = $this->callName($expr);
            // Context-aware / explicit HTML escapers: the output is safe even
            // though the argument is request data (CI4 `esc()`, Laravel `e()`,
            // plain `htmlspecialchars()`).
            if ($name !== null && in_array(strtolower($name), ['esc', 'htmlspecialchars', 'htmlentities', 'e'], true)) {
                return false;
            }
            if ($name === 'request' || $name === 'filter_input' || $name === 'filter_input_array' || $name === 'getallheaders') {
                return true;
            }
            foreach ($expr->args as $arg) {
                if ($arg instanceof Node\Arg && $this->isRequestExpression($arg->value, $requestVars)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Expr\BinaryOp) {
            return $this->isRequestExpression($expr->left, $requestVars)
                || $this->isRequestExpression($expr->right, $requestVars);
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            foreach ($expr->parts as $part) {
                if ($part instanceof Expr && $this->isRequestExpression($part, $requestVars)) {
                    return true;
                }
            }

            return false;
        }

        if ($expr instanceof Expr\Ternary) {
            return $this->isRequestExpression($expr->cond, $requestVars)
                || ($expr->if !== null && $this->isRequestExpression($expr->if, $requestVars))
                || $this->isRequestExpression($expr->else, $requestVars);
        }

        if ($expr instanceof Expr\Coalesce) {
            return $this->isRequestExpression($expr->left, $requestVars)
                || $this->isRequestExpression($expr->right, $requestVars);
        }

        if ($expr instanceof Expr\Cast) {
            return $this->isRequestExpression($expr->expr, $requestVars);
        }

        return false;
    }

    /**
     * @param array<string, true> $requestVars
     */
    private function isRequestReceiver(Expr $expr, array $requestVars): bool
    {
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            return in_array($expr->name, ['request', 'req'], true)
                || $expr->name === '_request'
                || isset($requestVars[$expr->name]);
        }

        if ($expr instanceof Expr\FuncCall) {
            $name = $this->callName($expr);

            return $name === 'request' || $name === 'app';
        }

        if ($expr instanceof Expr\StaticCall) {
            $name = $this->callName($expr);

            return in_array($name, ['Input', 'Request', 'Container'], true);
        }

        return false;
    }

    protected function callName(Expr $expr): ?string
    {
        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name) {
            return $expr->name->getLast();
        }
        if ($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall) {
            return $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
        }
        if ($expr instanceof Expr\StaticCall && $expr->name instanceof Node\Identifier) {
            return $expr->name->toString();
        }

        return null;
    }

    /**
     * Argument value at a position, honouring named arguments.
     */
    protected function argValue(Expr $call, int $position, ?string $name = null): ?Expr
    {
        if (
            !$call instanceof Expr\FuncCall
            && !$call instanceof Expr\MethodCall
            && !$call instanceof Expr\StaticCall
            && !$call instanceof Expr\New_
        ) {
            return null;
        }

        foreach ($call->args as $index => $arg) {
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            if ($name !== null && $arg->name !== null && $arg->name->toString() === $name) {
                return $arg->value;
            }
            if ($arg->name === null && $index === $position) {
                return $arg->value;
            }
        }

        return null;
    }

    protected function functionNameOf(Expr $expr): ?string
    {
        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name) {
            return strtolower($expr->name->toString());
        }

        return null;
    }

    /**
     * Variables passed into a function/method, for line-context heuristics.
     */
    protected function insideFunction(Node $node): bool
    {
        $current = $node;
        while (($parent = $current->getAttribute('parent')) instanceof Node) {
            if ($parent instanceof FunctionLike) {
                return true;
            }
            $current = $parent;
        }

        return false;
    }
}
