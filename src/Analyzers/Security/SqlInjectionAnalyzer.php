<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Analyzers\Security\Concerns\RequestTaint;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

final class SqlInjectionAnalyzer extends AbstractAnalyzer
{
    use RequestTaint;

    private const RULE = 'SQL_INJECTION';

    private const RAW_METHODS = [
        'select',
        'statement',
        'unprepared',
        'raw',
        'selectRaw',
        'whereRaw',
        'orderByRaw',
        'havingRaw',
        'groupByRaw',
        // Plain PDO / mysqli style APIs.
        'query',
        'exec',
        'multi_query',
        'real_query',
    ];

    /**
     * Builder methods whose first argument is a column/expression name, not a
     * value: tainted input here is column-name injection
     * (e.g. orderBy($request->sort)).
     */
    private const COLUMN_METHODS = [
        'orderBy',
        'orderByDesc',
        'groupBy',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $requestVars = $this->requestVariables($ast);
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall || $node instanceof Node\Expr\MethodCall;
        });

        foreach ($calls as $call) {
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
            if ($method === null) {
                continue;
            }

            $isRaw = in_array($method, self::RAW_METHODS, true);
            $isColumn = in_array($method, self::COLUMN_METHODS, true);
            if (!$isRaw && !$isColumn) {
                continue;
            }

            if (!$this->isDbContext($call)) {
                continue;
            }

            foreach ($call->args as $arg) {
                if ($this->containsTaintedInput($arg->value, $requestVars)) {
                    $issues[] = $this->makeIssue(
                        self::RULE,
                        $isColumn
                            ? sprintf('Potential SQL injection: tainted column name flows into %s() (column-name injection).', $method)
                            : sprintf('Potential SQL injection: tainted input flows into %s().', $method),
                        $file,
                        $call->getStartLine(),
                        Severity::$Critical,
                        ['method' => $method]
                    );
                    break;
                }
            }
        }

        return $issues;
    }

    private function isDbContext(Node $call): bool
    {
        if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name) {
            $class = $call->class->toString();

            return $class === 'DB' || substr_compare($class, '\\DB', -strlen('\\DB')) === 0;
        }

        if ($call instanceof Node\Expr\MethodCall) {
            $var = $call->var;
            if (
                $var instanceof Node\Expr\StaticCall
                && $var->class instanceof Node\Name
                && in_array($var->class->toString(), ['DB', 'Illuminate\\Support\\Facades\\DB'], true)
            ) {
                return true;
            }

            return $this->mentionsDb($var);
        }

        return false;
    }

    /**
     * DB handle names used by plain PDO / mysqli code. Kept as a name list
     * (not full type inference) because static analysis without a booted
     * container cannot know the runtime class.
     *
     * @var list<string>
     */
    private const DB_RECEIVER_NAMES = ['db', 'pdo', 'conn', 'connection', 'dbh', 'link', 'mysqli', 'database'];

    private function mentionsDb(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\MethodCall) {
            return $this->mentionsDb($expr->var);
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return in_array(strtolower($expr->name), self::DB_RECEIVER_NAMES, true);
        }

        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && in_array(strtolower($expr->name->toString()), self::DB_RECEIVER_NAMES, true)
        ) {
            return true;
        }

        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            $class = strtolower($expr->class->getLast());

            return in_array($class, ['pdo', 'mysqli'], true);
        }

        return false;
    }

    /**
     * @param array<string, true> $requestVars
     */
    private function containsTaintedInput(Node\Expr $expr, array $requestVars): bool
    {
        return $this->looksLikeInput($expr) || $this->isRequestExpression($expr, $requestVars);
    }

    private function looksLikeInput(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\FuncCall) {
            $name = $expr->name instanceof Node\Name ? $expr->name->toString() : null;
            if (in_array($name, ['input', 'request', 'all', 'get', 'post', 'cookie'], true)) {
                return true;
            }

            if (in_array($name, ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'], true)) {
                return true;
            }

            return false;
        }

        if ($expr instanceof Node\Expr\MethodCall) {
            $method = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
            if (in_array($method, ['input', 'query', 'get', 'post', 'all', 'only', 'except', 'cookie', 'header'], true)) {
                return $this->isRequestObject($expr->var);
            }

            return false;
        }

        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && in_array($expr->name->toString(), ['all', 'input', 'query'], true)
        ) {
            return $this->isRequestObject($expr->var);
        }

        if ($expr instanceof Node\Expr\Variable && in_array($expr->name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_ENV'], true)) {
            return true;
        }

        return false;
    }

    private function isRequestObject(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable && $expr->name === 'request') {
            return true;
        }

        if (
            $expr instanceof Node\Expr\PropertyFetch
            && $expr->name instanceof Node\Identifier
            && $expr->name->toString() === 'request'
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
        ) {
            return true;
        }

        if (
            $expr instanceof Node\Expr\FuncCall
            && $expr->name instanceof Node\Name
            && $expr->name->toString() === 'request'
        ) {
            return true;
        }

        return false;
    }
}
