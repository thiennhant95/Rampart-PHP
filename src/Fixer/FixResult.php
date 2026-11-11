<?php

declare(strict_types=1);

namespace Rampart\Php\Fixer;

/**
 * Value object describing the outcome of an auto-fix run.
 */
final class FixResult
{
    /**
     * @var int
     * @readonly
     */
    public int $filesFixed;
    /**
     * @var list<string>
     * @readonly
     */
    public array $errors;
    /**
     * @var string
     * @readonly
     */
    public string $output;
    /**
     * @param int $filesFixed Number of files the fixer reported as fixed.
     * @param list<string> $errors Human-readable failure messages, if any.
     * @param string $output Raw output captured from the underlying tool.
     */
    public function __construct(int $filesFixed, array $errors, string $output)
    {
        $this->filesFixed = $filesFixed;
        $this->errors = $errors;
        $this->output = $output;
    }
    /**
     * True when no errors were encountered.
     */
    public function success(): bool
    {
        return count($this->errors) === 0;
    }
}
