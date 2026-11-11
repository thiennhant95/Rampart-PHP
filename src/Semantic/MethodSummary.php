<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * One summarized method return. Param-derived summaries never store a
 * concrete provenance — `return $input` is `PARAM(0)`, and only the
 * call-site (with actual arguments) decides RAW / VALIDATED / BOUNDED /
 * INTERNAL. Context-insensitive RAW would be a false resolution.
 */
final class MethodSummary
{
    public const PARAM = 'param';

    public const INTERNAL = 'internal';

    public const UNKNOWN = 'unknown';

    public const OP_PASSTHROUGH = 'passthrough';

    public const OP_ALL = 'all';

    public const OP_INPUT = 'input';

    public const OP_ONLY = 'only';

    public const OP_EXCEPT = 'except';

    public const OP_VALIDATED = 'validated';

    public const OP_SAFE = 'safe';
    /**
     * @readonly
     */
    public string $class;
    /**
     * @readonly
     */
    public string $method;
    /**
     * @readonly
     */
    public string $kind;
    /**
     * @var list<string>
     * @readonly
     */
    public array $params;
    /**
     * @readonly
     */
    public ?int $paramIndex;
    /**
     * @readonly
     */
    public ?string $operation;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $fields;
    /**
     * @readonly
     */
    public string $confidence;
    /**
     * @readonly
     */
    public string $evidence;
    /**
     * @readonly
     */
    public ?string $unresolvedReason;
    /**
     * @readonly
     */
    public ?string $declaringClass = null;
    /**
     * @readonly
     */
    public string $visibility = 'public';
    /**
     * @param list<string> $params parameter names in order
     * @param list<string>|null $fields literal field-set (only/except)
     */
    public function __construct(string $class, string $method, string $kind, array $params, ?int $paramIndex, ?string $operation, ?array $fields, string $confidence, string $evidence, ?string $unresolvedReason, ?string $declaringClass = null, string $visibility = 'public')
    {
        $this->class = $class;
        $this->method = $method;
        $this->kind = $kind;
        $this->params = $params;
        $this->paramIndex = $paramIndex;
        $this->operation = $operation;
        $this->fields = $fields;
        $this->confidence = $confidence;
        $this->evidence = $evidence;
        $this->unresolvedReason = $unresolvedReason;
        $this->declaringClass = $declaringClass;
        $this->visibility = $visibility;
    }

    public static function unknown(
        string $class,
        string $method,
        string $reason,
        ?string $declaringClass = null,
        string $visibility = 'public'
    ): self {
        return new self($class, $method, self::UNKNOWN, [], null, null, null, 'low', '', $reason, $declaringClass, $visibility);
    }

    /**
     * @return array{class: string, method: string, kind: string, params: list<string>, param_index: int|null, operation: string|null, fields: list<string>|null, confidence: string, evidence: string, unresolved_reason: string|null, declaring_class: string|null, visibility: string}
     */
    public function toArray(): array
    {
        return [
            'class' => $this->class,
            'method' => $this->method,
            'kind' => $this->kind,
            'params' => $this->params,
            'param_index' => $this->paramIndex,
            'operation' => $this->operation,
            'fields' => $this->fields,
            'confidence' => $this->confidence,
            'evidence' => $this->evidence,
            'unresolved_reason' => $this->unresolvedReason,
            'declaring_class' => $this->declaringClass,
            'visibility' => $this->visibility,
        ];
    }
}
