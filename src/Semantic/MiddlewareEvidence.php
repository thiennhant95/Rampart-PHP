<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * Composable authorization evidence from a middleware `handle()`.
 * Answers "why is this finding absent?" — and, when attached to a
 * review finding's `middleware_resolution`, "what did the engine see?".
 */
final class MiddlewareEvidence
{
    public const MECHANISM_GATE = 'gate';

    public const MECHANISM_ROLE = 'role';
    /**
     * @readonly
     */
    public string $type;
    /**
     * @readonly
     */
    public string $alias;
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
    public string $mechanism;
    /**
     * @readonly
     */
    public ?string $ability;
    /**
     * @readonly
     */
    public string $source;
    /**
     * @readonly
     */
    public string $confidence;
    public function __construct(string $type, string $alias, string $class, string $method, string $mechanism, ?string $ability, string $source, string $confidence)
    {
        $this->type = $type;
        $this->alias = $alias;
        $this->class = $class;
        $this->method = $method;
        $this->mechanism = $mechanism;
        $this->ability = $ability;
        $this->source = $source;
        $this->confidence = $confidence;
    }

    /**
     * @return array{type: string, alias: string, class: string, method: string, mechanism: string, ability: string|null, source: string, confidence: string}
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'alias' => $this->alias,
            'class' => $this->class,
            'method' => $this->method,
            'mechanism' => $this->mechanism,
            'ability' => $this->ability,
            'source' => $this->source,
            'confidence' => $this->confidence,
        ];
    }
}
