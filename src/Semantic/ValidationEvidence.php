<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * Composable validation evidence for one controller action. Never a
 * boolean: presence, mechanism, fields and confidence travel together
 * so future rules (mass assignment) can ask *what* was validated, not
 * just *whether* something was.
 */
final class ValidationEvidence
{
    public const SOURCE_FORM_REQUEST = 'form-request';

    public const SOURCE_INLINE = 'inline-validate';

    public const SOURCE_MAKE = 'validator-make';

    public const SOURCE_VALIDATED = 'validated-use';
    /**
     * @readonly
     */
    public string $source;
    /**
     * @readonly
     */
    public ?string $requestClass;
    /**
     * @readonly
     */
    public bool $hasRules;
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
     * @param list<string>|null $fields null = validated, fields unknown
     */
    public function __construct(string $source, ?string $requestClass, bool $hasRules, ?array $fields, string $confidence)
    {
        $this->source = $source;
        $this->requestClass = $requestClass;
        $this->hasRules = $hasRules;
        $this->fields = $fields;
        $this->confidence = $confidence;
    }

    /**
     * @return array{source: string, request_class: string|null, has_rules: bool, fields: list<string>|null, confidence: string}
     */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'request_class' => $this->requestClass,
            'has_rules' => $this->hasRules,
            'fields' => $this->fields,
            'confidence' => $this->confidence,
        ];
    }
}
