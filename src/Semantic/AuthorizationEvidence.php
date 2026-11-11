<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * Authorization evidence from a FormRequest `authorize()` method.
 * `return true` (and absent `authorize()`) yield MECH_NONE — explicitly
 * not protection. Ability checks yield MECH_CAN; anything else
 * non-trivial yields MECH_CUSTOM (unrecognized but real logic, kept as
 * protection by consumers for backward compatibility).
 */
final class AuthorizationEvidence
{
    public const SOURCE_FORM_REQUEST = 'form-request';

    public const MECH_CAN = 'authorize-can';

    public const MECH_CUSTOM = 'authorize-custom';

    public const MECH_DENY = 'authorize-deny';

    public const MECH_NONE = 'authorize-none';
    /**
     * @readonly
     */
    public string $source;
    /**
     * @readonly
     */
    public string $requestClass;
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
    public string $confidence;
    public function __construct(string $source, string $requestClass, string $mechanism, ?string $ability, string $confidence)
    {
        $this->source = $source;
        $this->requestClass = $requestClass;
        $this->mechanism = $mechanism;
        $this->ability = $ability;
        $this->confidence = $confidence;
    }

    /**
     * @return array{source: string, request_class: string, mechanism: string, ability: string|null, confidence: string}
     */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'request_class' => $this->requestClass,
            'mechanism' => $this->mechanism,
            'ability' => $this->ability,
            'confidence' => $this->confidence,
        ];
    }
}
