<?php

declare(strict_types=1);

namespace Rampart\Php\Analysis;

/**
 * A proven-constant string value with its provenance chain. Only
 * exact values exist — anything not proven constant resolves to null
 * (no ConstantValue at all), never to a guess.
 */
final class ConstantValue
{
    /**
     * @readonly
     */
    public string $value;
    /**
     * @readonly
     */
    public string $confidence = 'exact';
    /**
     * @var list<array{kind: string, detail: string, file: (string | null), line: (int | null)}>
     * @readonly
     */
    public array $provenance = [];
    /**
     * @param list<array{kind: string, detail: string, file: string|null, line: int|null}> $provenance
     */
    public function __construct(string $value, string $confidence = 'exact', array $provenance = [])
    {
        $this->value = $value;
        $this->confidence = $confidence;
        $this->provenance = $provenance;
    }
    /**
     * @param array{kind: string, detail: string, file: string|null, line: int|null} $step
     */
    public function withStep(array $step): self
    {
        return new self($this->value, $this->confidence, [...$this->provenance, $step]);
    }
}
