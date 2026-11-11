<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * One classified input-to-sink flow. The status describes provenance,
 * never a verdict: `validated` does NOT mean mass-assignment safe (a
 * validated `is_admin` field is still a mass-assignment issue) — field
 * reasoning lands in v0.4.2 with model metadata.
 */
final class MassFlow
{
    public const RAW = 'tainted-raw';

    public const VALIDATED = 'validated';

    public const BOUNDED = 'bounded';

    public const INTERNAL = 'internal';

    public const UNKNOWN = 'unknown';
    /**
     * @readonly
     */
    public string $status;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $fields;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $excluded;
    /**
     * @readonly
     */
    public bool $forceBypass;
    /**
     * @readonly
     */
    public string $source;
    /**
     * @readonly
     */
    public string $sink;
    /**
     * @var list<array{kind: string, detail: string, line: (int | null)}>
     * @readonly
     */
    public array $trace;
    /**
     * @param list<string>|null $fields bounded/known fields (only())
     * @param list<string>|null $excluded removed fields (except())
     * @param list<array{kind: string, detail: string, line: int|null}> $trace
     */
    public function __construct(string $status, ?array $fields, ?array $excluded, bool $forceBypass, string $source, string $sink, array $trace)
    {
        $this->status = $status;
        $this->fields = $fields;
        $this->excluded = $excluded;
        $this->forceBypass = $forceBypass;
        $this->source = $source;
        $this->sink = $sink;
        $this->trace = $trace;
    }

    /**
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, force_bypass: bool, source: string, sink: string, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'fields' => $this->fields,
            'excluded' => $this->excluded,
            'force_bypass' => $this->forceBypass,
            'source' => $this->source,
            'sink' => $this->sink,
            'trace' => $this->trace,
        ];
    }
}
