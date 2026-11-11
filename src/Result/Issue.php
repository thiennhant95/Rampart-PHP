<?php

declare(strict_types=1);

namespace Rampart\Php\Result;

final class Issue
{
    public string $rule;
    public string $message;
    public ?string $file;
    public ?int $line;
    public Severity $severity;
    public string $source;
    public array $metadata = [];
    public Confidence $confidence;

    public function __construct(string $rule, string $message, ?string $file, ?int $line, Severity $severity, string $source, array $metadata = [], ?Confidence $confidence = null)
    {
        $this->rule = $rule;
        $this->message = $message;
        $this->file = $file;
        $this->line = $line;
        $this->severity = $severity;
        $this->source = $source;
        $this->metadata = $metadata;
        $this->confidence = $confidence ?? Confidence::$High;
    }
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
            'severity' => $this->severity->value,
            'source' => $this->source,
            'metadata' => $this->metadata,
            'confidence' => $this->confidence->value,
            'confidence_score' => $this->confidenceScore(),
        ];
    }

    /**
     * Numeric confidence 0.0-1.0. Same weights as the quality-score
     * deductions (see Reporters\QualityScore) so reports stay consistent.
     */
    public function confidenceScore(): float
    {
        switch ($this->confidence) {
            case Confidence::$High:
                return 1.0;
            case Confidence::$Medium:
                return 0.5;
            case Confidence::$Low:
                return 0.25;
            default:
                return 0.25;
        }
    }

    public static function fromArray(array $data): self
    {
        return new self((string) ($data['rule'] ?? 'UNKNOWN'), (string) ($data['message'] ?? ''), isset($data['file']) && $data['file'] !== null ? (string) $data['file'] : null, isset($data['line']) && $data['line'] !== null ? (int) $data['line'] : null, Severity::fromString((string) ($data['severity'] ?? 'error')), (string) ($data['source'] ?? 'custom'), is_array($data['metadata'] ?? null) ? $data['metadata'] : [], Confidence::fromString((string) ($data['confidence'] ?? 'high')));
    }

    /**
     * Signature used for baseline files and deduplication.
     */
    public function signature(): string
    {
        return md5(implode('|', [
            $this->rule,
            (string) $this->file,
            (string) ($this->line ?? 0),
            $this->message,
        ]));
    }
}
