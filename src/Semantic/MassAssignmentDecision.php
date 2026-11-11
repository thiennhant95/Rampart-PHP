<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * Source × Model assignability decision (v0.4.2, shadow mode).
 *
 * Mirrors AccessDecision architecture: a verdict with composable
 * evidence, never a bare boolean. `validated` input is never
 * auto-safe; `force*` bypasses model protection in reasoning;
 * internal data is never a request finding; unknown stays unknown.
 */
final class MassAssignmentDecision
{
    public const SAFE = 'safe';

    public const REVIEW = 'review';

    public const EXPOSED = 'exposed';

    public const UNKNOWN = 'unknown';
    /**
     * @readonly
     */
    public string $verdict;
    /**
     * @readonly
     */
    public string $input;
    /**
     * @readonly
     */
    public ?string $model;
    /**
     * @readonly
     */
    public string $assignability;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $inputFields;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $assignableFields;
    /**
     * @var list<string>|null
     * @readonly
     */
    public ?array $protectionFields;
    /**
     * @var list<string>
     * @readonly
     */
    public array $sensitiveFields;
    /**
     * @var list<string>
     * @readonly
     */
    public array $evidence;
    /**
     * @var list<array{kind: string, detail: string, line: (int | null)}>
     * @readonly
     */
    public array $trace;
    /**
     * @param list<string>|null $inputFields known input fields (only())
     * @param list<string>|null $assignableFields model-allowed fields
     *   (null = open or unknown set)
     * @param list<string>|null $protectionFields protection-defining
     *   fields (fillable list, guarded list, [] for guarded-all)
     * @param list<string> $sensitiveFields reserved slot (v0.4.2: always
     *   empty — risk ranking, not detection foundation)
     * @param list<string> $evidence
     * @param list<array{kind: string, detail: string, line: int|null}> $trace
     */
    public function __construct(string $verdict, string $input, ?string $model, string $assignability, ?array $inputFields, ?array $assignableFields, ?array $protectionFields, array $sensitiveFields, array $evidence, array $trace)
    {
        $this->verdict = $verdict;
        $this->input = $input;
        $this->model = $model;
        $this->assignability = $assignability;
        $this->inputFields = $inputFields;
        $this->assignableFields = $assignableFields;
        $this->protectionFields = $protectionFields;
        $this->sensitiveFields = $sensitiveFields;
        $this->evidence = $evidence;
        $this->trace = $trace;
    }

    /**
     * @return array{verdict: string, input: string, model: string|null, assignability: string, input_fields: list<string>|null, assignable_fields: list<string>|null, protection_fields: list<string>|null, sensitive_fields: list<string>, evidence: list<string>, trace: list<array{kind: string, detail: string, line: int|null}>}
     */
    public function toArray(): array
    {
        return [
            'verdict' => $this->verdict,
            'input' => $this->input,
            'model' => $this->model,
            'assignability' => $this->assignability,
            'input_fields' => $this->inputFields,
            'assignable_fields' => $this->assignableFields,
            'protection_fields' => $this->protectionFields,
            'sensitive_fields' => $this->sensitiveFields,
            'evidence' => $this->evidence,
            'trace' => $this->trace,
        ];
    }

    public static function decide(
        MassFlow $flow,
        ?ModelMetadata $metadata,
        bool $globallyUnguarded = false
    ): self {
        $evidence = [
            'input: ' . $flow->status . ' (' . $flow->source . ')',
            'sink: ' . $flow->sink . ($flow->forceBypass ? ' [guard-bypassing]' : ''),
        ];
        $mk = static fn (
            string $verdict,
            ?string $model,
            string $assignability,
            ?array $inputFields,
            ?array $assignableFields,
            ?array $protectionFields,
            array $extra
        ): self => new self(
            $verdict,
            $flow->status,
            $model,
            $assignability,
            $inputFields,
            $assignableFields,
            $protectionFields,
            [],
            array_merge($evidence, $extra),
            $flow->trace
        );

        // Internal data is never a request finding, whatever the model.
        if ($flow->status === MassFlow::INTERNAL) {
            return $mk(self::SAFE, ($metadata2 = $metadata) ? $metadata2->model : null, $metadata === null
                ? ModelMetadata::ASSIGN_UNKNOWN
                : $metadata->assignability()[0], null, null, null, ['internal data: not request mass assignment']);
        }

        // force* bypasses model protection by definition: the model
        // cannot save a raw request, whatever it declares.
        if ($flow->forceBypass) {
            return $mk(
                $flow->status === MassFlow::RAW ? self::EXPOSED : self::REVIEW,
                ($metadata2 = $metadata) ? $metadata2->model : null,
                $metadata === null ? ModelMetadata::ASSIGN_UNKNOWN : $metadata->assignability()[0],
                $flow->fields,
                null,
                null,
                ['force-bypass: model protection ignored']
            );
        }

        // Unresolved model: nothing provable (internal handled above) —
        // unless a global unguard is proven, which bypasses every model
        // including unscanned ones.
        if ($metadata === null && !$globallyUnguarded) {
            return $mk(self::UNKNOWN, null, ModelMetadata::ASSIGN_UNKNOWN, null, null, null, ['model: unresolved']);
        }
        [$assignability, $assignable] = $metadata === null
            ? [ModelMetadata::UNGUARDED, null]
            : $metadata->assignability();
        $modelName = ($metadata2 = $metadata) ? $metadata2->model : null;
        $protectionFields = ($metadata2 = $metadata) ? $metadata2->guardedFields : null;
        if ($assignability === ModelMetadata::FILLABLE) {
            $protectionFields = $assignable;
        }
        if ($assignability === ModelMetadata::GUARDED_ALL) {
            $protectionFields = [];
        }
        if ($globallyUnguarded && $assignability !== ModelMetadata::ASSIGN_UNKNOWN) {
            $assignability = ModelMetadata::UNGUARDED;
            $assignable = null;
            $protectionFields = null;
        }
        $modelLabel = ($modelName ?? 'unknown model') . ' (' . $assignability . ')';
        if ($assignability === ModelMetadata::ASSIGN_UNKNOWN) {
            return $mk(self::UNKNOWN, $modelName, $assignability, null, null, null, ['model: ' . $modelLabel]);
        }

        // Framework-protected models: nothing assignable, or the
        // framework drops non-fillable input.
        if ($assignability === ModelMetadata::GUARDED_ALL) {
            return $mk(self::SAFE, $modelName, $assignability, null, [], [], ['model: ' . $modelLabel]);
        }
        if ($assignability === ModelMetadata::FILLABLE) {
            return $mk(
                self::SAFE,
                $modelName,
                $assignability,
                $flow->fields,
                $assignable,
                $protectionFields,
                ['model: ' . $modelLabel]
            );
        }

        if ($assignability === ModelMetadata::GUARDED_LIST) {
            // Bounded input fully inside the guarded list is blocked.
            $guardedFields = ($metadata2 = $metadata) ? $metadata2->guardedFields : null;
            if (
                $flow->status === MassFlow::BOUNDED
                && $flow->fields !== null
                && $guardedFields !== null
                && $flow->fields !== []
                && array_diff($flow->fields, $guardedFields) === []
            ) {
                return $mk(
                    self::SAFE,
                    $modelName,
                    $assignability,
                    $flow->fields,
                    null,
                    $protectionFields,
                    ['model: ' . $modelLabel, 'all input fields guarded']
                );
            }

            return $mk(
                self::REVIEW,
                $modelName,
                $assignability,
                $flow->fields,
                null,
                $protectionFields,
                ['model: ' . $modelLabel, 'guarded list is not total protection']
            );
        }

        // UNGUARDED from here (explicit $guarded = [] or global unguard).
        // Raw request data flows unfiltered (EXPOSED); validated/bounded
        // input needs human review — validated is never auto-safe.
        $extra = ['model: ' . $modelLabel . ($globallyUnguarded ? ' [globally unguarded]' : '')];
        if ($flow->status === MassFlow::RAW) {
            return $mk(self::EXPOSED, $modelName, $assignability, null, null, null, $extra);
        }

        return $mk(self::REVIEW, $modelName, $assignability, $flow->fields, null, null, $extra);
    }
}
