<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * One object-level authorization verdict for a controller action (v0.6.1,
 * shadow mode). Four states — never a bare boolean, never a guess:
 *
 * - PROTECTED: ownership evidence exists (relationship-scoped query,
 *   where(owner, currentUser), explicit owner comparison + deny,
 *   enforcing Policy/Gate, `can:` middleware, ownership middleware).
 *   No finding.
 * - REVIEW: the action authenticates (auth middleware or principal use)
 *   and performs a sensitive operation on a request-identified resource,
 *   but nothing proves ownership. Human review (deleteLink lives here).
 * - EXPOSED: public route (no auth) + sensitive operation on a
 *   request-identified resource. High confidence.
 * - UNKNOWN: the chain cannot be proven — dynamic lookup (service
 *   return), tenant/team multi-hop, polymorphic ownership, custom
 *   middleware, or no route at all. Never a silent SAFE.
 *
 * Auth alone is never ownership. The full chain travels with the
 * verdict so review explains instead of asserting.
 */
final class OwnershipDecision
{
    public const PROTECTED = 'protected';

    public const REVIEW = 'review';

    public const EXPOSED = 'exposed';

    public const UNKNOWN = 'unknown';
    /**
     * @readonly
     */
    public string $status;
    /**
     * @readonly
     */
    public string $controller;
    /**
     * @readonly
     */
    public string $method;
    /**
     * @readonly
     */
    public string $file;
    /**
     * @readonly
     */
    public int $line;
    /**
     * @var array{methods: list<string>, uri: (string | null), file: string, line: (int | null)}|null
     * @readonly
     */
    public ?array $route;
    /**
     * @var list<string>
     * @readonly
     */
    public array $middleware;
    /**
     * @var array{kind: string, detail: string}|null
     * @readonly
     */
    public ?array $identifier;
    /**
     * @var array{kind: string, detail: string}|null
     * @readonly
     */
    public ?array $lookup;
    /**
     * @var array{kind: string, detail: string}|null
     * @readonly
     */
    public ?array $operation;
    /**
     * @var array{kind: string, detail: string}|null
     * @readonly
     */
    public ?array $principal;
    /**
     * @var list<array{mechanism: string, detail: string, confidence: string}>
     * @readonly
     */
    public array $ownershipEvidence;
    /**
     * @var list<array{mechanism: string, detail: string, confidence: string}>
     * @readonly
     */
    public array $authorizationEvidence;
    /**
     * @readonly
     */
    public string $confidence;
    /**
     * @var list<array{kind: string, detail: string, line: (int | null)}>
     * @readonly
     */
    public array $trace;
    /**
     * @var string
     * @readonly
     */
    public string $reason = '';
    /**
     * @param array{methods: list<string>, uri: string|null, file: string, line: int|null}|null $route
     * @param list<string> $middleware full inherited stack, outermost first
     * @param array{kind: string, detail: string}|null $identifier request-controlled id source
     * @param array{kind: string, detail: string}|null $lookup model lookup shape
     * @param array{kind: string, detail: string}|null $operation sensitive operation
     * @param array{kind: string, detail: string}|null $principal authenticated principal, if any
     * @param list<array{mechanism: string, detail: string, confidence: string}> $ownershipEvidence
     * @param list<array{mechanism: string, detail: string, confidence: string}> $authorizationEvidence
     * @param list<array{kind: string, detail: string, line: int|null}> $trace source → lookup → operation chain
     * @param string $reason calibration bucket (v0.6.1b): for PROTECTED the
     *   proving mechanism; for REVIEW/UNKNOWN one of AUTH_ONLY,
     *   ADMIN_CONTEXT, CUSTOM_MIDDLEWARE, UNRESOLVED_RESOURCE,
     *   UNRESOLVED_PRINCIPAL, AUTHORIZATION_AFTER_SINK; for EXPOSED NO_AUTH
     */
    public function __construct(string $status, string $controller, string $method, string $file, int $line, ?array $route, array $middleware, ?array $identifier, ?array $lookup, ?array $operation, ?array $principal, array $ownershipEvidence, array $authorizationEvidence, string $confidence, array $trace, string $reason = '')
    {
        $this->status = $status;
        $this->controller = $controller;
        $this->method = $method;
        $this->file = $file;
        $this->line = $line;
        $this->route = $route;
        $this->middleware = $middleware;
        $this->identifier = $identifier;
        $this->lookup = $lookup;
        $this->operation = $operation;
        $this->principal = $principal;
        $this->ownershipEvidence = $ownershipEvidence;
        $this->authorizationEvidence = $authorizationEvidence;
        $this->confidence = $confidence;
        $this->trace = $trace;
        $this->reason = $reason;
    }

    /**
     * @return array<string, mixed> sidecar-serializable chain
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'controller' => $this->controller,
            'method' => $this->method,
            'file' => $this->file,
            'line' => $this->line,
            'route' => $this->route,
            'middleware' => $this->middleware,
            'identifier' => $this->identifier,
            'lookup' => $this->lookup,
            'operation' => $this->operation,
            'principal' => $this->principal,
            'ownership_evidence' => $this->ownershipEvidence,
            'authorization_evidence' => $this->authorizationEvidence,
            'confidence' => $this->confidence,
            'trace' => $this->trace,
            'reason' => $this->reason,
        ];
    }
}
