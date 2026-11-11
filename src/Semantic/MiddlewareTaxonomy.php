<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * Middleware taxonomy for access-control decisions.
 *
 * Authentication is not authorization: `auth` (and its guards), token
 * guards and identity-assurance middleware prove *who* calls, never
 * *whether* they may mutate. Only ability checks (`can:*`,
 * `permission:*`, `role:*`, explicitly configured extras) count as
 * authorization evidence. Everything else with a name that *sounds*
 * protective (`admin`, `owner`, `checkLevel`, `signed`, ...) is an
 * unverifiable gate — recorded as evidence for review, never assumed
 * to authorize. Rate limiting (`throttle`), `guest` markers and the
 * framework `web`/`api` groups carry no access meaning at all.
 */
final class MiddlewareTaxonomy
{
    public const AUTHORIZATION = 'authorization';

    public const AUTHENTICATION = 'authentication';

    public const GATE = 'gate';

    public const NONE = 'none';

    /**
     * @param list<string> $extraFragments user-configured
     *   `extra_middleware` fragments — an explicit assertion by the
     *   project owner that these middleware authorize, so they rank as
     *   authorization evidence.
     */
    public static function classify(string $middleware, array $extraFragments = []): string
    {
        $parts = explode(':', $middleware, 2);
        $base = strtolower(trim($parts[0]));
        if ($base === '') {
            return self::NONE;
        }

        // Guest markers route *away* from authenticated users: the route
        // is public by design, never protected (even `guestAdmin`, which
        // merely contains a protective-sounding word).
        if ($base === 'guest' || strncmp($base, 'guest', strlen('guest')) === 0) {
            return self::NONE;
        }

        foreach ($extraFragments as $fragment) {
            if ($fragment !== '' && strpos($base, $fragment) !== false) {
                return self::AUTHORIZATION;
            }
        }

        // Ability checks: Laravel's `can:*` plus the de-facto standard
        // spatie/laravel-permission `permission:*` / `role:*`. The base
        // name (before ':') is compared — the parameter never matters.
        $lower = strtolower(trim($middleware));
        if (
            $base === 'can'
            || strncmp($lower, 'can:', strlen('can:')) === 0
            || $base === 'permission'
            || strncmp($lower, 'permission:', strlen('permission:')) === 0
            || $base === 'role'
            || strncmp($lower, 'role:', strlen('role:')) === 0
        ) {
            return self::AUTHORIZATION;
        }

        // Identity proofs: session guards, token guards, API-key guards,
        // OAuth, and email-verification (identity assurance stacked on
        // top of authentication — never a permission check).
        if (
            $base === 'auth'
            || strncmp($base, 'auth:', strlen('auth:')) === 0
            || $base === 'sanctum'
            || strncmp($base, 'sanctum:', strlen('sanctum:')) === 0
            || $base === 'jwt'
            || strncmp($base, 'jwt:', strlen('jwt:')) === 0
            || strncmp($base, 'jwt.', strlen('jwt.')) === 0
            || $base === 'oauth'
            || strncmp($base, 'oauth:', strlen('oauth:')) === 0
            || $base === 'verified'
            || $base === 'apikey'
            || $base === 'api_key'
            || $base === 'api.key'
            || strpos($base, 'api.key') !== false
            || strpos($base, 'api_key') !== false
            || strpos($base, 'apikey') !== false
        ) {
            return self::AUTHENTICATION;
        }

        // Plumbing with no access meaning: rate limiting, framework
        // default groups, route-model binding.
        if (
            $base === 'throttle'
            || strncmp($base, 'throttle:', strlen('throttle:')) === 0
            || $base === 'web'
            || $base === 'api'
            || $base === 'bindings'
        ) {
            return self::NONE;
        }

        // Anything else (`admin`, `owner`, `checkLevel`, `signed`, ...)
        // *sounds* protective but its implementation is unknown to the
        // engine: evidence for review, never assumed authorization.
        return self::GATE;
    }
}
