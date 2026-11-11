<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers;

use Rampart\Php\Analyzers\Convention\DeadCodeAnalyzer;
use Rampart\Php\Analyzers\Convention\LaravelPitfallAnalyzer;
use Rampart\Php\Analyzers\Convention\NamingConventionAnalyzer;
use Rampart\Php\Analyzers\Convention\TodoFixmeAnalyzer;
use Rampart\Php\Analyzers\Framework\RouteAuthAnalyzer;
use Rampart\Php\Analyzers\Frontend\BladeStackAnalyzer;
use Rampart\Php\Analyzers\Frontend\CssSyntaxAnalyzer;
use Rampart\Php\Analyzers\Frontend\JsSyntaxAnalyzer;
use Rampart\Php\Analyzers\Laravel\MigrationAnalyzer;
use Rampart\Php\Analyzers\Laravel\RouteValidationAnalyzer;
use Rampart\Php\Analyzers\Ops\EolAnalyzer;
use Rampart\Php\Analyzers\Ops\PermsAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspOwnershipAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspSsrfAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspSstiAnalyzer;
use Rampart\Php\Analyzers\Owasp\OwaspXxeAnalyzer;
use Rampart\Php\Analyzers\Security\AuthHardeningAnalyzer;
use Rampart\Php\Analyzers\Security\DangerousFunctionAnalyzer;
use Rampart\Php\Analyzers\Security\DebugOutputAnalyzer;
use Rampart\Php\Analyzers\Security\DisabledCsrfAnalyzer;
use Rampart\Php\Analyzers\Security\HardcodedSecretAnalyzer;
use Rampart\Php\Analyzers\Security\HeaderInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureCookieAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureHashAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureRandomAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureSessionAnalyzer;
use Rampart\Php\Analyzers\Security\LaravelTaintAnalyzer;
use Rampart\Php\Analyzers\Security\LdapInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\ObfuscatedAnalyzer;
use Rampart\Php\Analyzers\Security\RoguePhpAnalyzer;
use Rampart\Php\Analyzers\Security\SqlInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\UnsafeDeserializationAnalyzer;
use Rampart\Php\Analyzers\Security\UnsafeEvalAnalyzer;
use Rampart\Php\Analyzers\Security\WeakCryptoAnalyzer;
use Rampart\Php\Analyzers\Security\XssEchoAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\ControllerTestAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\FeatureTestAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\MissingTestAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\TestCoverageAnalyzer;
use Rampart\Php\Analyzers\TestCoverage\TestWithoutAssertAnalyzer;
use Rampart\Php\Framework\FrameworkProfile;

/**
 * Single place that turns config flags into analyzer instances.
 *
 * The Laravel-only analyzers stay registered so a Laravel target keeps full
 * parity, but they are keyed separately (`laravel.*`, `owasp.access_control`)
 * and only emit when the semantic index actually finds Laravel constructs.
 * Framework-agnostic rules are the ones enabled by default for every profile.
 */
final class AnalyzerRegistry
{
    /**
     * @param array<string, mixed> $analyzers config['analyzers']
     * @return list<array{enabled: bool, analyzer: object}>
     */
    public static function build(array $analyzers, FrameworkProfile $profile): array
    {
        $isLaravel = $profile->framework->value === 'laravel';

        return [
            // --- Framework-agnostic security (default on) -------------------
            self::entry($analyzers, 'security.sql_injection', new SqlInjectionAnalyzer()),
            self::entry($analyzers, 'security.unsafe_eval', new UnsafeEvalAnalyzer()),
            self::entry($analyzers, 'security.hardcoded_secret', new HardcodedSecretAnalyzer()),
            self::entry($analyzers, 'security.unsafe_unserialize', new UnsafeDeserializationAnalyzer()),
            self::entry($analyzers, 'security.insecure_hash', new InsecureHashAnalyzer()),
            self::entry($analyzers, 'security.insecure_cookie', new InsecureCookieAnalyzer()),
            self::entry($analyzers, 'security.rogue_php', new RoguePhpAnalyzer()),
            self::entry($analyzers, 'security.obfuscated', new ObfuscatedAnalyzer()),
            self::entry($analyzers, 'security.xss_echo', new XssEchoAnalyzer()),
            self::entry($analyzers, 'security.insecure_random', new InsecureRandomAnalyzer()),
            self::entry($analyzers, 'security.dangerous_function', new DangerousFunctionAnalyzer()),
            self::entry($analyzers, 'security.header_injection', new HeaderInjectionAnalyzer()),
            self::entry($analyzers, 'security.ldap_injection', new LdapInjectionAnalyzer()),
            self::entry($analyzers, 'security.weak_crypto', new WeakCryptoAnalyzer()),
            self::entry($analyzers, 'security.insecure_session', new InsecureSessionAnalyzer()),
            self::entry($analyzers, 'security.debug_output', new DebugOutputAnalyzer()),

            // --- OWASP (generic sinks; work on any framework) ---------------
            self::entry($analyzers, 'owasp.command_injection', new OwaspCommandInjectionAnalyzer()),
            self::entry($analyzers, 'owasp.path_traversal', new OwaspPathTraversalAnalyzer()),
            self::entry($analyzers, 'owasp.ssrf', new OwaspSsrfAnalyzer()),
            self::entry($analyzers, 'owasp.ssti', new OwaspSstiAnalyzer()),
            self::entry($analyzers, 'owasp.open_redirect', new OwaspOpenRedirectAnalyzer()),
            self::entry($analyzers, 'owasp.misconfiguration', new OwaspMisconfigurationAnalyzer()),
            self::entry($analyzers, 'owasp.xxe', new OwaspXxeAnalyzer()),
            self::laravelEntry($analyzers, 'owasp.blade_xss', new OwaspBladeXssAnalyzer(
                ['extra_sanitizers' => $analyzers['extra_sanitizers'] ?? []]
            ), $isLaravel),

            // --- Framework routing (profile-aware) --------------------------
            self::entry($analyzers, 'framework.route_auth', new RouteAuthAnalyzer($profile)),

            // --- Laravel-only semantics (no-op elsewhere) -------------------
            self::laravelEntry($analyzers, 'security.mass_assignment', new \Rampart\Php\Analyzers\Security\MassAssignmentAnalyzer(
                ['models_dirs' => $analyzers['models_dirs'] ?? ['app/Models']]
            ), $isLaravel),
            self::laravelEntry($analyzers, 'security.auth_hardening', new AuthHardeningAnalyzer(), $isLaravel),
            self::laravelEntry($analyzers, 'security.disabled_csrf', new DisabledCsrfAnalyzer(), $isLaravel),
            self::laravelEntry($analyzers, 'security.laravel_taint', new LaravelTaintAnalyzer(), $isLaravel),
            self::laravelEntry($analyzers, 'owasp.broken_access_control', new OwaspAccessControlAnalyzer(
                (bool) ($analyzers['owasp']['route_middleware'] ?? true),
                ['extra_middleware' => $analyzers['extra_middleware'] ?? []]
            ), $isLaravel),
            self::laravelEntry($analyzers, 'owasp.ownership_idor', new OwaspOwnershipAnalyzer(), $isLaravel),
            self::laravelEntry($analyzers, 'laravel.migration', new MigrationAnalyzer(), $isLaravel),
            self::laravelEntry($analyzers, 'laravel.route_validation', new RouteValidationAnalyzer(), $isLaravel),

            // --- Test coverage / convention / frontend / ops -----------------
            self::entry($analyzers, 'test_coverage.missing_controller_test', new ControllerTestAnalyzer()),
            self::entry($analyzers, 'test_coverage.missing_service_test', new MissingTestAnalyzer(['services', 'repositories'])),
            self::entry($analyzers, 'test_coverage.missing_model_test', new MissingTestAnalyzer(['models'])),
            self::entry($analyzers, 'test_coverage.missing_feature_coverage', new FeatureTestAnalyzer()),
            self::entry($analyzers, 'test_coverage.test_without_assert', new TestWithoutAssertAnalyzer()),
            self::entry($analyzers, 'test_coverage.unified', new TestCoverageAnalyzer()),
            self::entry($analyzers, 'convention.naming_convention', new NamingConventionAnalyzer()),
            self::entry($analyzers, 'convention.todo_fixme', new TodoFixmeAnalyzer()),
            self::entry($analyzers, 'convention.dead_code', new DeadCodeAnalyzer()),
            self::laravelEntry($analyzers, 'convention.laravel_pitfall', new LaravelPitfallAnalyzer(), $isLaravel),
            self::entry($analyzers, 'frontend.js_syntax', new JsSyntaxAnalyzer()),
            self::entry($analyzers, 'frontend.css_syntax', new CssSyntaxAnalyzer()),
            self::laravelEntry($analyzers, 'frontend.blade_stack', new BladeStackAnalyzer(), $isLaravel),
            self::entry($analyzers, 'ops.perms', new PermsAnalyzer()),
            self::entry($analyzers, 'ops.eol', new EolAnalyzer()),
        ];
    }

    /**
     * Laravel-only analyzers stay silent on other frameworks. Their rules are
     * bound to Eloquent/Blade/middleware semantics; running them on Phalcon or
     * plain PHP produced "mutating method without authorize()" false positives.
     *
     * @param array<string, mixed> $analyzers
     * @return array{enabled: bool, analyzer: object}
     */
    private static function laravelEntry(array $analyzers, string $key, object $analyzer, bool $isLaravel): array
    {
        $parts = explode('.', $key);
        $group = $parts[0];
        $rule = $parts[1];
        $configured = (bool) ($analyzers[$group][$rule] ?? false);

        return [
            'enabled' => $isLaravel && $configured,
            'analyzer' => $analyzer,
        ];
    }

    /**
     * @param array<string, mixed> $analyzers
     * @return array{enabled: bool, analyzer: object}
     */
    private static function entry(array $analyzers, string $key, object $analyzer, ?bool $enabled = null): array
    {
        $parts = explode('.', $key);
        $group = $parts[0];
        $rule = $parts[1];

        return [
            'enabled' => $enabled ?? (bool) ($analyzers[$group][$rule] ?? false),
            'analyzer' => $analyzer,
        ];
    }
}
