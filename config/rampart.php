<?php

return [
    // Framework layout: auto | plain | slim | codeigniter4 | fuelphp | symfony | laravel
    // "auto" reads composer.json and marker files, never boots the app.
    'framework' => 'auto',

    // Empty means "use the detected framework's default paths". Set explicitly
    // to override, e.g. ['src', 'web', 'tests'].
    'paths' => [],

    // Checkers to skip, merged with --exclude.
    'exclude' => [],

    // Never install anything into the target. The standalone binary is
    // read-only by default; opt in per run only if you trust the project.
    'auto_install_tools' => false,

    'tier' => 'quality',
    'min_confidence' => 'low',
    'min_severity' => 'info',

    'phpcs' => [
        'standard' => 'PSR12',
        'severity' => 0,
    ],

    'phpstan' => [
        'level' => 6,
        'memoryLimit' => '1G',
    ],

    'phpunit' => [
        'testsuite' => null,
        'coverageThreshold' => 60,
    ],

    'composer_audit' => [
        'enabled' => true,
    ],

    'npm_audit' => [
        'enabled' => true,
    ],

    'trivy' => [
        'enabled' => false,
        'mode' => 'config',
        'binary' => 'trivy',
        'version' => '0.74.0',
    ],

    'cache' => [
        'enabled' => true,
        'ttl' => 3600,
    ],

    'analyzers' => [
        'enabled' => true,
        'inline_suppression' => true,

        // Framework-agnostic security rules: on by default.
        'security' => [
            'sql_injection' => true,
            'unsafe_eval' => true,
            'hardcoded_secret' => true,
            'mass_assignment' => true,
            'unsafe_unserialize' => true,
            'insecure_hash' => true,
            'insecure_cookie' => true,
            'auth_hardening' => true,
            'laravel_taint' => true,
            'disabled_csrf' => true,
            // Only index.php in public/ is a Laravel convention. In plain PHP
            // and other frameworks public/*.php entrypoints are normal, so this
            // forensic rule is opt-in.
            'rogue_php' => false,
            'obfuscated' => true,
            'xss_echo' => true,
            'insecure_random' => true,
            'dangerous_function' => true,
            'header_injection' => true,
            'ldap_injection' => true,
            'weak_crypto' => true,
            'insecure_session' => true,
            // Low-confidence hint (CLI scripts legitimately dump variables).
            'debug_output' => false,
            'taint_engine' => false,
        ],

        // Generic sinks + Laravel semantic rules (Laravel-only ones no-op
        // elsewhere). All on by default; disable per rule to focus.
        'owasp' => [
            'broken_access_control' => true,
            'route_middleware' => true,
            'blade_xss' => true,
            'open_redirect' => true,
            'path_traversal' => true,
            'ssrf' => true,
            'ssti' => true,
            'misconfiguration' => true,
            'command_injection' => true,
            'xxe' => true,
            'ownership_idor' => true,
        ],

        // Framework routing: mutating route without visible auth marker.
        'framework' => [
            'route_auth' => true,
        ],

        'laravel' => [
            'migration' => true,
            'route_validation' => true,
        ],

        // Backlog noise on most codebases: opt in with --coverage.
        'test_coverage' => [
            'unified' => false,
            'missing_controller_test' => false,
            'missing_service_test' => false,
            'missing_model_test' => false,
            'missing_feature_coverage' => false,
            'test_without_assert' => false,
        ],

        'convention' => [
            'naming_convention' => false,
            'todo_fixme' => false,
            'dead_code' => false,
            'laravel_pitfall' => false,
        ],

        'frontend' => [
            'js_syntax' => true,
            'css_syntax' => true,
            'blade_stack' => true,
        ],

        'ops' => [
            'perms' => true,
            'eol' => true,
        ],

        'models_dirs' => ['app/Models'],
        'extra_middleware' => [],
        'extra_sanitizers' => [],

        'severity_overrides' => [
            'OWASP_BLADE_DYNAMIC_INCLUDE' => 'info',
        ],

        'max_file_kb' => 1024,

        // Fixtures exist to be vulnerable. Matched against the whole path,
        // case-insensitive; every excluded file is counted in the summary.
        'exclude_paths' => ['*/fixtures/*'],
    ],

    'remediation' => true,
    'fail_on' => 'error',

    'quality_gate' => [
        'ignore' => [],
    ],

    'output_dir' => 'reports/rampart',

    'html' => [
        'repo_url' => null,
        'branch' => 'main',
        'code_context' => 3,
        'client_brand' => 'RAMPART',
        'client_project' => null,
    ],
];
