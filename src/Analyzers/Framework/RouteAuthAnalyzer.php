<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Framework;

use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Framework\Framework;
use Rampart\Php\Framework\FrameworkProfile;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * Mutating route without a visible authorization marker.
 *
 * Framework-specific and deliberately conservative: it reads route
 * declarations, not controller bodies. Auth is "visible" when a middleware /
 * filter / attribute with an auth-ish name appears on the route, its group, or
 * (Symfony) in the first 40 lines of the action. A route protected only inside
 * the controller will still be reported — Confidence Low, severity Warning, so
 * it is a review hint and never fails a default gate.
 *
 * Supported: Slim 4, CodeIgniter 4, Symfony (attributes + YAML routes with
 * `security.yaml` access_control) and FuelPHP (`before()` in the controller).
 */
final class RouteAuthAnalyzer extends AbstractAnalyzer
{
    public const RULE = 'ROUTE_MISSING_AUTH';

    /**
     * Auth-ish middleware/filter/guard names. Matched only against
     * middleware/filter expressions, never the route path — `/admin/users`
     * is a URI, not an authorization check.
     */
    private const AUTH_NAME_PATTERN = '/(auth|admin|role|permission|jwt|sanctum|passport|polic|acl|guard|can|login|verified|owner)/i';

    private const MUTATING = ['post', 'put', 'patch', 'delete'];

    public function __construct(private readonly FrameworkProfile $profile)
    {
    }

    public function analyze(array $files): array
    {
        return match ($this->profile->framework) {
            Framework::SLIM => $this->analyzeSlim($this->routeFiles()),
            Framework::CODEIGNITER4 => $this->analyzeCodeIgniter($this->routeFiles()),
            Framework::FUELPHP => $this->analyzeFuelPhp($this->routeFiles()),
            Framework::SYMFONY => array_merge(
                $this->analyzeSymfony($files),
                $this->analyzeSymfonyYaml($this->routeFiles())
            ),
            default => [],
        };
    }

    /**
     * @return list<string>
     */
    private function routeFiles(): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }

        return $this->profile->existingRouteFiles($root);
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyzeSlim(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $index => $line) {
                if (preg_match('/(?:\$app|\$group|\$router|\$route)\s*->\s*(get|post|put|patch|delete|any)\s*\(\s*[\'"]([^\'"]+)[\'"]/i', $line, $m) !== 1) {
                    continue;
                }
                if (!$this->isMutating($m[1])) {
                    continue;
                }
                if ($this->hasSlimAuth($lines, $index)) {
                    continue;
                }
                $issues[] = $this->issue($file, $index + 1, strtoupper($m[1]), $m[2], 'Slim route');
            }
        }

        return $issues;
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyzeCodeIgniter(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $index => $line) {
                if (preg_match('/\$routes\s*->\s*(get|post|put|patch|delete|match|resource|presenter|apiresource)\s*\(\s*[\'"]([^\'"]+)[\'"]/i', $line, $m) !== 1) {
                    continue;
                }
                $verb = strtolower($m[1]);
                if (!in_array($verb, self::MUTATING, true) && !in_array($verb, ['match', 'resource', 'presenter', 'apiresource'], true)) {
                    continue;
                }
                if ($this->hasCi4Auth($lines, $index)) {
                    continue;
                }
                $issues[] = $this->issue($file, $index + 1, strtoupper($verb), $m[2], 'CodeIgniter route');
            }
        }

        return $issues;
    }

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyzeSymfony(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (strtolower((string) pathinfo($file, PATHINFO_EXTENSION)) !== 'php') {
                continue;
            }
            $lines = $this->lines($file);
            foreach ($lines as $index => $line) {
                if (preg_match('/#\[Route\([^\]]*methods\s*:\s*\[([^\]]*)\]/i', $line, $m) !== 1) {
                    // Also accept methods passed as a single string.
                    if (preg_match('/#\[Route\([^\]]*methods\s*:\s*[\'"]([^\'"]+)[\'"]/i', $line, $m) !== 1) {
                        continue;
                    }
                }
                $methods = strtoupper($m[1]);
                if (!$this->symfonyMutates($methods)) {
                    continue;
                }
                $window = [];
                for ($i = $index; $i < count($lines) && $i < $index + 40; $i++) {
                    if ($i > $index && preg_match('/#\[Route\(/', $lines[$i]) === 1) {
                        break;
                    }
                    $window[] = $lines[$i];
                }
                if (preg_match('/(#\[IsGranted|denyAccessUnlessGranted|isGranted\s*\()/i', implode("\n", $window)) === 1) {
                    continue;
                }
                $uri = $this->symfonyPath($line);
                $issues[] = $this->issue($file, $index + 1, $methods, $uri, 'Symfony action');
            }
        }

        return $issues;
    }

    private function symfonyMutates(string $methods): bool
    {
        foreach (self::MUTATING as $verb) {
            if (str_contains($methods, strtoupper($verb))) {
                return true;
            }
        }

        return false;
    }

    private function symfonyPath(string $line): string
    {
        if (preg_match('/#\[Route\(\s*[\'"]([^\'"]+)[\'"]/', $line, $m) === 1) {
            return $m[1];
        }

        return '(unknown)';
    }

    private function isMutating(string $verb): bool
    {
        $verb = strtolower($verb);

        return in_array($verb, self::MUTATING, true) || $verb === 'any';
    }

    /**
     * Statement text for the route call, including chained `->add(...)` lines.
     *
     * @param list<string> $lines
     */
    private function statementText(array $lines, int $index): string
    {
        $end = $index;
        while (
            $end + 1 < count($lines)
            && (str_ends_with(rtrim($lines[$end]), '->') || str_starts_with(ltrim($lines[$end + 1]), '->'))
        ) {
            ++$end;
        }

        return implode("\n", array_slice($lines, $index, $end - $index + 1));
    }

    /**
     * Slim: `->add(new AuthMiddleware())` / `->middleware('auth')` on the
     * route itself. Group-level `->add()` after the closure is not followed.
     *
     * @param list<string> $lines
     */
    private function hasSlimAuth(array $lines, int $index): bool
    {
        $statement = $this->statementText($lines, $index);
        if (
            preg_match('/(?:add|middleware)\s*\(/i', $statement) === 1
            && preg_match(self::AUTH_NAME_PATTERN, $statement) === 1
        ) {
            return true;
        }

        // Group form: the middleware is attached after the closure
        // (`})->add(new AdminOnlyMiddleware())`). Only follow the closing
        // brace when a group() declaration appears just above the route.
        $grouped = false;
        $start = max(0, $index - 12);
        for ($i = $start; $i < $index; $i++) {
            if (preg_match('/group\s*\(/i', $lines[$i]) === 1) {
                $grouped = true;
                break;
            }
        }
        if (!$grouped) {
            return false;
        }
        for ($i = $index + 1; $i < count($lines) && $i <= $index + 30; $i++) {
            if (preg_match('/^\s*\}\)\s*->\s*(?:add|middleware)\s*\(/i', $lines[$i]) === 1) {
                return preg_match(self::AUTH_NAME_PATTERN, $lines[$i]) === 1;
            }
            if (preg_match('/^\s*\}\)\s*;/', $lines[$i]) === 1) {
                break;
            }
        }

        return false;
    }

    /**
     * CodeIgniter 4: `['filter' => 'auth']` (or a filter list) on the route.
     * Only the filter value counts; the URI and controller name are ignored.
     *
     * @param list<string> $lines
     */
    private function hasCi4Auth(array $lines, int $index): bool
    {
        $statement = $this->statementText($lines, $index);
        if (preg_match('/[\'"]filter[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]/i', $statement, $m) === 1) {
            return preg_match(self::AUTH_NAME_PATTERN, $m[1]) === 1;
        }

        // Group-level filter declared above the route.
        $start = max(0, $index - 12);
        for ($i = $start; $i < $index; $i++) {
            if (preg_match('/group\s*\(/i', $lines[$i]) !== 1) {
                continue;
            }
            if (
                preg_match('/[\'"]filter[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]/i', $lines[$i], $g) === 1
                && preg_match(self::AUTH_NAME_PATTERN, $g[1]) === 1
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * FuelPHP: `Route::post('uri', 'controller/method')`. Fuel has no route
     * middleware; authorization normally lives in the controller's `before()`.
     * Follow the parent chain up to three levels so a shared
     * `Controller_Base::before()` counts.
     *
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyzeFuelPhp(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            $lines = $this->lines($file);
            foreach ($lines as $index => $line) {
                if (preg_match('/Route::\s*(get|post|put|patch|delete|any)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]/i', $line, $m) !== 1) {
                    continue;
                }
                if (!$this->isMutating($m[1])) {
                    continue;
                }
                if ($this->fuelActionHasAuth($m[3])) {
                    continue;
                }
                $issues[] = $this->issue($file, $index + 1, strtoupper($m[1]), $m[2], 'FuelPHP route');
            }
        }

        return $issues;
    }

    private function fuelActionHasAuth(string $action): bool
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return false;
        }
        $segments = array_values(array_filter(
            explode('/', trim($action, '/')),
            static fn (string $segment): bool => $segment !== ''
        ));
        if ($segments === []) {
            return false;
        }
        if (count($segments) > 1) {
            array_pop($segments);
        }
        $controller = implode('/', $segments);
        if ($controller === '') {
            $controller = (string) ($segments[0] ?? $action);
        }

        $candidates = [$controller, (string) ($segments[0] ?? '')];
        foreach (array_unique($candidates) as $candidate) {
            if ($candidate === '') {
                continue;
            }
            $file = $root . '/fuel/app/classes/controller/' . strtolower($candidate) . '.php';
            if (is_file($file) && $this->fuelControllerHasAuth($file, 0)) {
                return true;
            }
        }

        return false;
    }

    private function fuelControllerHasAuth(string $file, int $depth): bool
    {
        if ($depth > 3) {
            return false;
        }
        $source = $this->sharedSource($file);
        if ($source === '') {
            return false;
        }

        if (preg_match('/function\s+before\s*\([^)]*\)[^{]*\{/i', $source, $m, PREG_OFFSET_CAPTURE) === 1) {
            $start = (int) $m[0][1] + strlen($m[0][0]);
            $body = substr($source, $start, 2000);
            if (preg_match('/(?:\\\\?Auth::|Session::get\s*\(\s*[\'"]user|current_user|is_logged_in|login_required|has_access|permission|role)/i', $body) === 1) {
                return true;
            }
        }

        if (preg_match('/class\s+\w+\s+extends\s+([\\\\\w]+)/i', $source, $cm) === 1) {
            $parent = ltrim($cm[1], '\\');
            $position = strrpos($parent, '\\');
            $short = $position === false ? $parent : substr($parent, $position + 1);
            if (in_array(strtolower($short), ['controller', 'controller_template', 'controller_rest', 'controller_hybrid'], true)) {
                return false;
            }
            if (stripos($short, 'Controller_') === 0) {
                $relative = strtolower(str_replace('_', '/', substr($short, strlen('Controller_'))));
                $root = $this->scanRoot();
                $parentFile = $root !== null
                    ? $root . '/fuel/app/classes/controller/' . $relative . '.php'
                    : dirname($file) . '/' . basename($relative) . '.php';
                if (is_file($parentFile)) {
                    return $this->fuelControllerHasAuth($parentFile, $depth + 1);
                }
            }
        }

        return false;
    }

    /**
     * Symfony YAML routes (`config/routes.yaml`, `config/routes/*.yaml`).
     *
     * Auth is visible when the controller action carries
     * `#[IsGranted]`/`denyAccessUnlessGranted()`/`isGranted()`, or when
     * `security.yaml` `access_control` assigns a `ROLE_*` to the path.
     * `IS_AUTHENTICATED*` is authentication, not authorization, so it does not
     * suppress the finding.
     *
     * @param list<string> $files
     * @return list<Issue>
     */
    private function analyzeSymfonyYaml(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            $ext = strtolower((string) pathinfo($file, PATHINFO_EXTENSION));
            if (!in_array($ext, ['yaml', 'yml'], true)) {
                continue;
            }
            foreach ($this->yamlRouteBlocks($file) as $block) {
                if (!$this->symfonyMutates(strtoupper($block['methods']))) {
                    continue;
                }
                if ($this->symfonyYamlProtected($block['path'], $block['controller'])) {
                    continue;
                }
                $issues[] = $this->issue(
                    $file,
                    $block['line'],
                    strtoupper($block['methods']),
                    $block['path'],
                    'Symfony YAML route'
                );
            }
        }

        return $issues;
    }

    /**
     * @return list<array{path: string, methods: string, controller: string, line: int}>
     */
    private function yamlRouteBlocks(string $file): array
    {
        $lines = $this->lines($file);
        $blocks = [];
        $count = count($lines);
        for ($i = 0; $i < $count; $i++) {
            $line = $lines[$i];
            if (preg_match('/^[A-Za-z0-9_.-]+:\s*\{(.+)\}\s*$/', trim($line), $inline) === 1) {
                if ($this->inlineYamlRoute($inline[1], $i + 1, $blocks)) {
                    continue;
                }
            }
            if (preg_match('/^([A-Za-z0-9_.-]+):\s*$/', $line) !== 1) {
                continue;
            }

            $blockLines = [];
            for ($j = $i + 1; $j < $count; $j++) {
                $next = $lines[$j];
                if (trim($next) !== '' && preg_match('/^[A-Za-z0-9_.-]+:/', $next) === 1) {
                    break;
                }
                $blockLines[] = $next;
            }
            $block = $this->parseYamlRouteBlock($blockLines, $i + 1);
            if ($block !== null) {
                $blocks[] = $block;
            }
        }

        return $blocks;
    }

    /**
     * @param list<array{path: string, methods: string, controller: string, line: int}> $blocks
     */
    private function inlineYamlRoute(string $body, int $line, array &$blocks): bool
    {
        if (preg_match('/path:\s*[\'"]?([^\'",}]+)/', $body, $pm) !== 1) {
            return false;
        }
        $methods = 'GET';
        if (preg_match('/methods:\s*\[([^\]]+)\]/', $body, $mm) === 1) {
            $methods = $mm[1];
        } elseif (preg_match('/methods:\s*[\'"]?([A-Za-z|, ]+)/', $body, $mm) === 1) {
            $methods = $mm[1];
        }
        $controller = '';
        if (preg_match('/_controller:\s*[\'"]?([^\'",}]+)/', $body, $cm) === 1) {
            $controller = trim($cm[1]);
        }
        $blocks[] = [
            'path' => trim($pm[1]),
            'methods' => $methods,
            'controller' => $controller,
            'line' => $line,
        ];

        return true;
    }

    /**
     * @param list<string> $blockLines
     * @return array{path: string, methods: string, controller: string, line: int}|null
     */
    private function parseYamlRouteBlock(array $blockLines, int $line): ?array
    {
        $text = implode("\n", $blockLines);
        if (preg_match('/^\s*path:\s*[\'"]?([^\'"\n#]+)/m', $text, $pm) !== 1) {
            return null;
        }
        $methods = 'GET';
        if (preg_match('/^\s*methods:\s*\[([^\]]+)\]/m', $text, $mm) === 1) {
            $methods = $mm[1];
        } elseif (preg_match('/^\s*methods:\s*[\'"]?([A-Za-z|, ]+)[\'"]?\s*$/m', $text, $mm) === 1) {
            $methods = $mm[1];
        } elseif (
            preg_match('/^\s*methods:\s*$/m', $text) === 1
            && preg_match_all('/^\s*-\s*([A-Za-z]+)\s*$/m', $text, $list) > 0
        ) {
            $methods = implode(',', $list[1]);
        }
        $controller = '';
        if (preg_match('/^\s*_controller:\s*[\'"]?([^\'"\n#]+)/m', $text, $cm) === 1) {
            $controller = trim($cm[1]);
        }

        return [
            'path' => trim($pm[1]),
            'methods' => $methods,
            'controller' => $controller,
            'line' => $line,
        ];
    }

    private function symfonyYamlProtected(string $path, string $controller): bool
    {
        if ($controller !== '' && $this->symfonyControllerHasAuth($controller)) {
            return true;
        }

        foreach ($this->symfonyAccessControl() as $rule) {
            if (!$this->symfonyPathMatches($rule['pattern'], $path)) {
                continue;
            }
            foreach ($rule['roles'] as $role) {
                if (stripos($role, 'ROLE_') === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<array{pattern: string, roles: list<string>}>
     */
    private function symfonyAccessControl(): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $files = [
            $root . '/config/packages/security.yaml',
            $root . '/config/packages/security.yml',
            $root . '/config/security.yaml',
            $root . '/config/security.yml',
        ];

        $rules = [];
        foreach ($files as $file) {
            if (!is_file($file)) {
                continue;
            }
            $source = $this->sharedSource($file);
            if ($source === '') {
                continue;
            }
            if (preg_match('/^([ \t]*)access_control:[ \t]*$/m', $source, $m, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }
            $indent = strlen($m[1][0]);
            $offset = (int) $m[0][1] + strlen($m[0][0]);
            $sectionLines = [];
            foreach (explode("\n", substr($source, $offset)) as $line) {
                if (trim($line) !== '' && preg_match('/^([ \t]*)/', $line, $im) === 1 && strlen($im[1]) <= $indent) {
                    break;
                }
                $sectionLines[] = $line;
            }
            $section = implode("\n", $sectionLines);
            foreach (preg_split('/^[ \t]*-[ \t]+/m', $section) ?: [] as $chunk) {
                $chunk = trim(trim($chunk), '{} ');
                if ($chunk === '' || preg_match('/path:\s*[\'"]?([^\'"\n,}]+)/', $chunk, $pm) !== 1) {
                    continue;
                }
                $roles = [];
                if (preg_match('/roles:\s*\[([^\]]*)\]/', $chunk, $rm) === 1) {
                    $roles = $this->splitRoles($rm[1]);
                } elseif (preg_match('/roles:\s*([^\n]+)/', $chunk, $rm) === 1) {
                    $roles = $this->splitRoles($rm[1]);
                }
                $rules[] = ['pattern' => trim($pm[1]), 'roles' => $roles];
            }
        }

        return $rules;
    }

    /**
     * @return list<string>
     */
    private function splitRoles(string $roles): array
    {
        $roles = trim($roles, " \t\n\r\0\x0B[]{}'\"");
        $parts = preg_split('/[,\s]+/', $roles) ?: [];

        return array_values(array_filter(array_map(
            static fn (string $role): string => trim($role, "[]{}'\""),
            $parts
        ), static fn (string $role): bool => $role !== ''));
    }

    private function symfonyPathMatches(string $pattern, string $path): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '') {
            return false;
        }
        $result = @preg_match('#' . str_replace('#', '\\#', $pattern) . '#', $path);
        if ($result === 1) {
            return true;
        }
        if ($result === false) {
            $literal = trim($pattern, '^$');

            return $literal !== '' && str_starts_with($path, $literal);
        }

        return false;
    }

    private function symfonyControllerHasAuth(string $controller): bool
    {
        $controller = trim($controller, " \t\n\r\0\x0B'\"");
        $parts = preg_split('/::|:/', $controller, 2);
        if (!is_array($parts) || count($parts) < 2) {
            return false;
        }
        $class = ltrim($parts[0], '\\');
        $method = $parts[1];
        $root = $this->scanRoot();
        if ($root === null) {
            return false;
        }

        $relative = str_replace('\\', '/', $class);
        $candidates = [
            $root . '/src/' . preg_replace('#^App/#', '', $relative) . '.php',
            $root . '/' . $relative . '.php',
            $root . '/src/' . basename($relative) . '.php',
        ];
        foreach (array_unique($candidates) as $file) {
            if (!is_file($file)) {
                continue;
            }
            $source = $this->sharedSource($file);
            if ($source === '') {
                continue;
            }
            $offset = strpos($source, 'function ' . $method . '(');
            if ($offset === false) {
                continue;
            }
            $window = $this->methodWindow($source, $offset);
            if (preg_match('/#\[IsGranted|denyAccessUnlessGranted|isGranted\s*\(/i', $window) === 1) {
                return true;
            }
            $classPosition = strpos($source, 'class ');
            if ($classPosition !== false && preg_match('/#\[IsGranted/i', substr($source, 0, $classPosition)) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * The method body plus the few lines above it (attributes live there).
     * Brace matching is deliberately simple: it only has to be good enough to
     * keep a neighbouring method's `#[IsGranted]` out of this action's window.
     */
    private function methodWindow(string $source, int $offset): string
    {
        $start = max(0, $offset - 300);
        $brace = strpos($source, '{', $offset);
        if ($brace === false) {
            return substr($source, $start, 3000);
        }

        $depth = 0;
        $length = strlen($source);
        $end = $length - 1;
        for ($i = $brace; $i < $length; $i++) {
            if ($source[$i] === '{') {
                ++$depth;
            } elseif ($source[$i] === '}') {
                --$depth;
                if ($depth === 0) {
                    $end = $i;
                    break;
                }
            }
        }

        return substr($source, $start, max(0, $end - $start + 1));
    }

    /**
     * @return list<string>
     */
    private function lines(string $file): array
    {
        $source = $this->sharedSource($file);
        if ($source === '') {
            return [];
        }

        return explode("\n", str_replace(["\r\n", "\r"], "\n", $source));
    }

    private function issue(string $file, int $line, string $method, string $uri, string $kind): Issue
    {
        return $this->makeIssue(
            self::RULE,
            sprintf(
                '%s "%s %s" mutates data with no visible authorization middleware/attribute. Confirm a policy or auth check protects it.',
                $kind,
                $method,
                $uri
            ),
            $file,
            $line,
            Severity::Warning,
            ['method' => $method, 'uri' => $uri, 'framework' => $this->profile->framework->value],
            Confidence::Low
        );
    }
}
