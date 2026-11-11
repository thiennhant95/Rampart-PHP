<?php

declare(strict_types=1);

namespace Rampart\Php\Semantic;

/**
 * One resolved route: which controller action answers which HTTP
 * method(s) at which URI, under which middleware stack, and where it
 * was declared. This IS the evidence unit — never a bare boolean:
 * consumers can cite file/line and middleware instead of guessing.
 *
 * Unknown stays unknown: a dynamic URI or action resolves to null
 * rather than a guess.
 */
final class RouteNode
{
    /**
     * @var list<string>
     * @readonly
     */
    public array $methods;
    /**
     * @readonly
     */
    public ?string $uri;
    /**
     * @readonly
     */
    public ?string $controller;
    /**
     * @readonly
     */
    public ?string $action;
    /**
     * @var list<string>
     * @readonly
     */
    public array $middleware;
    /**
     * @readonly
     */
    public string $file;
    /**
     * @readonly
     */
    public ?int $line;
    /**
     * @param list<string> $methods lowercase HTTP verbs
     * @param list<string> $middleware middleware stack, outermost first
     */
    public function __construct(array $methods, ?string $uri, ?string $controller, ?string $action, array $middleware, string $file, ?int $line)
    {
        $this->methods = $methods;
        $this->uri = $uri;
        $this->controller = $controller;
        $this->action = $action;
        $this->middleware = $middleware;
        $this->file = $file;
        $this->line = $line;
    }
}
