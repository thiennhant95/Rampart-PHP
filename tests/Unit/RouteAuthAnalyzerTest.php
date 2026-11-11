<?php

declare(strict_types=1);

namespace Rampart\Php\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\Php\Analyzers\Framework\RouteAuthAnalyzer;
use Rampart\Php\Framework\Framework;
use Rampart\Php\Framework\FrameworkProfile;
use Rampart\Php\Scanning\ScanContext;

final class RouteAuthAnalyzerTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rampart-route-' . uniqid('', true);
        @mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($this->dir);
    }

    private function write(string $relative, string $code): string
    {
        $path = $this->dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $code);

        return $path;
    }

    /**
     * @param list<string> $files
     * @return list<string>
     */
    private function analyze(Framework $framework, array $files): array
    {
        $analyzer = new RouteAuthAnalyzer(FrameworkProfile::for($framework));
        $scan = new ScanContext();
        $scan->setBasePath($this->dir);
        $analyzer->setScanContext($scan);

        $rules = [];
        foreach ($analyzer->analyze($files) as $issue) {
            $rules[] = $issue->rule;
        }

        return $rules;
    }

    public function testSlimRouteWithoutAuthIsReported(): void
    {
        $file = $this->write('routes/routes.php', <<<'PHP'
<?php
use Slim\App;
return function (App $app) {
    $app->post('/admin/users', [AdminController::class, 'store']);
    $app->post('/safe/users', [AdminController::class, 'store'])->add(new AuthMiddleware());
};
PHP);

        $rules = $this->analyze(Framework::SLIM, [$file]);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
    }

    public function testSlimGroupAuthAfterClosureIsHonored(): void
    {
        $file = $this->write('routes/routes.php', <<<'PHP'
<?php
use Slim\App;
return function (App $app) {
    $app->group('/admin', function ($group) {
        $group->delete('/users/{id}', [AdminController::class, 'destroy']);
    })->add(new AdminOnlyMiddleware());
};
PHP);

        self::assertSame([], $this->analyze(Framework::SLIM, [$file]));
    }

    public function testCodeIgniterFilterIsHonored(): void
    {
        $file = $this->write('app/Config/Routes.php', <<<'PHP'
<?php
$routes->post('admin/users', 'Admin::store');
$routes->post('safe/users', 'Admin::store', ['filter' => 'auth']);
PHP);

        $rules = $this->analyze(Framework::CODEIGNITER4, [$file]);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
    }

    public function testSymfonyIsGrantedIsHonored(): void
    {
        $file = $this->write('src/Controller/AdminController.php', <<<'PHP'
<?php
namespace App\Controller;

class AdminController
{
    #[Route('/admin/users', methods: ['POST'])]
    public function store()
    {
        return null;
    }

    #[Route('/safe/users', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function safeStore()
    {
        return null;
    }
}
PHP);

        $rules = $this->analyze(Framework::SYMFONY, [$file]);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
    }

    public function testGetRoutesAreNeverReported(): void
    {
        $file = $this->write('routes/routes.php', <<<'PHP'
<?php
$app->get('/health', function ($request, $response) { return $response; });
PHP);

        self::assertSame([], $this->analyze(Framework::SLIM, [$file]));
    }

    public function testFuelPhpControllerWithoutBeforeAuthIsReported(): void
    {
        $this->write('fuel/app/config/routes.php', <<<'PHP'
<?php
Route::post('admin/users', 'admin/users');
PHP);
        $this->write('fuel/app/classes/controller/admin.php', <<<'PHP'
<?php
class Controller_Admin extends Controller
{
    public function users()
    {
        return 'ok';
    }
}
PHP);

        $rules = $this->analyze(Framework::FUELPHP, []);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
    }

    public function testFuelPhpBeforeAuthProtectsTheRoute(): void
    {
        $this->write('fuel/app/config/routes.php', <<<'PHP'
<?php
Route::post('admin/users', 'admin/users');
PHP);
        $this->write('fuel/app/classes/controller/admin.php', <<<'PHP'
<?php
class Controller_Admin extends Controller
{
    public function before()
    {
        if (!Auth::check()) {
            Response::redirect('login');
        }
    }

    public function users()
    {
        return 'ok';
    }
}
PHP);

        self::assertSame([], $this->analyze(Framework::FUELPHP, []));
    }

    public function testFuelPhpParentBeforeAuthProtectsTheRoute(): void
    {
        $this->write('fuel/app/config/routes.php', <<<'PHP'
<?php
Route::post('admin/users', 'admin/users');
PHP);
        $this->write('fuel/app/classes/controller/base.php', <<<'PHP'
<?php
class Controller_Base extends Controller
{
    public function before()
    {
        if (!Auth::check()) {
            Response::redirect('login');
        }
    }
}
PHP);
        $this->write('fuel/app/classes/controller/admin.php', <<<'PHP'
<?php
class Controller_Admin extends Controller_Base
{
    public function users()
    {
        return 'ok';
    }
}
PHP);

        self::assertSame([], $this->analyze(Framework::FUELPHP, []));
    }

    public function testSymfonyYamlRouteWithoutAuthIsReported(): void
    {
        $this->write('config/routes.yaml', <<<'YAML'
admin_users:
    path: /admin/users
    methods: [POST]
    _controller: App\Controller\AdminController::store

safe_users:
    path: /safe/users
    methods: [POST]
    _controller: App\Controller\AdminController::safeStore
YAML);
        $this->write('src/Controller/AdminController.php', <<<'PHP'
<?php
namespace App\Controller;

class AdminController
{
    public function store()
    {
        return null;
    }

    #[\Symfony\Component\Security\Http\Attribute\IsGranted('ROLE_ADMIN')]
    public function safeStore()
    {
        return null;
    }
}
PHP);

        $rules = $this->analyze(Framework::SYMFONY, []);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
    }

    public function testSymfonyAccessControlProtectsMatchingPath(): void
    {
        $this->write('config/routes.yaml', <<<'YAML'
admin_users:
    path: /admin/users
    methods: POST
    _controller: App\Controller\AdminController::store

public_users:
    path: /public/users
    methods: POST
    _controller: App\Controller\AdminController::store
YAML);
        $this->write('config/packages/security.yaml', <<<'YAML'
security:
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
YAML);
        $this->write('src/Controller/AdminController.php', <<<'PHP'
<?php
namespace App\Controller;

class AdminController
{
    public function store()
    {
        return null;
    }
}
PHP);

        $rules = $this->analyze(Framework::SYMFONY, []);

        self::assertSame(['ROUTE_MISSING_AUTH'], $rules);
        self::assertSame(1, count($rules), 'only /public/users should be reported');
    }
}
