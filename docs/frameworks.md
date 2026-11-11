# Framework detection

Rampart never boots the framework. It reads `composer.json` and a few marker
files, then chooses a layout (`FrameworkProfile`) that tells the collectors
where source, routes, views, tests and public files live.

## Detection order

1. `--framework=<name>` (or `framework` in `config/rampart.php`) — wins.
2. `composer.json` `require` / `require-dev` packages.
3. Marker files.
4. **Plain PHP** fallback.

| Framework | Composer package | Markers |
|---|---|---|
| Slim 4 | `slim/slim`, `slim/psr7` | `Slim` referenced from `public/index.php` |
| CodeIgniter 4 | `codeigniter4/framework`, `codeigniter4/appstarter` | `spark` + `app/Config/` |
| FuelPHP | `fuel/fuel`, `fuelphp/fuel` | `fuel/app/` |
| Symfony | `symfony/framework-bundle`, `symfony/symfony` | `config/bundles.php`, `src/Kernel.php` |
| Phalcon | `phalcon/cphalcon`, `phalcon/incubator` | `app/controllers/` + `public/index.php` referencing Phalcon |
| Laravel | `laravel/framework` | `routes/` + `app/Http/` |

## Layouts

| Framework | Scan paths | Route files | Views |
|---|---|---|---|
| Plain | `src`, `app`, `lib`, `includes`, `inc`, `public`, `tests` | — | `templates`, `views`, `public/views`, `resources/views` |
| Slim | `src`, `app`, `routes`, `config`, `tests` | `routes/*.php`, `public/index.php` | `templates`, `views`, `resources/views` |
| CodeIgniter 4 | `app`, `tests` | `app/Config/Routes.php`, `app/Config/*Routes*.php` | `app/Views` |
| FuelPHP | `fuel/app`, `fuel/core` | `fuel/app/config/routes.php` | `fuel/app/views` |
| Symfony | `src`, `config`, `templates`, `tests` | `config/routes.php`, `config/routes.yaml`, `config/routes/*` | `templates`, `views` |
| Phalcon | `app`, `src`, `config`, `tests` | `app/config/routes.php`, `app/config/router.php`, `public/index.php` | `app/views`, `views` |
| Laravel | `app`, `routes`, `database`, `config`, `tests` | `routes/*.php` | `resources/views` |

`--path=` overrides the scan paths; route and view collection still follows the
profile. `--exclude-path=` (or `analyzers.exclude_paths`) filters files from
both.

## Route authorization

`ROUTE_MISSING_AUTH` is a low-confidence hint for state-changing routes:

- **Slim** — `->add(new AuthMiddleware())` / `->middleware('auth')` on the route
  or on a group closure (`})->add(...)`).
- **CodeIgniter 4** — `['filter' => 'auth']` on the route or group.
- **FuelPHP** — the controller's `before()` (including a parent
  `Controller_Base::before()`) contains `Auth::`, `Session::get('user')`,
  `current_user`, `is_logged_in`, `login_required`, `has_access` or a
  role/permission check. Routes are resolved from
  `fuel/app/config/routes.php` to
  `fuel/app/classes/controller/<controller>.php` (parent chain up to 3 levels).
- **Symfony** — attributes: `#[IsGranted]`, `denyAccessUnlessGranted()` or
  `isGranted()` in the action. YAML: `config/routes*.yaml`, where a route is
  protected by a controller action check **or** by a matching
  `config/packages/security.yaml` `access_control` rule granting a `ROLE_*`.
  `IS_AUTHENTICATED*` counts as authentication, not authorization.
- **Phalcon** — the route target (`Admin::store`) is resolved to
  `app/controllers/AdminController.php`; `beforeExecuteRoute()` /
  `beforeDispatch()` / `initialize()` / `onConstruct()` containing
  `Acl`/`isAllowed`, `Auth::`, `currentUser`, role or permission checks counts
  as auth. The parent chain (`ControllerBase`) is followed up to 3 levels.
  `$router->add(...)->via(['POST'])` and `addPost()` are both understood.

Only `POST` / `PUT` / `PATCH` / `DELETE` (and Slim/FuelPHP/Phalcon `any`) are
considered. Auth is matched on middleware/filter names, never on the URI, so
`/admin/users` without a middleware is still reported.
