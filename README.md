# MonkeysLegion Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP Version](https://img.shields.io/badge/php-%5E8.4-8892BF)
![Version](https://img.shields.io/badge/version-2.0-brightgreen)
![Tests](https://img.shields.io/badge/tests-182%20passed-success)
![PSR](https://img.shields.io/badge/PSR-7%20|%2011%20|%2014%20|%2015%20|%2016%20|%2017-blue)

**MonkeysLegion** is a high-performance, attribute-first PHP 8.4+ framework built for modern web applications and APIs. It leverages PHP 8.4 property hooks, strict types, and compiled DI to deliver a developer experience that rivals Laravel and Symfony — with zero runtime compromise.

---

## 🚀 What's New in v2.0

- **PHP 8.4 Property Hooks** — Native getters/setters via property hooks across all packages
- **Attribute-First Architecture** — Routes, validation, providers, and commands discovered via attributes
- **MLC Configuration** — `.mlc` file format with env interpolation, cascading, and production compilation
- **Compiled DI Container** — Zero-overhead production builds with atomic cache writes
- **26 Integrated Packages** — Every component pinned to v2.0+ for API consistency
- **PSR-15 Middleware Pipeline** — Native security headers, CORS, rate limiting, CSRF, and request ID
- **Apex AI/ML** — Built-in AI provider abstraction with OpenAI, cost tracking, and embeddings
- **182-Test Suite** — Comprehensive PHPUnit 11 test coverage across all framework layers

---

## ✨ Features

| Category | Details |
|---|---|
| **🎯 PSR Compliant** | PSR-7, PSR-11, PSR-14, PSR-15, PSR-16, PSR-17 |
| **🔧 Modular** | 26 independent, composable packages |
| **🔐 Auth** | JWT, OAuth2, 2FA, API Keys, RBAC, Policies, remember-me |
| **🗄️ Database** | Connection manager, QueryBuilder, migrations, entity scanner |
| **🎨 Templates** | Custom engine with caching, layouts, and directives |
| **🌐 Routing** | Attribute-based, auto-discovered, grouped, middleware-aware |
| **⚡ DI** | PSR-11 container with compiled cache for production |
| **📝 Validation** | Attribute-based validation with DTO binding |
| **🌍 I18n** | Multi-language with database and file loaders |
| **📧 Mail** | SMTP and API-based email delivery |
| **📊 Telemetry** | OpenTelemetry-compatible metrics, tracing, and structured logging |
| **🎪 Events** | PSR-14 event dispatcher with listener auto-discovery |
| **💾 Cache** | Redis, file, in-memory backends (PSR-16) |
| **📨 Queue** | Background job processing with workers and retry |
| **📁 Files** | Unified storage, image processing, garbage collection |
| **📚 OpenAPI** | Auto-generated API docs from route attributes |
| **🤖 AI/ML** | Apex: OpenAI provider, cost tracking, embeddings |
| **🔄 CLI** | Attribute-discovered commands, schedule, dev-server |
| **🛡️ Security** | OWASP headers, CORS, rate limiting, CSRF, maintenance mode |

---

## 📦 Included Packages

| Package | Version | Description |
|---|---|---|
| `monkeyslegion-core` | ^2.0 | Core utilities, helpers, and base contracts |
| `monkeyslegion-di` | ^2.0 | PSR-11 dependency injection container |
| `monkeyslegion-http` | ^2.0 | PSR-7/PSR-15/PSR-17 HTTP layer and security middleware |
| `monkeyslegion-router` | ^2.1 | Attribute-based routing with auto-discovery |
| `monkeyslegion-database` | ^2.0 | Connection manager, PDO abstraction, transactions |
| `monkeyslegion-query` | ^2.0 | Fluent QueryBuilder with grammar compilation |
| `monkeyslegion-entity` | ^2.0 | Entity scanner and metadata extraction |
| `monkeyslegion-migration` | ^2.0 | Database migration generator and runner |
| `monkeyslegion-auth` | ^2.1 | JWT, session guards, password hashing, RBAC |
| `monkeyslegion-validation` | ^2.0 | Attribute-based validation and DTO binding |
| `monkeyslegion-cache` | ^2.0 | PSR-16 cache: Redis, file, in-memory stores |
| `monkeyslegion-session` | ^2.0 | Session manager with CSRF middleware |
| `monkeyslegion-template` | ^2.0 | Template engine with caching and layouts |
| `monkeyslegion-events` | ^2.0 | PSR-14 event dispatcher |
| `monkeyslegion-logger` | ^2.0 | PSR-3 logger with rotating file handlers |
| `monkeyslegion-queue` | ^1.2 | Queue factory, workers, and job dispatching |
| `monkeyslegion-schedule` | ^1.1 | Task scheduling with cron expressions |
| `monkeyslegion-mail` | ^1.1 | SMTP and API-based email |
| `monkeyslegion-i18n` | ^2.1 | Internationalization and locale management |
| `monkeyslegion-telemetry` | ^2.0 | Metrics, distributed tracing, request middleware |
| `monkeyslegion-files` | ^2.0 | File storage, image processing, garbage collection |
| `monkeyslegion-mlc` | ^3.2 | MLC config parser with env interpolation |
| `monkeyslegion-cli` | ^2.0 | CLI kernel with attribute-discovered commands |
| `monkeyslegion-apex` | ^1.0 | AI/ML abstraction: OpenAI, cost tracking |
| `monkeyslegion-openapi` | ^1.0 | Auto-generated OpenAPI v3 documentation |
| `monkeyslegion-dev-server` | ^1.0 | Built-in development server |

---

## 🔨 Installation

### Requirements

- **PHP 8.4+** (uses property hooks and modern features)
- **Composer 2.x**
- **MySQL/MariaDB/PostgreSQL/SQLite** (any PDO-supported database)
- **Redis** (optional — for caching, queues, sessions, and rate limiting)

### Quick Start

```bash
# Install via Composer
composer create-project monkeyscloud/monkeyslegion my-app

# Or add to an existing project
composer require monkeyscloud/monkeyslegion
```

### Project Structure

```
my-app/
├── app/
│   ├── Controller/         # HTTP controllers with route attributes
│   ├── Entity/             # Database entities
│   ├── Provider/           # Custom service providers
│   └── Middleware/         # Custom middleware
├── bootstrap/
│   ├── app.php             # Application factory
│   └── env.php             # Environment loader
├── config/                 # MLC configuration files
│   ├── app.mlc
│   ├── auth.mlc
│   ├── database.mlc
│   └── ...
├── public/
│   └── index.php           # HTTP entry point
├── resources/
│   └── views/              # Templates
├── tests/                  # PHPUnit test suite
├── var/
│   ├── cache/              # Compiled container, templates
│   └── logs/               # Application logs
├── .env                    # Environment variables
├── composer.json
└── phpunit.xml
```

---

## 🏗️ Architecture

### Boot Sequence

```
public/index.php
  └── bootstrap/app.php
        └── Application::create(basePath)
              ├── ENV cascade: .env → .env.local → .env.{APP_ENV} → .env.{APP_ENV}.local
              ├── MLC config: config/*.mlc → Loader → Config (compiled in production)
              ├── Service Providers: AppConfig → 19 providers → DI Container
              ├── SAPI detection: HTTP → Kernel | CLI → CliKernel
              └── run()
```

### Request Lifecycle (HTTP)

```
┌─────────────────────────────────────────────────┐
│  ServerRequest::fromGlobals()                   │
├─────────────────────────────────────────────────┤
│  CoreRequestHandler (PSR-15 Pipeline)           │
│  ├── SecurityHeadersMiddleware (OWASP)          │
│  ├── TrustedProxyMiddleware                     │
│  ├── RequestIdMiddleware                        │
│  ├── CorsMiddleware                             │
│  ├── RateLimitMiddleware                        │
│  ├── MaintenanceModeMiddleware                  │
│  ├── SessionMiddleware                          │
│  ├── VerifyCsrfToken                            │
│  ├── AuthenticationMiddleware                   │
│  └── Router → Controller → Response             │
├─────────────────────────────────────────────────┤
│  SapiEmitter → Client                          │
└─────────────────────────────────────────────────┘
```

---

## 📚 Usage Guide

### Entry Point (v2.0)

**public/index.php**

```php
<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$app = require __DIR__ . '/../bootstrap/app.php';

$app
    ->withMiddleware([
        App\Middleware\CustomMiddleware::class,
    ])
    ->withBindings([
        App\Service\PaymentGateway::class => fn($c) => new App\Service\StripeGateway(
            apiKey: $_ENV['STRIPE_API_KEY'],
        ),
    ])
    ->run();
```

> **Migration from v1:** Replace `HttpBootstrap::run()` with `Application::create()->run()`. The legacy class still works but triggers a deprecation notice.

### Configuration (MLC Format)

MonkeysLegion uses `.mlc` files — a clean, typed config format with env interpolation:

**config/app.mlc**

```mlc
app {
    name = "My Application"
    url = "${env.APP_URL}"
    locale = "en"
    fallback_locale = "en"
    timezone = "UTC"
}
```

**config/database.mlc**

```mlc
database {
    connections {
        mysql {
            driver = "mysql"
            host = "${env.DB_HOST}"
            port = 3306
            database = "${env.DB_DATABASE}"
            username = "${env.DB_USERNAME}"
            password = "${env.DB_PASSWORD}"
            charset = "utf8mb4"
        }
    }
}
```

**config/auth.mlc**

```mlc
auth {
    default_guard = "jwt"
    jwt_secret = "${env.JWT_SECRET}"
    access_ttl = 1800
    refresh_ttl = 604800

    password {
        algorithm = "argon2id"
        memory_cost = 65536
        time_cost = 4
    }

    rate_limit {
        max_attempts = 60
        lockout_seconds = 60
    }
}
```

**Environment cascade:** `.env` → `.env.local` → `.env.{APP_ENV}` → `.env.{APP_ENV}.local`

### Routing

Define routes using PHP 8 attributes with auto-discovery:

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use MonkeysLegion\Router\Attribute\Route;
use MonkeysLegion\Router\Attribute\Get;
use MonkeysLegion\Router\Attribute\Post;
use MonkeysLegion\Router\Attribute\Delete;
use Psr\Http\Message\ResponseInterface;

#[Route('/api/users', name: 'users')]
final class UserController
{
    #[Get('/', name: 'index')]
    public function index(): ResponseInterface
    {
        return json_response(['users' => []]);
    }

    #[Get('/{id:\d+}', name: 'show')]
    public function show(int $id): ResponseInterface
    {
        return json_response(['id' => $id]);
    }

    #[Post('/', name: 'create')]
    public function create(CreateUserRequest $request): ResponseInterface
    {
        // DTO is auto-validated via DtoBinder
        return json_response(['created' => true], 201);
    }

    #[Delete('/{id:\d+}', name: 'delete')]
    public function delete(int $id): ResponseInterface
    {
        return json_response(null, 204);
    }
}
```

### Database & Query Builder

```php
use MonkeysLegion\Query\Query\QueryBuilder;

$qb = $container->get(QueryBuilder::class);

// Select
$users = $qb->select(['id', 'name', 'email'])
    ->from('users')
    ->where('status', '=', 'active')
    ->orderBy('created_at', 'DESC')
    ->limit(10)
    ->get();

// Joins
$posts = $qb->select(['posts.*', 'users.name as author'])
    ->from('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->get();

// Transactions
$connection->transaction(function () use ($qb): void {
    $qb->insert('orders', ['total' => 100]);
    $qb->update('inventory', ['stock' => 'stock - 1']);
});
```

### Authentication

```php
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;

// Login
$result = $authService->login([
    'email'    => 'user@example.com',
    'password' => 'secret',
]);

if ($result->isAuthenticated()) {
    $tokens = $result->getTokens();
    // $tokens['access_token']
    // $tokens['refresh_token']
}

// Protect routes via middleware
#[Route('/admin', middleware: [AuthenticationMiddleware::class])]
final class AdminController { /* ... */ }
```

**Auth capabilities:** JWT, OAuth2 (Google, GitHub), TOTP 2FA, password reset, API keys, RBAC, policies, rate limiting, token blacklisting, remember-me.

### Validation & DTO Binding

```php
use MonkeysLegion\Validation\Attribute\Required;
use MonkeysLegion\Validation\Attribute\Email;
use MonkeysLegion\Validation\Attribute\MinLength;

final class CreateUserRequest
{
    #[Required]
    #[MinLength(3)]
    public string $name;

    #[Required]
    #[Email]
    public string $email;

    #[Required]
    #[MinLength(8)]
    public string $password;
}

// In controller — automatically validated and bound
#[Post('/users')]
public function create(CreateUserRequest $request): ResponseInterface
{
    // Invalid data returns 422 with structured errors
}
```

### Service Providers

Create custom modular providers with attribute discovery:

```php
<?php

declare(strict_types=1);

namespace App\Provider;

use MonkeysLegion\Config\Providers\AbstractServiceProvider;
use MonkeysLegion\Framework\Attributes\Provider;
use MonkeysLegion\Framework\Attributes\BootAfter;
use MonkeysLegion\Config\Providers\DatabaseProvider;

#[Provider(priority: 10, context: 'all')]
#[BootAfter(DatabaseProvider::class)]
final class PaymentProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            PaymentGateway::class => fn($c) => new StripeGateway(
                apiKey: $_ENV['STRIPE_API_KEY'],
            ),
        ];
    }

    public function context(): string
    {
        return 'http'; // Only loaded during HTTP requests
    }
}
```

### Template Engine

```html
<!-- resources/views/welcome.html -->
<!DOCTYPE html>
<html>
  <head>
    <title>{{ $title }}</title>
  </head>
  <body>
    <h1>Welcome, {{ $user.name }}</h1>

    @if($posts)
    <ul>
      @foreach($posts as $post)
      <li>{{ $post.title }}</li>
      @endforeach
    </ul>
    @endif
  </body>
</html>
```

```php
use MonkeysLegion\Template\Renderer;

public function index(Renderer $renderer): ResponseInterface
{
    return $renderer->render('welcome', [
        'title' => 'Home',
        'user'  => ['name' => 'John'],
        'posts' => $this->getPosts(),
    ]);
}
```

### Events (PSR-14)

```php
// Define event
final readonly class UserRegistered
{
    public function __construct(public int $userId) {}
}

// Register listener
$provider->addListener(UserRegistered::class, function (UserRegistered $event): void {
    // Send welcome email, audit log, etc.
});

// Dispatch
$dispatcher->dispatch(new UserRegistered($user->getAuthIdentifier()));
```

### AI/ML with Apex

```php
use MonkeysLegion\Apex\AI;

$ai = $container->get(AI::class);

// Chat completion
$response = $ai->chat([
    ['role' => 'user', 'content' => 'Explain PHP property hooks.'],
]);

echo $response->content;
echo $response->usage->totalTokens;

// Embeddings
$vector = $ai->embed('Search query text');

// Cost tracking (built-in)
$cost = $ai->getCostTracker()->getTotalCost();
```

### Queue System

```php
use MonkeysLegion\Queue\Contracts\QueueInterface;

$queue = $container->get(QueueInterface::class);

// Dispatch job
$queue->push(new SendEmailJob($userId));

// Worker (CLI)
// php bin/ml queue:work --tries=3 --timeout=60
```

### File Management

```php
use MonkeysLegion\Files\FilesManager;
use MonkeysLegion\Files\Image\ImageProcessor;

$files = $container->get(FilesManager::class);
$image = $container->get(ImageProcessor::class);

// Store upload
$path = $files->store($uploadedFile, 'avatars');

// Process image
$image->process($path, [
    'resize' => [150, 150],
    'format' => 'webp',
]);
```

### Internationalization

```php
use MonkeysLegion\I18n\Translator;

$t = $container->get(Translator::class);

echo $t->trans('welcome.message');                         // "Welcome!"
echo $t->trans('user.greeting', ['name' => 'John']);       // "Hello, John"

$t->setLocale('es');
echo $t->trans('welcome.message');                         // "¡Bienvenido!"
```

### Telemetry & Observability

```php
use MonkeysLegion\Telemetry\Metrics\MetricsInterface;
use MonkeysLegion\Telemetry\Tracing\TracerInterface;

// Metrics
$metrics->counter('http_requests_total')->inc();
$metrics->histogram('response_time_ms')->observe($duration);

// Distributed tracing
$span = $tracer->startSpan('process_order');
// ... work ...
$span->end();
```

### Maintenance Mode

```php
// Activate: create var/maintenance.php
file_put_contents('var/maintenance.php', '<?php return [
    "retry"   => 600,
    "message" => "Upgrading to v2.0...",
];');

// Bypass via secret: ?secret=bypass123
// Bypass via IP whitelist: configured in MiddlewareProvider

// Deactivate: remove the file
unlink('var/maintenance.php');
```

### CLI Commands

```bash
# Cache compiled container for production
php bin/ml config:cache

# Clear container cache
php bin/ml config:clear

# Run migrations
php bin/ml migrate:run

# Create migration
php bin/ml make:migration CreateUsersTable

# Clear application cache
php bin/ml cache:clear

# List all routes
php bin/ml route:list

# Start queue worker
php bin/ml queue:work

# Run scheduled tasks
php bin/ml schedule:run

# Framework info
php bin/ml about
```

### Custom Middleware

```php
<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class ApiVersionMiddleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $request = $request->withAttribute('api_version', 'v2');

        $response = $handler->handle($request);

        return $response->withHeader('X-API-Version', '2.0');
    }
}
```

Register in `config/middleware.mlc`:

```mlc
middleware {
    global = [
        "MonkeysLegion\\Http\\Middleware\\SecurityHeadersMiddleware",
        "MonkeysLegion\\Http\\Middleware\\CorsMiddleware",
        "App\\Middleware\\ApiVersionMiddleware"
    ]
}
```

---

## 🧪 Testing

MonkeysLegion ships with a comprehensive test suite (PHPUnit 11):

```bash
# Run tests
php vendor/bin/phpunit

# Run with testdox output
php vendor/bin/phpunit --testdox

# Run specific test
php vendor/bin/phpunit --filter=ApplicationTest

# Static analysis (PHPStan Level 9)
php vendor/bin/phpstan analyse
```

### Test Suite Coverage

| Test Class | Target | Tests |
|---|---|---|
| `CompiledContainerCacheTest` | DI compiled cache | 14 |
| `AttributeTest` | Provider & BootAfter attributes | 7 |
| `MaintenanceModeMiddlewareTest` | Maintenance mode bypass | 7 |
| `ProviderScannerTest` | Auto-discovery scanner | 4 |
| `AppConfigTest` | Provider aggregator & context | 7 |
| `ConfigLoaderTest` | MLC config loading | 4 |
| `ProviderDefinitionsTest` | All 19 service providers | 90+ |
| `ApplicationTest` | Boot lifecycle & container | 13 |
| `ExceptionHandlerTest` | Error handling (JSON/HTML) | 10 |
| `DatabaseUserProviderTest` | Auth user operations | 15 |
| `HttpBootstrapTest` | v1 deprecation | 1 |
| **Total** | | **182 tests, 440 assertions** |

### Writing Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Feature;

use MonkeysLegion\Framework\Application;
use PHPUnit\Framework\TestCase;

final class UserServiceTest extends TestCase
{
    private Application $app;

    protected function setUp(): void
    {
        $this->app = Application::create(basePath: dirname(__DIR__));
    }

    public function testContainerResolvesService(): void
    {
        $container = $this->app->boot();

        $service = $container->get(UserService::class);

        $this->assertInstanceOf(UserService::class, $service);
    }
}
```

---

## ⚡ Production Optimization

### Compiled Container

```bash
# Compile DI definitions for zero-overhead resolution
php bin/ml config:cache

# Clear when definitions change
php bin/ml config:clear
```

### MLC Config Compilation

The `ConfigLoader` automatically compiles `.mlc` files to PHP arrays in `var/cache/config.compiled.php` for production. No parsing overhead on subsequent requests.

### OPcache

```ini
; php.ini recommended settings
opcache.enable=1
opcache.validate_timestamps=0    ; Disable in production
opcache.max_accelerated_files=20000
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.jit=1255
opcache.jit_buffer_size=128M
```

---

## 🔧 Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `production` | Environment: `production`, `staging`, `dev`, `testing` |
| `APP_DEBUG` | `false` | Enable debug mode (error details, stack traces) |
| `APP_URL` | — | Application base URL |
| `APP_TIMEZONE` | `UTC` | Default timezone |
| `DB_CONNECTION` | `mysql` | Database driver |
| `DB_HOST` | `127.0.0.1` | Database host |
| `DB_PORT` | `3306` | Database port |
| `DB_DATABASE` | — | Database name |
| `DB_USERNAME` | `root` | Database user |
| `DB_PASSWORD` | — | Database password |
| `JWT_SECRET` | — | JWT signing key |
| `REDIS_HOST` | `127.0.0.1` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |

---

## 📖 API Reference

For detailed API documentation, visit [monkeyslegion.com/docs](https://monkeyslegion.com/docs) or explore the individual package repositories on [GitHub](https://github.com/MonkeysCloud).

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

MonkeysLegion is open-source software licensed under the [MIT License](LICENSE).

## 🙏 Credits

Created and maintained by the **MonkeysCloud** team.

## 📞 Support

- **Documentation**: [monkeyslegion.com/docs](https://monkeyslegion.com/docs)
- **Issues**: [github.com/MonkeysCloud/MonkeysLegion/issues](https://github.com/MonkeysCloud/MonkeysLegion/issues)
- **Discussions**: [github.com/MonkeysCloud/MonkeysLegion/discussions](https://github.com/MonkeysCloud/MonkeysLegion/discussions)

## 🗺️ Roadmap

- [ ] WebSocket Server / Real-time Broadcasting
- [ ] GraphQL Support
- [ ] Admin Panel Generator
- [ ] Advanced CLI Scaffolding (make:controller, make:entity)
- [ ] Notifications package (email, SMS, Slack, push)
- [ ] Database seeder and factory system

---

**Built with ❤️ by MonkeysCloud**
