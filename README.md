# MonkeysLegion Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP Version](https://img.shields.io/badge/php-%5E8.4-blue)
![Version](https://img.shields.io/badge/version-1.0-green)

**MonkeysLegion** is a modern, modular PHP framework designed for building high-performance web applications and APIs. It follows PSR standards and provides a comprehensive suite of integrated packages for rapid application development.

## 🚀 Features

- **🎯 PSR Compliant** - Fully compliant with PSR-7, PSR-11, PSR-14, PSR-15, PSR-16, PSR-17
- **🔧 Modular Architecture** - Use only what you need with independent, composable packages
- **🔐 Comprehensive Authentication** - JWT, OAuth2, 2FA, API Keys, RBAC, and Policies
- **🗄️ Database Layer** - Query Builder, Migrations, Entity Scanner, and Repository Pattern
- **🎨 Template Engine** - Powerful, custom template engine with caching
- **🌐 Advanced Routing** - Attribute-based routing with middleware support and auto-discovery
- **⚡ Dependency Injection** - Fast, PSR-11 compliant DI container
- **📝 Validation** - Attribute-based validation with DTO binding
- **🌍 Internationalization** - Multi-language support with database and file loaders
- **📧 Email Service** - SMTP and API-based email delivery
- **📊 Telemetry & Monitoring** - Built-in metrics and logging capabilities
- **🎪 Event System** - PSR-14 event dispatcher for decoupled architecture
- **💾 Caching** - Multiple cache backends (Redis, File, In-Memory)
- **🔄 CLI Tools** - Powerful command-line interface for development tasks

## 📦 Included Packages

MonkeysLegion is a meta-package that bundles the following modular components:

| Package                    | Description                              |
| -------------------------- | ---------------------------------------- |
| `monkeyslegion-core`       | Core framework components and utilities  |
| `monkeyslegion-http`       | PSR-7/PSR-15 HTTP layer and middleware   |
| `monkeyslegion-router`     | Advanced routing with attribute support  |
| `monkeyslegion-di`         | Dependency injection container           |
| `monkeyslegion-database`   | Database abstraction and connections     |
| `monkeyslegion-query`      | Query builder and ORM features           |
| `monkeyslegion-entity`     | Entity scanner and metadata extraction   |
| `monkeyslegion-migration`  | Database migration system                |
| `monkeyslegion-auth`       | Complete authentication & authorization  |
| `monkeyslegion-template`   | Custom template engine                   |
| `monkeyslegion-mlc`        | Configuration file parser (.mlc format)  |
| `monkeyslegion-validation` | Attribute-based validation               |
| `monkeyslegion-i18n`       | Internationalization and localization    |
| `monkeyslegion-events`     | PSR-14 event dispatcher                  |
| `monkeyslegion-logger`     | Logging abstraction built on Monolog     |
| `monkeyslegion-mail`       | Email sending capabilities               |
| `monkeyslegion-cache`      | Cache abstraction layer                  |
| `monkeyslegion-files`      | File operations and storage              |
| `monkeyslegion-cli`        | Command-line interface kernel            |
| `monkeyslegion-telemetry`  | Application metrics and monitoring       |
| `monkeyslegion-dev-server` | Development server for rapid prototyping |

## 🔨 Installation

### Requirements

- PHP 8.4 or higher
- Composer 2.x
- MySQL/MariaDB (or any PDO-supported database)
- Redis (optional, for caching and rate limiting)

### Quick Start

```bash
# Install via Composer
composer require monkeyscloud/monkeyslegion

# Create project structure
mkdir my-app && cd my-app
mkdir -p {app/Controller,app/Entity,config,public,resources/views,var/{cache,log}}

# Create public/index.php
cat > public/index.php << 'EOF'
<?php

declare(strict_types=1);

define('ML_BASE_PATH', dirname(__DIR__));

require_once ML_BASE_PATH . '/vendor/autoload.php';

use MonkeysLegion\Framework\HttpBootstrap;

HttpBootstrap::run(ML_BASE_PATH);
EOF

# Create .env file
cat > .env << 'EOF'
APP_ENV=dev
APP_DEBUG=true
APP_URL=http://localhost:8000

DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=myapp
DB_USERNAME=root
DB_PASSWORD=
DB_CHARSET=utf8mb4

JWT_SECRET=your-secret-key-change-this
EOF

# Create bootstrap/env.php (if not exists)
mkdir -p bootstrap
cp vendor/monkeyscloud/monkeyslegion/bootstrap/env.php bootstrap/

# Start development server
php -S localhost:8000 -t public
```

## 📚 Documentation

### Architecture

MonkeysLegion follows a layered architecture:

```
┌─────────────────────────────────────┐
│     Controllers & Routes            │
├─────────────────────────────────────┤
│     Middleware Pipeline             │
├─────────────────────────────────────┤
│     Service Layer                   │
├─────────────────────────────────────┤
│     Repositories & Query Builder    │
├─────────────────────────────────────┤
│     Database Connection Layer       │
└─────────────────────────────────────┘
```

### Configuration

MonkeysLegion uses `.mlc` configuration files for clean, structured settings:

**config/app.mlc**

```mlc
app {
    name = "My Application"
    url = "http://localhost:8000"
    locale = "en"
    fallback_locale = "en"
}

cache {
    enabled = true
    driver = "redis"
    prefix = "myapp:"
}

auth {
    jwt_secret = "${env.JWT_SECRET}"
    access_ttl = 1800
    refresh_ttl = 604800

    rate_limit {
        driver = "cache"  # Options: "redis", "cache", "memory"
        max_attempts = 60
        lockout_seconds = 60
    }

    token_storage {
        driver = "memory"  # Options: "redis", "memory"
        prefix = "auth:"
    }
}

redis {
    host = "127.0.0.1"
    port = 6379
    timeout = 0.0
    database = 0
    # password = "your-password"  # Optional
    # prefix = "myapp:"           # Optional key prefix
}
```

### Routing

Define routes using PHP attributes:

```php
<?php

namespace App\Controller;

use MonkeysLegion\Router\Attribute\Route;
use MonkeysLegion\Router\Attribute\Get;
use MonkeysLegion\Router\Attribute\Post;
use Psr\Http\Message\ResponseInterface;

#[Route('/api/users', name: 'users')]
class UserController
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
    public function create(): ResponseInterface
    {
        return json_response(['created' => true], 201);
    }
}
```

### Database & Query Builder

```php
use MonkeysLegion\Query\QueryBuilder;

// Get from container
$qb = $container->get(QueryBuilder::class);

// Simple queries
$users = $qb->table('users')
    ->where('status', '=', 'active')
    ->orderBy('created_at', 'DESC')
    ->limit(10)
    ->get();

// Joins
$posts = $qb->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->select(['posts.*', 'users.name as author'])
    ->get();

// Transactions
$qb->transaction(function($qb) {
    $qb->table('orders')->insert(['total' => 100]);
    $qb->table('inventory')->update(['stock' => 'stock - 1']);
});
```

### Authentication

MonkeysLegion provides comprehensive authentication out of the box:

```php
use MonkeysLegion\Auth\Service\AuthService;

// Login
$result = $authService->login([
    'email' => 'user@example.com',
    'password' => 'secret'
]);

if ($result->isAuthenticated()) {
    $tokens = $result->getTokens();
    // $tokens['access_token']
    // $tokens['refresh_token']
}

// Middleware protection
#[Route('/admin', middleware: [AuthenticationMiddleware::class])]
class AdminController { /* ... */ }
```

#### Features:

- ✅ JWT-based authentication
- ✅ OAuth2 (Google, GitHub)
- ✅ Two-Factor Authentication (TOTP)
- ✅ Password reset & email verification
- ✅ API key authentication
- ✅ Role-Based Access Control (RBAC)
- ✅ Policy-based authorization
- ✅ Rate limiting
- ✅ Token blacklisting

### Validation

Use attributes for clean validation:

```php
use MonkeysLegion\Validation\Attribute\Required;
use MonkeysLegion\Validation\Attribute\Email;
use MonkeysLegion\Validation\Attribute\MinLength;

class CreateUserRequest
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

// In controller
#[Post('/users')]
public function create(CreateUserRequest $request): ResponseInterface
{
    // $request is automatically validated and bound
    // Invalid data returns 422 response
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
// In controller
use MonkeysLegion\Template\Renderer;

public function index(Renderer $renderer): ResponseInterface
{
    return $renderer->render('welcome', [
        'title' => 'Home',
        'user' => ['name' => 'John'],
        'posts' => $this->getPosts()
    ]);
}
```

### Events

Leverage the PSR-14 event dispatcher:

```php
// Define event
class UserRegistered
{
    public function __construct(public readonly int $userId) {}
}

// Register listener
use Psr\EventDispatcher\ListenerProviderInterface;

$provider->addListener(UserRegistered::class, function(UserRegistered $event) {
    // Send welcome email
    // Log analytics
});

// Dispatch
use Psr\EventDispatcher\EventDispatcherInterface;

$dispatcher->dispatch(new UserRegistered($user->getId()));
```

### Internationalization

```php
use MonkeysLegion\I18n\Translator;

$translator = $container->get(Translator::class);

echo $translator->trans('welcome.message'); // "Welcome to our app"
echo $translator->trans('user.greeting', ['name' => 'John']); // "Hello, John"

// Change locale
$translator->setLocale('es');
echo $translator->trans('welcome.message'); // "Bienvenido a nuestra aplicación"
```

### Middleware

Create custom middleware:

```php
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CustomMiddleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        // Before request
        $request = $request->withAttribute('timestamp', time());

        $response = $handler->handle($request);

        // After request
        return $response->withHeader('X-Custom-Header', 'value');
    }
}
```

Register in `config/middleware.mlc`:

```mlc
middleware {
    global = [
        "MonkeysLegion\\Core\\Middleware\\CorsMiddleware",
        "App\\Middleware\\CustomMiddleware"
    ]
}
```

### Dependency Injection

```php
use MonkeysLegion\DI\ContainerBuilder;

// Define services in config/app.php
return [
    MyService::class => fn($c) => new MyService(
        $c->get(SomeDependency::class)
    ),

    // Use interfaces
    MyInterface::class => fn($c) => $c->get(MyImplementation::class),
];

// Auto-wiring in controllers
class UserController
{
    public function __construct(
        private MyService $service,
        private QueryBuilder $qb
    ) {}
}
```

### CLI Commands

```bash
# Run migrations
php bin/console migrate:run

# Create migration
php bin/console make:migration CreateUsersTable

# Clear cache
php bin/console cache:clear

# List routes
php bin/console route:list
```

Create custom commands:

```php
use MonkeysLegion\Cli\Command;

class MyCommand extends Command
{
    protected string $signature = 'my:command {argument} {--option=}';
    protected string $description = 'My custom command';

    public function handle(): int
    {
        $arg = $this->argument('argument');
        $opt = $this->option('option');

        $this->info('Processing...');
        $this->success('Done!');

        return 0;
    }
}
```

## 🧪 Testing

MonkeysLegion is designed with testability in mind:

```php
use PHPUnit\Framework\TestCase;

class UserServiceTest extends TestCase
{
    public function testUserCreation(): void
    {
        $container = $this->buildTestContainer();
        $service = $container->get(UserService::class);

        $user = $service->create([
            'name' => 'Test User',
            'email' => 'test@example.com'
        ]);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('test@example.com', $user->getEmail());
    }
}
```

## 🔧 Advanced Usage

### Custom Service Providers

Extend the framework with custom providers:

```php
namespace App\Provider;

use MonkeysLegion\DI\ContainerBuilder;

class PaymentServiceProvider
{
    public static function register(string $root, ContainerBuilder $builder): void
    {
        $builder->addDefinitions([
            PaymentGateway::class => fn($c) => new StripeGateway(
                apiKey: $_ENV['STRIPE_API_KEY']
            ),
        ]);
    }
}
```

Register in `composer.json`:

```json
{
  "extra": {
    "monkeyslegion": {
      "providers": ["App\\Provider\\PaymentServiceProvider"]
    }
  }
}
```

### Environment Configuration

Create environment-specific configuration:

- `.env` - Base configuration
- `.env.local` - Local overrides (gitignored)
- `.env.production` - Production settings
- `.env.production.local` - Production local overrides

## 📖 API Reference

For detailed API documentation, please visit [our documentation site](https://monkeyslegion.com/docs) or explore individual package repositories.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MonkeysLegion is open-source software licensed under the [MIT license](LICENSE).

## 🙏 Credits

Created and maintained by the MonkeysCloud team.

## 📞 Support

- **Documentation**: https://monkeyslegion.com/docs
- **Issues**: https://github.com/monkeyscloud/monkeyslegion/issues
- **Discussions**: https://github.com/monkeyscloud/monkeyslegion/discussions

## 🗺️ Roadmap

- [ ] GraphQL support
- [ ] WebSocket server
- [ ] Queue/Job system
- [ ] Admin panel generator
- [ ] Real-time broadcasting
- [ ] File storage abstraction (S3, local, etc.)
- [ ] Advanced caching strategies
- [ ] Full OpenAPI/Swagger integration
- [ ] Enhanced CLI scaffolding tools

---

**Built with ❤️ by MonkeysCloud**
