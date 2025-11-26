<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use Laminas\Diactoros\ServerRequestFactory;

use MonkeysLegion\Auth\AuthService;
use MonkeysLegion\Auth\AuthService\AuthorizationService;
use MonkeysLegion\Auth\JwtService;
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;
use MonkeysLegion\Auth\Middleware\JwtAuthMiddleware;
use MonkeysLegion\Auth\Middleware\JwtUserMiddleware;
use MonkeysLegion\Auth\PasswordHasher;
use MonkeysLegion\Cli\Support\CommandFinder;
use MonkeysLegion\Core\Middleware\CorsMiddleware;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Query\QueryBuilder;
use MonkeysLegion\Repository\RepositoryFactory;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

use Psr\SimpleCache\CacheInterface;
use MonkeysLegion\Http\SimpleFileCache;
use MonkeysLegion\Http\Factory\HttpFactory;

use MonkeysLegion\Cli\CliKernel;
use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\Database\Cache\Contracts\CacheItemPoolInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Database\MySQL\Connection;
use MonkeysLegion\Database\Factory\CacheFactory;
use MonkeysLegion\Database\Factory\ConnectionFactory;
use MonkeysLegion\Entity\Scanner\EntityScanner;

use MonkeysLegion\Http\{
    CoreRequestHandler,
    Middleware\ErrorHandlerMiddleware,
    RouteRequestHandler,
    Middleware\AuthMiddleware,
    Middleware\LoggingMiddleware,
    Middleware\RateLimitMiddleware,
    MiddlewareDispatcher,
    Emitter\SapiEmitter
};

use MonkeysLegion\Migration\MigrationGenerator;
use MonkeysLegion\Mlc\{
    Config as MlcConfig,
    Loader as MlcLoader,
    Parser as MlcParser
};

use MonkeysLegion\Router\{
    RouteCache,
    RouteCollection,
    Router,
    UrlGenerator
};

use MonkeysLegion\Template\{
    Compiler as TemplateCompiler,
    Loader   as TemplateLoader,
    Parser   as TemplateParser,
    Renderer as TemplateRenderer
};

use MonkeysLegion\I18n\Translator;

use MonkeysLegion\Telemetry\{
    MetricsInterface,
    NullMetrics,
};

use MonkeysLegion\Events\{
    ListenerProvider,
    EventDispatcher
};

use MonkeysLegion\Http\OpenApi\{
    OpenApiGenerator,
    OpenApiMiddleware
};
use MonkeysLegion\Validation\ValidatorInterface;
use MonkeysLegion\Validation\AttributeValidator;
use MonkeysLegion\Validation\DtoBinder;
use MonkeysLegion\Validation\Middleware\ValidationMiddleware;

/**  Default DI definitions shipped by the framework.  */
final class AppConfig
{
    public function __invoke(): array
    {
        return [
            ...((new LoggerConfig())()),

            /* ----------------------------------------------------------------- */
            /* PSR-17 factories                                                   */
            /* ----------------------------------------------------------------- */
            HttpFactory::class                  => fn() => new HttpFactory(),

            ResponseFactoryInterface::class     => fn($c) => $c->get(HttpFactory::class),
            StreamFactoryInterface::class       => fn($c) => $c->get(HttpFactory::class),
            UploadedFileFactoryInterface::class => fn($c) => $c->get(HttpFactory::class),
            UriFactoryInterface::class          => fn($c) => $c->get(HttpFactory::class),

            /* ----------------------------------------------------------------- */
            /* PSR-7 ServerRequest (create once from globals)                    */
            /* ----------------------------------------------------------------- */
            ServerRequestInterface::class       => fn() =>
            new ServerRequestFactory()->fromGlobals(),

            /* ----------------------------------------------------------------- */
            /* PSR-16 Cache (file-based fallback for rate-limiting)              */
            /* ----------------------------------------------------------------- */
            CacheInterface::class => fn() => new SimpleFileCache(
                base_path('var/cache/rate_limit')
            ),

            /* ----------------------------------------------------------------- */
            /* Metrics / Telemetry (choose one)                                   */
            /* ----------------------------------------------------------------- */
            MetricsInterface::class => fn() => new NullMetrics(),

            /* ———————————————————————————————————————————————
            *  Event dispatcher (PSR-14)
            * ——————————————————————————————————————————————— */
            ListenerProvider::class        => fn() => new ListenerProvider(),
            EventDispatcherInterface::class => fn($c) => new EventDispatcher(
                $c->get(ListenerProvider::class)
            ),

            /* ----------------------------------------------------------------- */
            /* .mlc config support                                                */
            /* ----------------------------------------------------------------- */
            MlcParser::class                    => fn()   => new MlcParser(),
            MlcLoader::class                    => fn($c) => new MlcLoader(
                $c->get(MlcParser::class),
                base_path('config'),
                base_path()
            ),

            MlcConfig::class => static function ($c) {
                /** @var MlcLoader $loader */
                $loader = $c->get(MlcLoader::class);
                $files = glob(base_path('config/*.mlc')) ?: [];
                $names = array_map(
                    static fn(string $path) => pathinfo($path, PATHINFO_FILENAME),
                    $files
                );
                sort($names);
                return $loader->load($names);
            },

            /* ----------------------------------------------------------------- */
            /* Template engine                                                    */
            /* ----------------------------------------------------------------- */
            TemplateParser::class   => fn()   => new TemplateParser(),
            TemplateCompiler::class => fn($c) => new TemplateCompiler($c->get(TemplateParser::class)),
            TemplateLoader::class   => fn()   => new TemplateLoader(
                base_path('resources/views'),
                base_path('var/cache/views')
            ),
            TemplateRenderer::class => fn($c) => new TemplateRenderer(
                $c->get(TemplateParser::class),
                $c->get(TemplateCompiler::class),
                $c->get(TemplateLoader::class),
                (bool) $c->get(MlcConfig::class)->get('cache.enabled', true)
            ),

            Translator::class => fn($c) => new Translator(
                $c->get(MlcConfig::class)->get('app.locale', 'en'),
                base_path('resources/lang'),
                'en'
            ),

            /* ----------------------------------------------------------------- */
            /* Database                                                            */
            /* ----------------------------------------------------------------- */
            ConnectionInterface::class => fn() => ConnectionFactory::create(require base_path('config/database.php') ?? []),
            Connection::class => fn() => ConnectionFactory::create(require base_path('config/database.php') ?? []),

            /* ----------------------------------------------------------------- */
            /* Query Builder & Repositories                                       */
            /* ----------------------------------------------------------------- */
            QueryBuilder::class   => fn($c) => new QueryBuilder($c->get(ConnectionInterface::class)),

            RepositoryFactory::class => fn($c) => new RepositoryFactory(
                $c->get(QueryBuilder::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Entity scanner + migration generator                               */
            /* ----------------------------------------------------------------- */
            EntityScanner::class      => fn() => new EntityScanner(base_path('app/Entity')),
            MigrationGenerator::class => fn($c) => new MigrationGenerator(
                $c->get(ConnectionInterface::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Routing - Enhanced Router Package v2                              */
            /* ----------------------------------------------------------------- */

            /**
             * Route Collection - stores all registered routes with support for:
             * - Named routes
             * - Middleware per route
             * - Route constraints (int, uuid, slug, alpha, alphanumeric, custom regex)
             * - Default parameter values
             * - Domain constraints
             * - Route metadata (for OpenAPI generation)
             */
            RouteCollection::class => fn() => new RouteCollection(),

            /**
             * Route Cache - enables route caching for production performance.
             * Cache is stored in var/cache/routes directory.
             * Enable via routing.cache = true in your .mlc config.
             */
            RouteCache::class => fn() => new RouteCache(
                base_path('var/cache/routes')
            ),

            /**
             * Main Router instance with:
             * - Fluent route registration (get, post, put, delete, patch, options, any, match)
             * - Route groups with shared prefix, middleware, and constraints
             * - Controller registration via #[Route] attributes
             * - Middleware registration and groups
             * - Custom 404/405 handlers
             * - URL generation via named routes
             * 
             * If route caching is enabled, routes are loaded from cache instead of
             * being re-registered on each request.
             */
            Router::class => static function ($c) {
                /** @var RouteCollection $collection */
                $collection = $c->get(RouteCollection::class);

                /** @var RouteCache $cache */
                $cache = $c->get(RouteCache::class);

                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                // Check if route caching is enabled (typically in production)
                $cacheEnabled = (bool) $mlc->get('routing.cache', false);

                if ($cacheEnabled && $cache->has()) {
                    // Load routes from cache
                    $cached = $cache->load();
                    if ($cached !== null) {
                        $collection->import($cached);
                    }
                }

                $router = new Router($collection);

                // Set base URL for absolute URL generation
                $baseUrl = $mlc->get('app.url', '');
                if ($baseUrl) {
                    $router->getUrlGenerator()->setBaseUrl($baseUrl);
                }

                // Register global middleware if configured
                $globalMiddleware = $mlc->get('routing.global_middleware', []);
                foreach ($globalMiddleware as $middleware) {
                    $router->addGlobalMiddleware($middleware);
                }

                // Register middleware groups if configured
                $middlewareGroups = $mlc->get('routing.middleware_groups', []);
                foreach ($middlewareGroups as $name => $middlewares) {
                    $router->registerMiddlewareGroup($name, $middlewares);
                }

                return $router;
            },

            /**
             * URL Generator - generates URLs from named routes.
             * Exposed separately for injection into services, controllers,
             * and templates that need URL generation without the full Router dependency.
             * 
             * Usage: $urlGenerator->generate('users.show', ['id' => 42]);
             */
            UrlGenerator::class => fn($c) => $c->get(Router::class)->getUrlGenerator(),

            /**
             * Route Loader - scans controllers for #[Route] attributes.
             * Now supports the enhanced route metadata from the new Router package:
             * - #[RoutePrefix('/api')] on controllers
             * - #[Route('/users', methods: ['GET'], name: 'users.index')]
             * - #[Middleware('auth', 'throttle')]
             * - Inline constraints: /users/{id:int}
             */
            RouteLoader::class => fn($c) => new RouteLoader(
                $c->get(Router::class),
                $c,
                base_path('app/Controller'),
                'App\\Controller'
            ),

            /* ----------------------------------------------------------------- */
            /* Adapt Router to PSR-15 RequestHandlerInterface                     */
            /* ----------------------------------------------------------------- */
            RouteRequestHandler::class => fn($c) => new RouteRequestHandler(
                $c->get(Router::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Core PSR-15 dispatcher + final application handler                 */
            /* ----------------------------------------------------------------- */
            CoreRequestHandler::class => fn($c) => new CoreRequestHandler(
                $c->get(RouteRequestHandler::class),
                $c->get(ResponseFactoryInterface::class)
            ),

            /* ----------------------------------------------------------------- */
            /* CORS middleware                                                   */
            /* ----------------------------------------------------------------- */
            CorsMiddleware::class => fn($c) => new CorsMiddleware(
                allowOrigin: $c->get(MlcConfig::class)->get('cors.allow_origin', '*'),
                allowMethods: $c->get(MlcConfig::class)->get('cors.allow_methods', ['GET', 'POST', 'OPTIONS', 'PATCH', 'DELETE']),
                allowHeaders: $c->get(MlcConfig::class)->get('cors.allow_headers', ['Content-Type', 'Authorization']),
                exposeHeaders: $c->get(MlcConfig::class)->get('cors.expose_headers', null),
                allowCredentials: (bool)$c->get(MlcConfig::class)->get('cors.allow_credentials', false),
                maxAge: (int)$c->get(MlcConfig::class)->get('cors.max_age', 0),
                responseFactory: $c->get(ResponseFactoryInterface::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Error handler middleware                                          */
            /* ----------------------------------------------------------------- */
            ErrorHandlerMiddleware::class => fn() => new ErrorHandlerMiddleware(),

            /* ----------------------------------------------------------------- */
            /* Rate-limit middleware                                              */
            /* ----------------------------------------------------------------- */
            RateLimitMiddleware::class =>
            fn($c) => new RateLimitMiddleware(
                $c->get(ResponseFactoryInterface::class),
                $c->get(CacheInterface::class),
                5000,
                60
            ),

            /* ----------------------------------------------------------------- */
            /* Authentication middleware                                          */
            /* ----------------------------------------------------------------- */
            AuthMiddleware::class => fn($c) => new AuthMiddleware(
                $c->get(ResponseFactoryInterface::class),
                'Protected',
                (string)$c->get(MlcConfig::class)->get('auth.token'),
                $c->get(MlcConfig::class)->get('auth.public_paths', [])
            ),

            /* ----------------------------------------------------------------- */
            /* Simple logging middleware                                          */
            /* ----------------------------------------------------------------- */
            LoggingMiddleware::class    => fn() => new LoggingMiddleware(),

            PasswordHasher::class => fn() => new PasswordHasher(),
            JwtService::class => fn($c) => new JwtService(
                (string)$c->get(MlcConfig::class)->get('auth.jwt_secret'),
                (int)$c->get(MlcConfig::class)->get('auth.jwt_ttl', 3600),
                (int)$c->get(MlcConfig::class)->get('auth.jwt_leeway', 0),
                (int)$c->get(MlcConfig::class)->get('auth.nbf_skew', 0),
            ),
            AuthService::class     => fn($c) => new AuthService(
                $c->get(RepositoryFactory::class),
                $c->get(PasswordHasher::class),
                $c->get(JwtService::class)
            ),
            JwtAuthMiddleware::class => fn($c) => new JwtAuthMiddleware(
                $c->get(JwtService::class),
                $c->get(ResponseFactoryInterface::class)
            ),

            AuthorizationService::class => function () {
                $svc = new AuthorizationService();
                // Register policies here when needed
                // $svc->registerPolicy(App\Entity\Post::class, App\Policy\PostPolicy::class);
                return $svc;
            },

            AuthorizationMiddleware::class => fn($c) =>
            new AuthorizationMiddleware(
                $c->get(AuthorizationService::class)
            ),

            JwtUserMiddleware::class => fn($c) => new JwtUserMiddleware(
                $c->get(JwtService::class),
                $c->get(MlcConfig::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Validation layer                                                  */
            /* ----------------------------------------------------------------- */
            ValidatorInterface::class => fn() => new AttributeValidator(),

            DtoBinder::class          => fn($c) => new DtoBinder(
                $c->get(ValidatorInterface::class)
            ),

            ValidationMiddleware::class => fn($c) => new ValidationMiddleware(
                $c->get(DtoBinder::class),
                [
                    // 'user_create' => \App\Http\Dto\CreateUserRequest::class,
                ]
            ),

            /*----------------------------------------------------*/
            /*  OpenAPI                                           */
            /*----------------------------------------------------*/
            OpenApiGenerator::class => fn($c) => new OpenApiGenerator(
                $c->get(RouteCollection::class)
            ),

            OpenApiMiddleware::class => fn($c) => new OpenApiMiddleware(
                $c->get(OpenApiGenerator::class),
                $c->get(ResponseFactoryInterface::class)
            ),

            /* -----------------------------------------------------------------
             | PSR-15 pipeline — driven *solely* by config/middleware.mlc
             * ---------------------------------------------------------------- */
            MiddlewareDispatcher::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $ids = $mlc->get('middleware.global', []);
                $stack = array_map([$c, 'get'], $ids);

                return new MiddlewareDispatcher(
                    $stack,
                    $c->get(CoreRequestHandler::class)
                );
            },

            /* ----------------------------------------------------------------- */
            /* SAPI emitter                                                       */
            /* ----------------------------------------------------------------- */
            SapiEmitter::class          => fn() => new SapiEmitter(),

            /* ----------------------------------------------------------------- */
            /* CLI commands + kernel                                            */
            /* ----------------------------------------------------------------- */
            CliKernel::class => fn($c) => new CliKernel(
                $c,
                CommandFinder::all()
            ),

            /* ----------------------------------------------------------------- */
            /* Cache                                                             */
            /* ----------------------------------------------------------------- */
            CacheItemPoolInterface::class => fn() => CacheFactory::create(require base_path('config/cache.php') ?? []),
        ];
    }

    /**
     * Called by your bootstrap to add framework defaults.
     */
    public static function register(ContainerBuilder $builder): void
    {
        $builder->addDefinitions(new self()());
    }
}
