<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use App\Repository\UserRepository;
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
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use MonkeysLegion\Http\SimpleFileCache;
use MonkeysLegion\Http\Factory\HttpFactory;

use MonkeysLegion\Cli\CliKernel;

use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\Database\MySQL\Connection;
use MonkeysLegion\Entity\Scanner\EntityScanner;

use MonkeysLegion\Http\{
    CoreRequestHandler,
    Middleware\ContentNegotiationMiddleware,
    Middleware\ErrorHandlerMiddleware,
    Middleware\RequestLog,
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
    RouteCollection,
    Router
};

use MonkeysLegion\Template\{
    Compiler as TemplateCompiler,
    Loader   as TemplateLoader,
    Parser   as TemplateParser,
    Renderer as TemplateRenderer
};

use MonkeysLegion\I18n\Translator;

use Prometheus\Storage\APC;               // or Redis
use MonkeysLegion\Telemetry\{
    MetricsInterface,
    NullMetrics,
    PrometheusMetrics,
    StatsDMetrics
};

use MonkeysLegion\Events\{
    ListenerProvider,
    EventDispatcher
};

use MonkeysLegion\Http\OpenApi\{
    OpenApiGenerator,
    OpenApiMiddleware
};
use MonkeysLegion\Logger\FrameworkLoggerInterface;
use MonkeysLegion\Logger\MonkeyLogger;
use MonkeysLegion\Mail\Provider\MailServiceProvider;
use MonkeysLegion\Validation\ValidatorInterface;
use MonkeysLegion\Validation\AttributeValidator;
use MonkeysLegion\Validation\DtoBinder;
use MonkeysLegion\Validation\Middleware\ValidationMiddleware;
use RuntimeException;

/**  Default DI definitions shipped by the framework.  */
final class AppConfig
{
    public function __invoke(): array
    {
        return [

            /*
            |--------------------------------------------------------------------------
            | PSR-3 Logger (Monolog)
            |--------------------------------------------------------------------------
            */
            LoggerInterface::class => function ($c) {
                /** @var MlcConfig $mlc */
                $mlc     = $c->get(MlcConfig::class);
                $logging = $mlc->get('logging', []);

                // Master switch
                if (empty($logging['enabled'])) {
                    return new NullLogger();
                }

                $logger = new Logger('app');

                // stdout handler
                if (! empty($logging['stdout']['enabled'])) {
                    $level = strtoupper($logging['stdout']['level'] ?? 'info');
                    $logger->pushHandler(
                        new StreamHandler('php://stdout', Logger::toMonologLevel($level))
                    );
                }

                // file handler
                if (! empty($logging['file']['enabled'])) {
                    $path  = base_path($logging['file']['path'] ?? 'var/log/app.log');
                    $level = strtoupper($logging['file']['level'] ?? 'info');
                    $logger->pushHandler(
                        new StreamHandler($path, Logger::toMonologLevel($level))
                    );
                }

                return $logger;
            },

            /* ----------------------------------------------------------------- */
            /* Framework logger (MonkeysLegion\Logger\MonkeyLogger)                */
            /* ----------------------------------------------------------------- */
            FrameworkLoggerInterface::class => fn() => new MonkeyLogger(),

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
            // 1) No-op (default)
            MetricsInterface::class => fn() => new NullMetrics(),

            // 2) Prometheus (APC in dev – swap to Redis in prod)
            //MetricsInterface::class => fn() => new PrometheusMetrics(new APC()),

            // 3) StatsD
            //MetricsInterface::class => fn() => new StatsDMetrics('127.0.0.1', 8125),

            /* ———————————————————————————————————————————————
            *  Event dispatcher (PSR-14)
            * ——————————————————————————————————————————————— */
            ListenerProvider::class        => fn() => new ListenerProvider(),
            EventDispatcherInterface::class => fn($c) => new EventDispatcher(
                $c->get(ListenerProvider::class)
            ),

            // Example: register a listener right here (commented)
            /*
            App\Listeners\AuditLogger::class => function ($c) {
                $cb = [$c->get(LoggerInterface::class), 'info'];
                $c->get(ListenerProvider::class)
                   ->add(App\Events\UserDeleted::class, $cb, priority: 10);

                return new App\Listeners\AuditLogger();
            },
            */

            /* ----------------------------------------------------------------- */
            /* .mlc config support                                                */
            /* ----------------------------------------------------------------- */
            MlcParser::class                    => fn()   => new MlcParser(),
            MlcLoader::class                    => fn($c) => new MlcLoader(
                $c->get(MlcParser::class),
                base_path('config')
            ),

            /* -----------------------------------------------------------------
             | Dynamic .mlc config loader
             | – picks up every *.mlc file in config/ at runtime
             * ---------------------------------------------------------------- */
            MlcConfig::class => static function ($c) {
                /** @var MlcLoader $loader */
                $loader = $c->get(MlcLoader::class);

                // 1 grab every *.mlc in the config dir
                $files = glob(base_path('config/*.mlc')) ?: [];

                // 2 turn "config/foo.mlc" into just "foo"
                $names = array_map(
                    static fn(string $path) => pathinfo($path, PATHINFO_FILENAME),
                    $files
                );

                // 3 deterministic order (alpha) so overrides are stable
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
                // fetch locale from env or request (here default 'en')
                $c->get(MlcConfig::class)->get('app.locale', 'en'),
                base_path('resources/lang'),
                'en'
            ),

            /* ----------------------------------------------------------------- */
            /* Database                                                            */
            /* ----------------------------------------------------------------- */
            Connection::class => fn() => new Connection(
                require base_path('config/database.php')
            ),

            /* ----------------------------------------------------------------- */
            /* Query Builder & Repositories                                       */
            /* ----------------------------------------------------------------- */
            QueryBuilder::class   => fn($c) => new QueryBuilder($c->get(Connection::class)),

            RepositoryFactory::class => fn($c) => new RepositoryFactory(
                $c->get(QueryBuilder::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Entity scanner + migration generator                               */
            /* ----------------------------------------------------------------- */
            EntityScanner::class      => fn() => new EntityScanner(base_path('app/Entity')),
            MigrationGenerator::class => fn($c) => new MigrationGenerator(
                $c->get(Connection::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Routing                                                             */
            /* ----------------------------------------------------------------- */
            RouteCollection::class    => fn()   => new RouteCollection(),
            Router::class             => fn($c) => new Router($c->get(RouteCollection::class)),
            RouteLoader::class        => fn($c) => new RouteLoader(
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
                allowMethods: $c->get(MlcConfig::class)->get('cors.allow_methods', ['GET', 'POST', 'OPTIONS']),
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
                5000,   // limit
                60     // window (seconds)
            ),

            /* ----------------------------------------------------------------- */
            /* Authentication middleware                                          */
            /* ----------------------------------------------------------------- */
            AuthMiddleware::class => fn($c) => new AuthMiddleware(
                $c->get(ResponseFactoryInterface::class),
                // realm FIRST (matches vendor order)
                'Protected',
                // token SECOND
                (string)$c->get(MlcConfig::class)->get('auth.token'),
                // wildcard-aware public paths
                $c->get(MlcConfig::class)->get('auth.public_paths', [])
            ),

            /* ----------------------------------------------------------------- */
            /* Simple logging middleware                                          */
            /* ----------------------------------------------------------------- */
            LoggingMiddleware::class    => fn() => new LoggingMiddleware(
                // you can inject LoggerInterface here if your middleware takes it
            ),

            PasswordHasher::class => fn() => new PasswordHasher(),
            JwtService::class      => fn($c) => new JwtService(
                $c->get(MlcConfig::class)->get('auth.jwt_secret'),
                (int)$c->get(MlcConfig::class)->get('auth.jwt_ttl', 3600)
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

            /**
             * Concrete AuthorizationService instance.
             * Register policies here if/when you create them.
             */
            AuthorizationService::class => function () {
                $svc = new AuthorizationService();

                // example policy registrations — comment-out until you have them
                // $svc->registerPolicy(App\Entity\Post::class, App\Policy\PostPolicy::class);
                // $svc->registerPolicy(App\Entity\User::class, App\Policy\UserPolicy::class);

                return $svc;
            },

            AuthorizationMiddleware::class => fn($c) =>
            new AuthorizationMiddleware(
                $c->get(AuthorizationService::class)
            ),

            /* ----------------------------------------------------------------- */
            /* User repository + middleware for JWT user extraction             */
            /* ----------------------------------------------------------------- */
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

            /**
             * Map <router-name ⇒ DTO class>.  Adjust to your routes.
             * Example assumes you have a CreateUserRequest DTO.
             */
            ValidationMiddleware::class => fn($c) => new ValidationMiddleware(
                $c->get(DtoBinder::class),
                [
                    // 'user_create' => \App\Http\Dto\CreateUserRequest::class,
                    // 'order_create' => \App\Http\Dto\CreateOrderRequest::class,
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

                // Try reading user‐defined list; fall back to DEFAULT_MIDDLEWARE if empty
                $ids = $mlc->get('middleware.global', []);

                // Instantiate each middleware from the container
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
        ];
    }

    /**
     * Called by your bootstrap to add framework defaults.
     */
    public static function register(ContainerBuilder $builder): void
    {
        // invoke the instance and feed its array into the builder
        $builder->addDefinitions(new self()());
    }
}
