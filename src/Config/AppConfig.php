<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use Laminas\Diactoros\ServerRequestFactory;
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Service\AuthorizationService;
use MonkeysLegion\Auth\Service\RedisTokenStorage;
use MonkeysLegion\Auth\Service\TwoFactorService;
use MonkeysLegion\Auth\Service\PasswordResetService;
use MonkeysLegion\Auth\Service\EmailVerificationService;

use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;

use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;
use MonkeysLegion\Auth\Middleware\RateLimitMiddleware as AuthRateLimitMiddleware;

use MonkeysLegion\Auth\RateLimit\RedisRateLimiter;
use MonkeysLegion\Auth\RateLimit\CacheRateLimiter;
use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;

use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use MonkeysLegion\Auth\TwoFactor\TwoFactorService as TwoFactorProviderService;

use MonkeysLegion\Auth\RBAC\RoleRegistry;
use MonkeysLegion\Auth\RBAC\PermissionChecker;
use MonkeysLegion\Auth\RBAC\RbacService;

use MonkeysLegion\Auth\Policy\Gate;

use MonkeysLegion\Auth\OAuth\OAuthService;
use MonkeysLegion\Auth\OAuth\GoogleProvider;
use MonkeysLegion\Auth\OAuth\GitHubProvider;

use MonkeysLegion\Auth\ApiKey\ApiKeyService;

use MonkeysLegion\Auth\Storage\InMemoryTokenStorage;
use MonkeysLegion\Auth\Storage\InMemoryUserProvider;
use MonkeysLegion\Framework\Auth\DatabaseUserProvider;

/* -------------------------------------------------------------------------
 * Other Framework Imports
 * ------------------------------------------------------------------------- */
use MonkeysLegion\Cli\Support\CommandFinder;
use MonkeysLegion\Core\Middleware\CorsMiddleware;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Query\QueryBuilder;
use MonkeysLegion\Repository\RepositoryFactory;

use Psr\Log\LoggerInterface;

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
use MonkeysLegion\Database\Cache\Contracts\CacheInterface as DatabaseCacheInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Database\MySQL\Connection;
use MonkeysLegion\Cache\CacheManager;
use MonkeysLegion\Database\Cache\CacheManagerBridge;
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
use MonkeysLegion\I18n\TranslatorFactory;
use MonkeysLegion\I18n\LocaleManager;
use MonkeysLegion\I18n\Middleware\LocaleMiddleware;
use MonkeysLegion\Framework\Middleware\CallableMiddlewareAdapter;

use MonkeysLegion\Telemetry\Factory\TelemetryFactory;
use MonkeysLegion\Telemetry\Logging\TelemetryLogger;
use MonkeysLegion\Telemetry\Logging\TracingContextProvider;
use MonkeysLegion\Telemetry\Metrics\MetricsInterface;
use MonkeysLegion\Telemetry\Tracing\TracerInterface;

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

use MonkeysLegion\Files\FilesServiceProvider;
use MonkeysLegion\Files\FilesManager;
use MonkeysLegion\Files\Contracts\StorageInterface;
use MonkeysLegion\Files\Contracts\ChunkedUploadInterface;
use MonkeysLegion\Files\Image\ImageProcessor;
use MonkeysLegion\Files\Repository\FileRepository;
use MonkeysLegion\Files\Upload\ChunkedUploadManager;
use MonkeysLegion\Files\Storage\LocalStorage;
use MonkeysLegion\Files\RateLimit\UploadRateLimiter;
use MonkeysLegion\Files\Maintenance\GarbageCollector;
use MonkeysLegion\Files\Cdn\CdnUrlGenerator;
use MonkeysLegion\Files\Security\VirusScannerInterface;
use MonkeysLegion\Files\Security\ClamAvScanner;
use MonkeysLegion\Files\Security\HttpVirusScanner;

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
            (new ServerRequestFactory())->fromGlobals(),

            /* ----------------------------------------------------------------- */
            /* PSR-16 Cache (file-based fallback for rate-limiting)              */
            /* ----------------------------------------------------------------- */
            CacheInterface::class => fn() => new SimpleFileCache(
                base_path('var/cache/rate_limit')
            ),

            /* ----------------------------------------------------------------- */
            /* Redis Client (for rate limiting, caching, token storage)          */
            /* ----------------------------------------------------------------- */
            \Redis::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $redis = new \Redis();

                $host = $mlc->get('redis.host', '127.0.0.1');
                $port = (int) $mlc->get('redis.port', 6379);
                $timeout = (float) $mlc->get('redis.timeout', 0.0);
                $database = (int) $mlc->get('redis.database', 0);

                $connected = $redis->connect($host, $port, $timeout);

                if (!$connected) {
                    throw new \RuntimeException("Failed to connect to Redis at {$host}:{$port}");
                }

                // Optional authentication
                $password = $mlc->get('redis.password', null);
                if ($password !== null && $password !== '') {
                    $redis->auth($password);
                }

                // Select database
                if ($database > 0) {
                    $redis->select($database);
                }

                // Optional prefix for all keys
                $prefix = $mlc->get('redis.prefix', null);
                if ($prefix !== null && $prefix !== '') {
                    $redis->setOption(\Redis::OPT_PREFIX, $prefix);
                }

                return $redis;
            },

            /* ----------------------------------------------------------------- */
            /* Metrics / Telemetry (v2.0)                                         */
            /* ----------------------------------------------------------------- */
            MetricsInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return TelemetryFactory::createMetrics($mlc->get('telemetry.metrics', []));
            },

            TracerInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return TelemetryFactory::createTracer($mlc->get('telemetry.tracing', []));
            },

            TelemetryLogger::class => static function ($c) {
                return new TelemetryLogger(
                    logger: $c->get(LoggerInterface::class),
                    contextProvider: new TracingContextProvider($c->get(TracerInterface::class))
                );
            },

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
                base_path(),
                new SimpleFileCache(base_path('var/cache/mlc'))
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

            /* ----------------------------------------------------------------- */
            /* Internationalization (I18n)                                        */
            /* ----------------------------------------------------------------- */
            Translator::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                // Use factory to configure translator with file loader and cache
                return TranslatorFactory::create([
                    'locale'   => $mlc->get('app.locale', 'en'),
                    'fallback' => $mlc->get('app.fallback_locale', 'en'),
                    'path'     => base_path('resources/lang'),
                    'cache'    => $mlc->get('cache.enabled', true) ? $c->get(CacheInterface::class) : null,
                ]);
            },

            LocaleManager::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return TranslatorFactory::createLocaleManager([
                    'default'   => $mlc->get('app.locale', 'en'),
                    'fallback'  => $mlc->get('app.fallback_locale', 'en'),
                    'supported' => $mlc->get('app.supported_locales', ['en']),
                    'detectors' => $mlc->get('app.locale_detectors', ['url', 'session', 'cookie', 'header']),
                ]);
            },

            // Hack: Override the LocaleMiddleware service ID to return a PSR-15 adapter
            // This is necessary because LocaleMiddleware does not implement MiddlewareInterface
            LocaleMiddleware::class => static function ($c) {
                $localeMiddleware = new LocaleMiddleware(
                    $c->get(LocaleManager::class),
                    $c->get(Translator::class)
                );

                return new CallableMiddlewareAdapter($localeMiddleware);
            },

            /* ----------------------------------------------------------------- */
            /* Database                                                            */
            /* ----------------------------------------------------------------- */
            ConnectionInterface::class => function () {
                $path = base_path('config/database.php');
                if (file_exists($path)) {
                    $config = require $path;
                } else {
                    // Fallback for verification/testing
                    $config = [
                        'default' => 'sqlite',
                        'connections' => [
                            'sqlite' => [
                                'driver' => 'sqlite',
                                'database' => ':memory:',
                            ],
                        ],
                    ];
                }
                return ConnectionFactory::create($config);
            },
            Connection::class => function ($c) {
                return $c->get(ConnectionInterface::class);
            },

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

            RouteCollection::class => fn() => new RouteCollection(),

            RouteCache::class => fn() => new RouteCache(
                base_path('var/cache/routes')
            ),

            Router::class => static function ($c) {
                /** @var RouteCollection $collection */
                $collection = $c->get(RouteCollection::class);

                /** @var RouteCache $cache */
                $cache = $c->get(RouteCache::class);

                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $cacheEnabled = (bool) $mlc->get('routing.cache', false);

                if ($cacheEnabled && $cache->has()) {
                    $cached = $cache->load();
                    if ($cached !== null) {
                        $collection->import($cached);
                    }
                }

                $router = new Router($collection);

                $baseUrl = $mlc->get('app.url', '');
                if ($baseUrl) {
                    $router->getUrlGenerator()->setBaseUrl($baseUrl);
                }

                $globalMiddleware = $mlc->get('routing.global_middleware', []);
                foreach ($globalMiddleware as $middleware) {
                    $router->addGlobalMiddleware($middleware);
                }

                $middlewareGroups = $mlc->get('routing.middleware_groups', []);
                foreach ($middlewareGroups as $name => $middlewares) {
                    $router->registerMiddlewareGroup($name, $middlewares);
                }

                return $router;
            },

            UrlGenerator::class => fn($c) => $c->get(Router::class)->getUrlGenerator(),

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
            /* Rate-limit middleware (framework default)                          */
            /* ----------------------------------------------------------------- */
            RateLimitMiddleware::class =>
            fn($c) => new RateLimitMiddleware(
                $c->get(ResponseFactoryInterface::class),
                $c->get(CacheInterface::class),
                5000,
                60
            ),

            /* ----------------------------------------------------------------- */
            /* Legacy Authentication middleware (kept for compatibility)          */
            /* ----------------------------------------------------------------- */
            AuthMiddleware::class => fn($c) => new AuthMiddleware(
                $c->get(ResponseFactoryInterface::class),
                'Protected',
                (string)$c->get(MlcConfig::class)->get('auth.token', ''),
                $c->get(MlcConfig::class)->get('auth.public_paths', [])
            ),

            /* ----------------------------------------------------------------- */
            /* Simple logging middleware                                          */
            /* ----------------------------------------------------------------- */
            LoggingMiddleware::class    => fn() => new LoggingMiddleware(),

            /* ----------------------------------------------------------------- */
            /* Password Hasher                                                    */
            /* ----------------------------------------------------------------- */
            PasswordHasher::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $algorithm = match ($mlc->get('auth.password.algorithm', 'default')) {
                    'bcrypt' => PASSWORD_BCRYPT,
                    'argon2id' => PASSWORD_ARGON2ID,
                    default => PASSWORD_DEFAULT,
                };

                return new PasswordHasher(
                    algorithm: $algorithm,
                    cost: (int) $mlc->get('auth.password.cost', 12)
                );
            },

            /* ----------------------------------------------------------------- */
            /* JWT Service                                                        */
            /* ----------------------------------------------------------------- */
            JwtService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new JwtService(
                    secret: (string) $mlc->get('auth.jwt_secret', ''),
                    accessTtl: (int) $mlc->get('auth.access_ttl', 1800),
                    refreshTtl: (int) $mlc->get('auth.refresh_ttl', 604800),
                    leeway: (int) $mlc->get('auth.jwt_leeway', 60),
                    issuer: $mlc->get('auth.issuer', null),
                    audience: $mlc->get('auth.audience', null),
                );
            },

            /* ----------------------------------------------------------------- */
            /* Rate Limiter (Auth Package)                                        */
            /* ----------------------------------------------------------------- */
            RateLimiterInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driver = $mlc->get('auth.rate_limit.driver', 'cache');

                return match ($driver) {
                    'redis' => new RedisRateLimiter(
                        $c->get(\Redis::class)
                    ),
                    'cache' => new CacheRateLimiter(
                        $c->get(CacheInterface::class)
                    ),
                    default => new InMemoryRateLimiter(),
                };
            },

            /* ----------------------------------------------------------------- */
            /* User Provider                                                      */
            /* ----------------------------------------------------------------- */
            UserProviderInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new DatabaseUserProvider(
                    connection: $c->get(ConnectionInterface::class),
                    table: $mlc->get('auth.users.table', 'users'),
                    modelClass: $mlc->get('auth.users.model', 'App\\Entity\\User'),
                );
            },

            /* ----------------------------------------------------------------- */
            /* Token Storage (Blacklist & Refresh Tokens)                         */
            /* ----------------------------------------------------------------- */
            TokenStorageInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driver = $mlc->get('auth.token_storage.driver', 'memory');

                return match ($driver) {
                    'redis' => new RedisTokenStorage(
                        $c->get(\Redis::class),
                        $mlc->get('auth.token_storage.prefix', 'auth:')
                    ),
                    // 'database' => new DatabaseTokenStorage($c->get(ConnectionInterface::class)),
                    default => new InMemoryTokenStorage(),
                };
            },

            /* ----------------------------------------------------------------- */
            /* Core Auth Service                                                  */
            /* ----------------------------------------------------------------- */
            AuthService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthService(
                    users: $c->get(UserProviderInterface::class),
                    hasher: $c->get(PasswordHasher::class),
                    jwt: $c->get(JwtService::class),
                    tokenStorage: $c->get(TokenStorageInterface::class),
                    rateLimiter: $mlc->get('auth.rate_limit.enabled', true)
                        ? $c->get(RateLimiterInterface::class)
                        : null,
                    events: $c->get(EventDispatcherInterface::class),
                );
            },

            /* ----------------------------------------------------------------- */
            /* Two-Factor Authentication (TOTP)                                   */
            /* ----------------------------------------------------------------- */
            TotpProvider::class => fn() => new TotpProvider(),

            TwoFactorService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new TwoFactorService(
                    provider: $c->get(TotpProvider::class),
                    events: $c->get(EventDispatcherInterface::class),
                    issuer: $mlc->get('auth.two_factor.issuer', 'MonkeysLegion'),
                );
            },

            /* ----------------------------------------------------------------- */
            /* RBAC - Role Registry & Permission Checker                          */
            /* ----------------------------------------------------------------- */
            RoleRegistry::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $registry = new RoleRegistry();

                // Load roles from config
                $roles = $mlc->get('rbac.roles', []);
                if (!empty($roles)) {
                    $registry->registerFromConfig($roles);
                }

                return $registry;
            },

            PermissionChecker::class => fn($c) => new PermissionChecker(
                $c->get(RoleRegistry::class)
            ),

            RbacService::class => fn($c) => new RbacService(
                $c->get(RoleRegistry::class),
                $c->get(PermissionChecker::class)
            ),

            /* ----------------------------------------------------------------- */
            /* Authorization Gate & Service                                       */
            /* ----------------------------------------------------------------- */
            Gate::class => static function ($c) {
                $gate = new Gate();

                // Register policies here or via a PolicyServiceProvider
                // Example:
                // $gate->policy(\App\Entity\Post::class, \App\Policy\PostPolicy::class);

                return $gate;
            },

            AuthorizationService::class => fn($c) => new AuthorizationService(
                $c->get(PermissionChecker::class)
            ),

            /* ----------------------------------------------------------------- */
            /* OAuth2 Service                                                     */
            /* ----------------------------------------------------------------- */
            OAuthService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $oauth = new OAuthService(
                    pdo: $c->get(ConnectionInterface::class)->pdo(),
                    jwt: $c->get(JwtService::class),
                    users: $c->get(UserProviderInterface::class),
                );

                // Register Google provider if enabled
                if ($mlc->get('oauth.google.enabled', false)) {
                    $baseUrl = $mlc->get('app.url', '');
                    $oauth->registerProvider(new GoogleProvider(
                        clientId: $mlc->get('oauth.google.client_id', ''),
                        clientSecret: $mlc->get('oauth.google.client_secret', ''),
                        redirectUri: $baseUrl . $mlc->get('oauth.google.redirect_uri', '/oauth/google/callback'),
                    ));
                }

                // Register GitHub provider if enabled
                if ($mlc->get('oauth.github.enabled', false)) {
                    $baseUrl = $mlc->get('app.url', '');
                    $oauth->registerProvider(new GitHubProvider(
                        clientId: $mlc->get('oauth.github.client_id', ''),
                        clientSecret: $mlc->get('oauth.github.client_secret', ''),
                        redirectUri: $baseUrl . $mlc->get('oauth.github.redirect_uri', '/oauth/github/callback'),
                    ));
                }

                return $oauth;
            },

            /* ----------------------------------------------------------------- */
            /* API Key Service                                                    */
            /* ----------------------------------------------------------------- */
            // ApiKeyService::class => fn($c) => new ApiKeyService(
            // Requires ApiKeyRepositoryInterface implementation
            // $c->get(ApiKeyRepositoryInterface::class)
            // ),

            /* ----------------------------------------------------------------- */
            /* Password Reset Service                                             */
            /* ----------------------------------------------------------------- */
            PasswordResetService::class => fn($c) => new PasswordResetService(
                users: $c->get(UserProviderInterface::class),
                hasher: $c->get(PasswordHasher::class),
                jwt: $c->get(JwtService::class),
                events: $c->get(EventDispatcherInterface::class),
            ),

            /* ----------------------------------------------------------------- */
            /* Email Verification Service                                         */
            /* ----------------------------------------------------------------- */
            EmailVerificationService::class => fn($c) => new EmailVerificationService(
                users: $c->get(UserProviderInterface::class),
                jwt: $c->get(JwtService::class),
                events: $c->get(EventDispatcherInterface::class),
            ),

            /* ----------------------------------------------------------------- */
            /* Authentication Middleware (JWT)                                    */
            /* ----------------------------------------------------------------- */
            AuthenticationMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthenticationMiddleware(
                    auth: $c->get(AuthService::class),
                    users: $c->get(UserProviderInterface::class),
                    publicPaths: $mlc->get('auth.public_paths', []),
                    responseFactory: function (\Throwable $e) use ($c) {
                        return $c->get(ResponseFactoryInterface::class)
                            ->createResponse(401)
                            ->withHeader('Content-Type', 'application/json');
                    },
                );
            },

            /* ----------------------------------------------------------------- */
            /* Authorization Middleware (RBAC + Policies)                         */
            /* ----------------------------------------------------------------- */
            AuthorizationMiddleware::class => static function ($c) {
                return new AuthorizationMiddleware(
                    authorization: $c->get(AuthorizationService::class),
                    permissions: $c->get(PermissionChecker::class),
                    publicPaths: [],
                    responseFactory: function (\Throwable $e) use ($c) {
                        $code = match (true) {
                            $e instanceof \MonkeysLegion\Auth\Exception\UnauthorizedException => 401,
                            $e instanceof \MonkeysLegion\Auth\Exception\ForbiddenException => 403,
                            default => 500,
                        };

                        return $c->get(ResponseFactoryInterface::class)
                            ->createResponse($code)
                            ->withHeader('Content-Type', 'application/json');
                    },
                );
            },

            /* ----------------------------------------------------------------- */
            /* Auth Rate Limit Middleware                                         */
            /* ----------------------------------------------------------------- */
            AuthRateLimitMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthRateLimitMiddleware(
                    limiter: $c->get(RateLimiterInterface::class),
                    defaultMaxAttempts: (int) $mlc->get('auth.rate_limit.max_attempts', 60),
                    defaultDecaySeconds: (int) $mlc->get('auth.rate_limit.lockout_seconds', 60),
                    responseFactory: $c->get(ResponseFactoryInterface::class),
                );
            },

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
            DatabaseCacheInterface::class => function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->get('cache', []);

                $manager = new CacheManager($config);
                return new CacheManagerBridge($manager, $config['prefix'] ?? '');
            },

            /* ----------------------------------------------------------------- */
            /* Files Package                                                      */
            /* ----------------------------------------------------------------- */

            StorageInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $diskConfig = $mlc->get('files.disks.local', [
                    'driver' => 'local',
                    'root' => base_path('storage/files'),
                    'visibility' => 'public',
                ]);

                return new LocalStorage(
                    basePath: $diskConfig['root'] ?? base_path('storage/files'),
                    baseUrl: $diskConfig['url'] ?? '/storage/files',
                    directoryPermissions: $diskConfig['permissions']['dir'] ?? 0755,
                    filePermissions: $diskConfig['permissions']['file'] ?? 0644,
                    visibility: $diskConfig['visibility'] ?? 'public',
                );
            },

            FilesManager::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $manager = new FilesManager(
                    config: $mlc->get('files', []),
                    logger: $c->get(LoggerInterface::class),
                );

                // Set cache if available
                $cacheConfig = $mlc->get('cache', []);
                if (!empty($cacheConfig) && isset($cacheConfig['driver'])) {
                    $cacheManager = new CacheManager($cacheConfig);
                    $manager->setCache($cacheManager->store());
                }

                // Register the default storage disk
                $manager->addDisk('local', $c->get(StorageInterface::class));

                // Set file repository if database tracking enabled
                if ($mlc->get('files.database.enabled', false)) {
                    $manager->setRepository($c->get(FileRepository::class));
                }

                return $manager;
            },

            ImageProcessor::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ImageProcessor(
                    driver: $mlc->get('files.image.driver', 'gd'),
                    quality: (int) $mlc->get('files.image.quality', 85),
                );
            },

            ChunkedUploadInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ChunkedUploadManager(
                    storage: $c->get(StorageInterface::class),
                    tempDir: $mlc->get('files.upload.temp_dir', sys_get_temp_dir() . '/ml-uploads'),
                    cache: (new CacheManager($mlc->get('cache', [])))->store(),
                    chunkSize: (int) $mlc->get('files.upload.chunk_size', 5 * 1024 * 1024),
                    uploadExpiry: (int) $mlc->get('files.upload.chunk_expiry', 86400),
                );
            },

            ChunkedUploadManager::class => fn($c) => $c->get(ChunkedUploadInterface::class),

            FileRepository::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new FileRepository(
                    connection: $c->get(ConnectionInterface::class),
                    tableName: $mlc->get('files.database.tables.files', 'ml_files'),
                    conversionsTable: $mlc->get('files.database.tables.conversions', 'ml_file_conversions'),
                    trackAccess: (bool) $mlc->get('files.database.track_access', true),
                    softDelete: (bool) $mlc->get('files.database.soft_delete', true),
                );
            },

            UploadRateLimiter::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new UploadRateLimiter(
                    cache: new CacheManager($mlc->get('cache', [])),
                    maxUploadsPerMinute: (int) $mlc->get('files.rate_limiting.uploads_per_minute', 10),
                    maxBytesPerHour: (int) $mlc->get('files.rate_limiting.bytes_per_hour', 104857600),
                    maxConcurrentUploads: (int) $mlc->get('files.rate_limiting.concurrent_uploads', 3),
                );
            },

            GarbageCollector::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new GarbageCollector(
                    storage: $c->get(StorageInterface::class),
                    repository: $mlc->get('files.database.enabled', false)
                        ? $c->get(FileRepository::class)
                        : null,
                    config: [
                        'deleted_files_days' => (int) $mlc->get('files.garbage_collection.deleted_files_days', 30),
                        'incomplete_uploads_hours' => (int) $mlc->get('files.garbage_collection.incomplete_uploads_hours', 24),
                        'unused_conversions_days' => (int) $mlc->get('files.garbage_collection.unused_conversions_days', 7),
                    ],
                    logger: $c->get(LoggerInterface::class),
                );
            },
        ];
    }

    /**
     * Called by your bootstrap to add framework defaults.
     */
    public static function register(string $basePath, ContainerBuilder $builder): void
    {
        // Fix for OAuthService expecting legacy JwtService class
        if (!class_exists('MonkeysLegion\Auth\JwtService')) {
            class_alias(\MonkeysLegion\Auth\Service\JwtService::class, 'MonkeysLegion\Auth\JwtService');
        }

        $builder->addDefinitions((new self())());
    }
}
