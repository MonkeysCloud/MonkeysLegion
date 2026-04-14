<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

use MonkeysLegion\Cli\Application\MLRunner;
use MonkeysLegion\Cli\CliKernel;
use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Config\LoggerConfig;
use MonkeysLegion\Core\Attribute\Provider;
use MonkeysLegion\Core\Error\Renderer\PlainTextErrorRenderer;
use MonkeysLegion\Session\SessionServiceProvider;
use MonkeysLegion\Router\ControllerScanner;
use MonkeysLegion\DI\CompiledContainerCache;
use MonkeysLegion\DI\Container;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Env\Contracts\EnvBootstrapperInterface;
use MonkeysLegion\Env\EnvManager;
use MonkeysLegion\Env\Loaders\DotenvLoader;
use MonkeysLegion\Env\Repositories\NativeEnvRepository;
use MonkeysLegion\Files\FilesServiceProvider;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Message\ServerRequest;
use MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Router;
use MonkeysLegion\Framework\Provider\ProviderScanner;
use MonkeysLegion\Http\Error\ErrorHandler;
use MonkeysLegion\Http\Error\Renderer\BasicHtmlErrorRenderer;
use MonkeysLegion\Http\Error\Renderer\HtmlErrorRenderer;
use MonkeysLegion\Http\Error\Renderer\JsonErrorRenderer;
use MonkeysLegion\Mlc\Contracts\ParserInterface;
use MonkeysLegion\Session\SessionManager;
use MonkeysLegion\Template\Loader;
use MonkeysLegion\Template\Renderer;
use MonkeysLegion\Template\TemplateServiceProvider;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class HttpBootstrap
{

    private static ?ErrorHandler $errorHandler = null;

    /** 
     * Build container with framework defaults + project overrides
     * 
     * @param string $root project root (usually ML_BASE_PATH)
     * @param null|EnvBootstrapperInterface $envBootstrapper optional env bootstrapper for custom env loading
     * @return Container
     */
    public static function buildContainer(string $root, ?EnvBootstrapperInterface $envBootstrapper = null): Container
    {
        // Set the global request instance for HttpFactory so it's available throughout the app (e.g. in error handlers)
        $req = ServerRequest::fromGlobals();

        $envBootstrapper = self::bootstrapEnv($root, $envBootstrapper);

        // Register error handler
        self::registerErrorHandler();

        // Bootstrap logger early so it's available during container build
        $logger = self::getAppLogger();

        // configure the error handler with a logger
        self::configureErrorHandlerLogger($logger);

        $b = new ContainerBuilder();

        // 1) Production compiled cache — skip all provider instantiation
        $cachePath = $root . '/var/cache/container.php';
        $env = $_ENV['APP_ENV'] ?? 'dev';
        $cached = null;

        if ($env === 'production' && CompiledContainerCache::exists($cachePath)) {
            $cached = CompiledContainerCache::load($cachePath);
        }

        if ($cached !== null) {
            $b->addDefinitions($cached);
        } else {
            // 1a) framework definitions via modular providers
            $b->addDefinitions((new AppConfig())());
        }

        // 2) project overrides (always applied, even on cached boots)
        if (is_file($root . '/config/app.php')) {
            $b->addDefinitions(require $root . '/config/app.php');
        }
        // 2.1) add env bootstrapper
        $b->addDefinitions([
            EnvBootstrapperInterface::class => fn() => $envBootstrapper,
        ]);

        // 2.2) register package service providers (interface → concrete bindings)
        $b->addProvider(new TemplateServiceProvider());
        $b->addProvider(new SessionServiceProvider());

        // 3) now build the container
        $container = $b->build();

        // Only switch to HTML error renderer for HTTP requests (not CLI)
        self::switchToHtmlRendererIfUsed(
            $container->get(Loader::class),
            $container->get(Renderer::class),
            $req,
            $container->has(SessionManager::class) ? $container->get(SessionManager::class) : null
        );

        // 4) register the Files provider with the built container
        (new FilesServiceProvider(
            container: $container,
            config: null,
            cacheManager: null,
            dbConnection: null,
            logger: null,
            parser: $container->get(ParserInterface::class) ?? null,
        ))->register();

        // 5) Scan and run attribute-based providers
        self::runAttributeProviders($container, $root);

        // 6) Configure PHP-native error logging based on .mlc settings
        /** @var MlcConfig $mlc */
        $mlc     = $container->get(MlcConfig::class);
        $debug = $mlc->get('app.debug', []);
        $logging = $mlc->get('logging', []);

        if ($debug && isset($logging['php_errors']) && $logging['php_errors']['enabled'] ?? false) {
            // show all errors
            error_reporting(E_ALL);
            ini_set(
                'display_errors',
                $logging['php_errors']['display'] ?? 'stderr'
            );
            ini_set('log_errors', '1');
            ini_set(
                'error_log',
                base_path(
                    $logging['php_errors']['file']
                        ?? 'var/log/php-errors.log'
                )
            );
        }

        return $container;
    }

    /**
     * Run the whole HTTP flow.
     *
     * @param string $root project root (usually ML_BASE_PATH)
     * @param null|callable $customizer optional closure to customise the run
     *                                   function (
     *                                   ContainerInterface $c,
     *                                   ServerRequest      $req,
     *                                   Router             $router,
     *                                   ResponseFactoryInterface $rf
     *                                   ): ResponseInterface
     * @param null|EnvBootstrapperInterface $envBootstrapper optional env bootstrapper for custom env loading
     * @throws \Throwable
     */
    public static function run(string $root, ?callable $customizer = null, ?EnvBootstrapperInterface $envBootstrapper = null): void
    {
        $c = self::buildContainer($root, $envBootstrapper);

        define('ML_CONTAINER', $c);

        // boot any necessary services (e.g. ML Runner for inline tasks)
        self::boot($c);

        // auto-discover controllers (new router scanner)
        $c->get(ControllerScanner::class)->scan(
            $root . '/app/Controller',
            'App\\Controller'
        );

        // build request & grab router / factory
        $req  = ServerRequest::fromGlobals();
        $rt   = $c->get(Router::class);
        $rf   = $c->get(ResponseFactoryInterface::class);

        // delegate to app-supplied closure or use default pipeline
        $res = $customizer
            ? $customizer($c, $req, $rt, $rf)
            : self::defaultPipeline($c, $req);

        // emit
        $c->get(SapiEmitter::class)->emit($res);
    }

    /**
     * Register global error handler
     */
    private static function registerErrorHandler(): void
    {
        static $registered = false;
        if ($registered) {
            return;
        }

        self::$errorHandler = new ErrorHandler();

        if (PHP_SAPI === 'cli') {
            self::$errorHandler->useRenderer(new PlainTextErrorRenderer());
        } elseif (str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') || str_starts_with($_SERVER['REQUEST_URI'], '/api')) {
            self::$errorHandler->useRenderer(new JsonErrorRenderer());
        } else {
            self::$errorHandler->useRenderer(new BasicHtmlErrorRenderer());
        }

        self::$errorHandler->register();
        $registered = true;
    }

    private static function switchToHtmlRendererIfUsed(
        Loader $loader,
        Renderer $renderer,
        ServerRequest $request,
        ?SessionManager $session = null
    ) {
        if (PHP_SAPI === 'cli' || str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')) {
            // no switch required
        } else {
            self::$errorHandler->useRenderer(new HtmlErrorRenderer(
                loader: $loader,
                renderer: $renderer,
                request: $request,
                session: $session
            ));
        }
    }

    /** Default PSR-15 pipeline driven by middleware.global
     * @throws \Throwable
     */
    private static function defaultPipeline(
        ContainerInterface        $c,
        ServerRequest             $req
    ): ResponseInterface {
        $core = new CoreRequestHandler($c->get(RequestHandlerInterface::class));
        /** @var MlcConfig $mlc */
        $mlc = $c->get(MlcConfig::class);

        foreach ($mlc->get('middleware.global', []) as $id) {
            $core->pipe(
                $c->get(ltrim($id, '\\'))
            );
        }

        return $core->handle($req);
    }

    private static function bootstrapEnv(string $root, ?EnvBootstrapperInterface $envBootstrapper = null): EnvBootstrapperInterface
    {
        if ($envBootstrapper === null) {
            $envManager = new EnvManager(
                new DotenvLoader(),
                new NativeEnvRepository()
            );
            if (!$envManager->isBooted()) {
                $envManager->boot($root);
            }
            return $envManager;
        } else {
            $envBootstrapper->boot($root);
            return $envBootstrapper;
        }
    }

    private static function getAppLogger(): MonkeysLoggerInterface
    {
        $b = new ContainerBuilder();
        $b->addDefinitions((new LoggerConfig())());
        $cb = $b->build();

        // Ensure the logger is set up correctly
        if (!$cb->has(MonkeysLoggerInterface::class)) {
            throw new \RuntimeException('LoggerInterface is not defined in the container.');
        }

        /** @var MonkeysLoggerInterface $logger */
        $logger = $cb->get(MonkeysLoggerInterface::class);
        return $logger;
    }

    private static function registerExtras($root, MonkeysLoggerInterface $logger): array
    {
        $composerExtraProviders = [];
        $installedJson = $root . '/vendor/composer/installed.json';

        if (!file_exists($installedJson)) {
            throw new \RuntimeException("Composer metadata not found. Run 'composer install' first.");
        }

        $data = json_decode(file_get_contents($installedJson), true);
        $packages = $data['packages'] ?? [];

        $composerExtraProviders = [];

        foreach ($packages as $package) {
            // Check if the package has the "monkeyslegion" extra key
            if (isset($package['extra']['monkeyslegion']['providers'])) {
                $providers = $package['extra']['monkeyslegion']['providers'];

                // Merge them into your list
                foreach ($providers as $provider) {
                    $composerExtraProviders[] = $provider;
                }
            }
        }
        // filer Providers that don't adapt #[Provider] attribute and Filter duplication
        $filteredProviders = [];
        foreach ($composerExtraProviders as $providerClass) {
            if (class_exists($providerClass)) {
                $reflectionClass = new \ReflectionClass($providerClass);
                $attributes = $reflectionClass->getAttributes(Provider::class);
                if (!empty($attributes)) {
                    $filteredProviders[] = $providerClass;
                } else {
                    $logger->warning(sprintf(
                        "Provider %s is registered in composer.json but does not have the #[Provider] attribute. Skipping.",
                        $providerClass
                    ));
                }
            } else {
                $logger->warning(sprintf(
                    "Provider class %s defined in composer.json not found. Skipping.",
                    $providerClass
                ));
            }
        }

        return $filteredProviders;
    }

    /**
     * Scan for providers with #[Provider] attribute and run their register() method.
     */
    private static function runAttributeProviders(ContainerInterface $c, string $root): void
    {
        $scanner = new ProviderScanner();
        $providers = $scanner->scan($root . '/app/Providers', 'App\\Providers');
        $providers = [...$providers, ...self::registerExtras($root, $c->get(MonkeysLoggerInterface::class))];

        foreach ($providers as $class) {
            $instance = $c->get($class);
            if (method_exists($instance, 'register')) {
                $method = new \ReflectionMethod($instance, 'register');
                $args = [];

                foreach ($method->getParameters() as $parameter) {
                    $type = $parameter->getType();

                    if ($type instanceof \ReflectionNamedType && !$type->isBuiltin()) {
                        $args[] = $c->get($type->getName());
                    } elseif ($parameter->isDefaultValueAvailable()) {
                        $args[] = $parameter->getDefaultValue();
                    } else {
                        // If it's the container itself
                        if ($type instanceof \ReflectionNamedType && $type->getName() === ContainerInterface::class) {
                            $args[] = $c;
                        } else {
                            throw new \RuntimeException(sprintf(
                                "Cannot resolve parameter '%s' for %s::register()",
                                $parameter->getName(),
                                $class
                            ));
                        }
                    }
                }

                $method->invokeArgs($instance, $args);
            }
        }
    }

    /**
     * Configure the error handler with a logger
     */
    private static function configureErrorHandlerLogger(MonkeysLoggerInterface $logger): void
    {
        if (self::$errorHandler !== null) {
            self::$errorHandler->useLogger($logger);
        }
    }

    private static function boot(ContainerInterface $c): void
    {
        // boot the ml runner if we're in a CLI context - this allows us to run inline tasks with `php ml runner run ...`
        MLRunner::boot($c->get(CliKernel::class));
    }
}
