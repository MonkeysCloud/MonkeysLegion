<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Config\LoggerConfig;
use MonkeysLegion\Core\Provider\ProviderInterface;
use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\DI\Container;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Files\FilesServiceProvider;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\RouteRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Message\ServerRequest;
use MonkeysLegion\Http\Error\ErrorHandler;
use MonkeysLegion\Http\Error\Renderer\{PlainTextErrorRenderer, JsonErrorRenderer, HtmlErrorRenderer};
use MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface;
use MonkeysLegion\Mail\Provider\MailServiceProvider;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Router;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final class HttpBootstrap
{

    private static ?ErrorHandler $errorHandler = null;

    /** Build container with framework defaults + project overrides */
    public static function buildContainer(string $root): Container
    {
        // Register error handler
        self::registerErrorHandler();

        self::bootstrapEnv($root);

        // Bootstrap logger early so it's available during container build
        $logger = self::getAppLogger();

        // configure the error handler with a logger
        self::configureErrorHandlerLogger($logger);

        $b = new ContainerBuilder();

        // 1) framework definitions
        $b->addDefinitions((new AppConfig())());

        // 2) project overrides
        if (is_file($root . '/config/app.php')) {
            $b->addDefinitions(require $root . '/config/app.php');
        }

        // 3) set up mail logger after container is built
        MailServiceProvider::setLogger($logger);

        // 4) mail provider also onto builder
        MailServiceProvider::register($root, $b);

        // 4.1) register any extra providers from composer.json
        self::registerExtras($b, $root, $logger);

        // 5) now build the container
        $container = $b->build();

        // 6) register the Files provider with the built container
        (new FilesServiceProvider($container))->register();

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
     * @throws \Throwable
     */
    public static function run(string $root, ?callable $customizer = null): void
    {
        $c = self::buildContainer($root);
        define('ML_CONTAINER', $c);

        // Configure PHP-native error logging based on .mlc settings
        /** @var MlcConfig $mlc */
        $mlc     = $c->get(MlcConfig::class);
        $logging = $mlc->get('logging', []);

        // Enable/Disable debug mode in error handler by looking at debug/logging
        self::$errorHandler->setDebug(self::$errorHandler !== null && !empty($logging['enabled']) && ($logging['stdout']['level'] ?? '') === 'debug');

        if (! empty($logging['php_errors']['enabled'])) {
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

        // auto-discover controllers
        $c->get(RouteLoader::class)->loadControllers();

        // build request & grab router / factory
        $req  = ServerRequest::fromGlobals();
        $rt   = $c->get(Router::class);
        $rf   = $c->get(ResponseFactoryInterface::class);

        // delegate to app-supplied closure or use default pipeline
        $res = $customizer
            ? $customizer($c, $req, $rt, $rf)
            : self::defaultPipeline($c, $req, $rf);

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
            self::$errorHandler->useRenderer(new HtmlErrorRenderer());
        }

        self::$errorHandler->register();
        $registered = true;
    }

    /** Default PSR-15 pipeline driven by middleware.global
     * @throws \Throwable
     */
    private static function defaultPipeline(
        ContainerInterface        $c,
        ServerRequest             $req,
        ResponseFactoryInterface  $rf
    ): ResponseInterface {
        $core = new CoreRequestHandler(
            $c->get(RouteRequestHandler::class),
            $rf
        );
        /** @var MlcConfig $mlc */
        $mlc = $c->get(MlcConfig::class);

        foreach ($mlc->get('middleware.global', []) as $id) {
            $core->pipe(
                $c->get(ltrim($id, '\\'))
            );
        }

        return $core->handle($req);
    }

    private static function bootstrapEnv(string $root): void
    {
        static $loaded = false;
        if ($loaded) {
            return;
        }

        $envBootstrap = $root . '/bootstrap/env.php';
        if (is_file($envBootstrap)) {
            require $envBootstrap;
        }

        $loaded = true;
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

    private static function registerExtras(ContainerBuilder $b, $root, MonkeysLoggerInterface $logger): void
    {
        $composerExtraProviders = [];
        $composerJson = $root . '/composer.json';
        if (is_file($composerJson)) {
            $composerData = json_decode(file_get_contents($composerJson), true);
            $composerExtraProviders = $composerData['extra']['monkeyslegion']['providers'] ?? [];
        }

        foreach ($composerExtraProviders as $providerClass) {
            if (!class_exists($providerClass)) continue;
            /** @var ProviderInterface $providerClass */

            try {
                if (method_exists($providerClass, 'setLogger')) {
                    $providerClass::setLogger($logger);
                }
                if (method_exists($providerClass, 'register')) {
                    $providerClass::register(base_path(), $b);
                }
            } catch (\Exception $e) {
                $logger->error(
                    "Failed to register provider: {$providerClass}",
                    ['exception' => $e]
                );
                // don't stop the bootstrap process if a provider fails
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
}
