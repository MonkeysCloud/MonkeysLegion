<?php

namespace MonkeysLegion\Framework;

use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Files\Support\ServiceProvider as FilesServiceProvider;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\RouteRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Message\ServerRequest;
use MonkeysLegion\Logger\FrameworkLoggerInterface;
use MonkeysLegion\Mail\Provider\MailServiceProvider;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Router;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

final class HttpBootstrap
{
    /** Build container with framework defaults + project overrides */
    public static function buildContainer(string $root): ContainerInterface
    {
        self::bootstrapEnv($root);

        $b = new ContainerBuilder();

        // 1) framework definitions
        $b->addDefinitions((new AppConfig())());

        // 2) project overrides
        if (is_file($root . '/config/app.php')) {
            $b->addDefinitions(require $root . '/config/app.php');
        }

        // 3) register the Files provider onto the *builder*
        (new FilesServiceProvider())->register($b);

        // 4) mail provider also onto builder
        MailServiceProvider::register($b);

        // 5) now build the container
        $container = $b->build();

        // 6) set up mail logger(SOON GONNA BE REMOVED)
        // Set logger after container is built 
        MailServiceProvider::setLogger(
            $container->get(LoggerInterface::class)
        );

        // Set LoggerInterface/Environment to the framework logger
        $container->get(FrameworkLoggerInterface::class)
            ->setLogger($container->get(LoggerInterface::class))
            ->setEnvironment((string) $container->get(MlcConfig::class)->get('app.env', 'dev'));

        return $container;
    }

    /**
     * Run the whole HTTP flow.
     *
     * @param string        $root        project root (usually ML_BASE_PATH)
     * @param null|callable $customizer  optional closure to customise the run
     *                                   function (
     *                                   ContainerInterface $c,
     *                                   ServerRequest      $req,
     *                                   Router             $router,
     *                                   ResponseFactoryInterface $rf
     *                                   ): ResponseInterface
     */
    public static function run(string $root, ?callable $customizer = null): void
    {
        $c = self::buildContainer($root);
        define('ML_CONTAINER', $c);

        // Configure PHP-native error logging based on .mlc settings
        /** @var MlcConfig $mlc */
        $mlc     = $c->get(MlcConfig::class);
        $logging = $mlc->get('logging', []);

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

    /** Default PSR-15 pipeline driven by middleware.global */
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
        if ($loaded) {            // idempotent
            return;
        }

        $envBootstrap = $root . '/bootstrap/env.php';   // <-- your file
        if (is_file($envBootstrap)) {
            require $envBootstrap;                    // loads vlucas/phpdotenv
        }

        $loaded = true;
    }
}
