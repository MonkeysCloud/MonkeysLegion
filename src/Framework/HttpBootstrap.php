<?php
namespace MonkeysLegion\Framework;

use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\RouteRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Message\ServerRequest;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Router;
use Psr\Http\Message\ResponseFactoryInterface;

final class HttpBootstrap
{
    /**
     * Build your container (framework defaults + app overrides).
     */
    public static function buildContainer(string $projectRoot)
    {
        $builder = new ContainerBuilder();

        // 1) framework defaults
        $builder->addDefinitions(new AppConfig()());

        // 2) app‐specific overrides
        $override = $projectRoot . '/config/app.php';
        if (is_file($override)) {
            $builder->addDefinitions(require $override);
        }

        return $builder->build();
    }

    /**
     * Run the entire HTTP flow, optionally letting the app override
     * any part via a callback.
     *
     * @param string $projectRoot
     * @param callable|null $customizer
     *        Signature: function(
     *           \Psr\Container\ContainerInterface $container,
     *           ServerRequest                        $request,
     *           Router                               $router,
     *           ResponseFactoryInterface             $responseFactory
     *        ): \Psr\Http\Message\ResponseInterface
     */
    public static function run(string $projectRoot, ?callable $customizer = null): void
    {
        // build & expose
        $container = self::buildContainer($projectRoot);
        define('ML_CONTAINER', $container);

        // auto-discover your controllers
        $container->get(RouteLoader::class)
            ->loadControllers();

        // create the PSR-7 request
        $request = ServerRequest::fromGlobals();

        // grab router & response factory (in case the app needs them)
        $router          = $container->get(Router::class);
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        // if the app passed in a custom runner, delegate to it
        if ($customizer) {
            $response = $customizer($container, $request, $router, $responseFactory);
        } else {
            // otherwise use the standard pipeline
            $routeHandler = $container->get(RouteRequestHandler::class);
            $core         = new CoreRequestHandler($routeHandler, $responseFactory);

            /** @var MlcConfig $mlc */
            $mlc = $container->get(MlcConfig::class);
            foreach ($mlc->get('middleware.global', []) as $id) {
                $core->pipe($container->get($id));
            }

            $response = $core->handle($request);
        }

        // emit back to the client
        $container->get(SapiEmitter::class)
            ->emit($response);
    }
}