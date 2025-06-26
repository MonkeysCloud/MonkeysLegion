<?php
namespace MonkeysLegion\Framework;

use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\RouteRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Message\ServerRequest;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Router;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final class HttpBootstrap
{
    /** Build container with framework defaults + project overrides */
    public static function buildContainer(string $root): ContainerInterface
    {
        $b = new ContainerBuilder();
        $b->addDefinitions((new AppConfig())());                 // framework
        if (is_file($root . '/config/app.php')) {                // project
            $b->addDefinitions(require $root . '/config/app.php');
        }
        return $b->build();
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
}