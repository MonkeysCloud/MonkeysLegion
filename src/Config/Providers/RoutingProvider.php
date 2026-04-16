<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\ControllerScanner;
use MonkeysLegion\Router\RouteCache;
use MonkeysLegion\Router\RouteCollection;
use MonkeysLegion\Router\Router;
use MonkeysLegion\Router\UrlGenerator;
use Psr\Container\ContainerInterface;

/**
 * Router, route collection, controller scanner, and URL generator provider.
 *
 * HTTP-only context. Uses the Router package's ControllerScanner for
 * attribute-based route discovery.
 */
final class RoutingProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            RouteCollection::class => fn(): RouteCollection => new RouteCollection(),

            RouteCache::class => fn(): RouteCache => new RouteCache(
                base_path('var/cache/routes'),
            ),

            Router::class => static function ($c): Router {
                /** @var RouteCollection $collection */
                $collection = $c->get(RouteCollection::class);

                $router = new Router($collection);

                // Inject container so router can resolve controller classes
                if ($c instanceof ContainerInterface) {
                    $router->setContainer($c);
                }

                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                // Register global middleware
                $globalMiddleware = $mlc->getArray('routing.global_middleware', []) ?? [];

                foreach ($globalMiddleware as $middleware) {
                    $router->addGlobalMiddleware($middleware);
                }

                // Register middleware groups
                $middlewareGroups = $mlc->getArray('routing.middleware_groups', []) ?? [];

                foreach ($middlewareGroups as $name => $middlewares) {
                    if (is_array($middlewares)) {
                        $router->registerMiddlewareGroup($name, $middlewares);
                    }
                }

                return $router;
            },

            UrlGenerator::class => fn(): UrlGenerator => new UrlGenerator(),

            /* Controller scanner for attribute-based route discovery */
            ControllerScanner::class => fn($c): ControllerScanner => new ControllerScanner(
                $c->get(Router::class),
            ),
        ];
    }
}
