<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Core\Routing\RouteLoader;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\RouteCache;
use MonkeysLegion\Router\RouteCollection;
use MonkeysLegion\Router\Router;
use MonkeysLegion\Router\UrlGenerator;

final class RoutingProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
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
        ];
    }
}
