<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Core\Middleware\CorsMiddleware;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Middleware\AuthMiddleware;
use MonkeysLegion\Http\Middleware\ErrorHandlerMiddleware;
use MonkeysLegion\Http\Middleware\LoggingMiddleware;
use MonkeysLegion\Http\Middleware\RateLimitMiddleware;
use MonkeysLegion\Http\MiddlewareDispatcher;
use MonkeysLegion\Http\RouteRequestHandler;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\SimpleCache\CacheInterface;

final class MiddlewareProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            /* Route → PSR-15 adapter */
            RouteRequestHandler::class => fn($c) => new RouteRequestHandler(
                $c->get(\MonkeysLegion\Router\Router::class)
            ),

            /* Core handler */
            CoreRequestHandler::class => fn($c) => new CoreRequestHandler(
                $c->get(RouteRequestHandler::class),
                $c->get(ResponseFactoryInterface::class)
            ),

            /* CORS */
            CorsMiddleware::class => fn($c) => new CorsMiddleware(
                allowOrigin:      $c->get(MlcConfig::class)->get('cors.allow_origin', '*'),
                allowMethods:     $c->get(MlcConfig::class)->get('cors.allow_methods', ['GET', 'POST', 'OPTIONS', 'PATCH', 'DELETE']),
                allowHeaders:     $c->get(MlcConfig::class)->get('cors.allow_headers', ['Content-Type', 'Authorization']),
                exposeHeaders:    $c->get(MlcConfig::class)->get('cors.expose_headers', null),
                allowCredentials: (bool)$c->get(MlcConfig::class)->get('cors.allow_credentials', false),
                maxAge:           (int)$c->get(MlcConfig::class)->get('cors.max_age', 0),
                responseFactory:  $c->get(ResponseFactoryInterface::class)
            ),

            /* Error handler */
            ErrorHandlerMiddleware::class => fn() => new ErrorHandlerMiddleware(),

            /* Rate-limit */
            RateLimitMiddleware::class => fn($c) => new RateLimitMiddleware(
                $c->get(ResponseFactoryInterface::class),
                $c->get(CacheInterface::class),
                5000,
                60
            ),

            /* Legacy auth */
            AuthMiddleware::class => fn($c) => new AuthMiddleware(
                $c->get(ResponseFactoryInterface::class),
                'Protected',
                (string)$c->get(MlcConfig::class)->get('auth.token', ''),
                $c->get(MlcConfig::class)->get('auth.public_paths', [])
            ),

            /* Logging */
            LoggingMiddleware::class => fn() => new LoggingMiddleware(),

            /* SAPI emitter */
            SapiEmitter::class => fn() => new SapiEmitter(),

            /* PSR-15 pipeline (driven by middleware.mlc) */
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
        ];
    }
}
