<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Core\Error\Renderer\ErrorRendererInterface;
use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Middleware\AuthMiddleware;
use MonkeysLegion\Http\Middleware\CorsMiddleware;
use MonkeysLegion\Http\Middleware\ErrorHandlerMiddleware;
use MonkeysLegion\Http\Middleware\LoggingMiddleware;
use MonkeysLegion\Http\Middleware\RateLimitMiddleware;
use MonkeysLegion\Http\MiddlewareDispatcher;
use MonkeysLegion\Template\Loader as TemplateLoader;
use MonkeysLegion\Template\Renderer as TemplateRenderer;
use MonkeysLegion\Session\SessionManager;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Router\Middleware\CallableHandlerAdapter;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
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
            /* Router adapter — bridge for Router v2 to PSR-15 */
            RequestHandlerInterface::class => fn($c) => new CallableHandlerAdapter(
                fn($req) => $c->get(\MonkeysLegion\Router\Router::class)->dispatch($req)
            ),

            /* Core handler */
            CoreRequestHandler::class => fn($c) => new CoreRequestHandler(
                $c->get(RequestHandlerInterface::class)
            ),

            /* CORS */
            CorsMiddleware::class => fn($c) => new CorsMiddleware(
                allowedOrigins: (array) $c->get(MlcConfig::class)->get('cors.allow_origin', ['*']),
                allowedMethods: (array) $c->get(MlcConfig::class)->get('cors.allow_methods', ['GET', 'POST', 'OPTIONS', 'PATCH', 'DELETE']),
                allowedHeaders: (array) $c->get(MlcConfig::class)->get('cors.allow_headers', ['Content-Type', 'Authorization']),
                exposedHeaders: (array) $c->get(MlcConfig::class)->get('cors.expose_headers', []),
                allowCredentials: (bool) $c->get(MlcConfig::class)->get('cors.allow_credentials', false),
                maxAge: (int) $c->get(MlcConfig::class)->get('cors.max_age', 86400)
            ),

            /* B.C. Alias for old CorsMiddleware namespace */
            'MonkeysLegion\Core\Middleware\CorsMiddleware' => fn($c) => $c->get(CorsMiddleware::class),

            /* Error handler middleware */
            ErrorHandlerMiddleware::class => function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ErrorHandlerMiddleware(
                    debug: (bool) $mlc->get('app.debug', false),
                    renderer: $c->has(ErrorRendererInterface::class) ? $c->get(ErrorRendererInterface::class) : null,
                    logger: $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : null,
                    loader: $c->has(TemplateLoader::class) ? $c->get(TemplateLoader::class) : null,
                    template: $c->has(TemplateRenderer::class) ? $c->get(TemplateRenderer::class) : null,
                    session: $c->has(SessionManager::class) ? $c->get(SessionManager::class) : null
                );
            },

            /* Rate-limit */
            RateLimitMiddleware::class => fn($c) => new RateLimitMiddleware(
                cache: $c->get(CacheInterface::class),
                limit: 5000,
                window: 60
            ),

            /* Auth */
            AuthMiddleware::class => fn($c) => new AuthMiddleware(
                requiredToken: (string) $c->get(MlcConfig::class)->get('auth.token', ''),
                publicPaths: (array) $c->get(MlcConfig::class)->get('auth.public_paths', []),
                realm: 'Protected'
            ),

            /* Logging */
            LoggingMiddleware::class => fn($c) => new LoggingMiddleware($c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : null),

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
