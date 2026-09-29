<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Http\CoreRequestHandler;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\Middleware\CompressionMiddleware;
use MonkeysLegion\Http\Middleware\ConditionalMiddleware;
use MonkeysLegion\Http\Middleware\CorrelationIdMiddleware;
use MonkeysLegion\Http\Middleware\CorsMiddleware;
use MonkeysLegion\Http\Middleware\CspMiddleware;
use MonkeysLegion\Http\Middleware\DeprecationMiddleware;
use MonkeysLegion\Http\Middleware\ErrorHandlerMiddleware;
use MonkeysLegion\Http\Middleware\LoggingMiddleware;
use MonkeysLegion\Http\Middleware\RateLimitMiddleware;
use MonkeysLegion\Http\Middleware\RequestIdMiddleware;
use MonkeysLegion\Http\Middleware\SecurityHeadersMiddleware;
use MonkeysLegion\Http\Middleware\SignedUrlMiddleware;
use MonkeysLegion\Http\Middleware\TrustedProxyMiddleware;
use MonkeysLegion\Http\MiddlewareDispatcher;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * HTTP middleware stack, emitter, and security middleware provider.
 *
 * Uses the HTTP package's built-in middleware classes.
 * HTTP-only context.
 */
final class MiddlewareProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            /* Core request handler — wraps Router::dispatch() as PSR-15 handler */
            CoreRequestHandler::class => static function ($c): CoreRequestHandler {
                $router = $c->get(\MonkeysLegion\Router\Router::class);

                // Adapt Router::dispatch() to RequestHandlerInterface
                $routerHandler = new class($router) implements \Psr\Http\Server\RequestHandlerInterface {
                    public function __construct(
                        private readonly \MonkeysLegion\Router\Router $router,
                    ) {}

                    public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
                    {
                        return $this->router->dispatch($request);
                    }
                };

                return new CoreRequestHandler($routerHandler);
            },

            /* Security Headers (HTTP package built-in) */
            SecurityHeadersMiddleware::class => static function ($c): SecurityHeadersMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $preset = $mlc->getString('security.preset', 'strict') ?? 'strict';

                return new SecurityHeadersMiddleware(
                    preset: $preset,
                    overrides: array_filter([
                        'X-Frame-Options'         => $mlc->getString('security.frame_options'),
                        'Referrer-Policy'         => $mlc->getString('security.referrer_policy'),
                        'Content-Security-Policy' => $mlc->getString('security.csp'),
                    ]),
                );
            },

            /* Request ID (HTTP package built-in) */
            RequestIdMiddleware::class => fn(): RequestIdMiddleware => new RequestIdMiddleware(),

            /* Trusted Proxy (HTTP package built-in) */
            TrustedProxyMiddleware::class => static function ($c): TrustedProxyMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new TrustedProxyMiddleware(
                    trustedProxies: $mlc->getArray('security.trusted_proxies', ['127.0.0.1', '::1']) ?? [],
                );
            },

            /* CORS (HTTP package built-in) */
            CorsMiddleware::class => static function ($c): CorsMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new CorsMiddleware(
                    allowedOrigins: $mlc->getArray('cors.allow_origin', ['*']) ?? ['*'],
                    allowedMethods: $mlc->getArray('cors.allow_methods', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) ?? [],
                    allowedHeaders: $mlc->getArray('cors.allow_headers', ['Content-Type', 'Authorization', 'X-Request-Id', 'Accept']) ?? [],
                    exposedHeaders: $mlc->getArray('cors.expose_headers', []) ?? [],
                    allowCredentials: $mlc->getBool('cors.allow_credentials', false) ?? false,
                    maxAge: $mlc->getInt('cors.max_age', 86400) ?? 86400,
                );
            },

            /* Error handler */
            ErrorHandlerMiddleware::class => static function ($c): ErrorHandlerMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ErrorHandlerMiddleware(
                    debug: $mlc->getBool('app.debug', false) ?? false,
                    logger: $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : null,
                );
            },

            /* Rate-limit */
            RateLimitMiddleware::class => static function ($c): RateLimitMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new RateLimitMiddleware(
                    cache: $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null,
                    limit: $mlc->getInt('rate_limit.max_requests', 5000) ?? 5000,
                    window: $mlc->getInt('rate_limit.window_seconds', 60) ?? 60,
                );
            },

            /* Logging */
            LoggingMiddleware::class => static function ($c): LoggingMiddleware {
                return new LoggingMiddleware(
                    logger: $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : null,
                );
            },

            /* CSP (Content Security Policy) */
            CspMiddleware::class => static function ($c): CspMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new CspMiddleware(
                    directives: $mlc->getArray('security.csp.directives', [
                        'default-src' => ["'self'"],
                        'script-src'  => ["'self'", "'unsafe-inline'"],
                        'style-src'   => ["'self'", "'unsafe-inline'"],
                        'img-src'     => ["'self'", 'data:', 'https:'],
                    ]) ?? [],
                    reportOnly: $mlc->getBool('security.csp.report_only', false) ?? false,
                );
            },

            /* Gzip Compression */
            CompressionMiddleware::class => static function ($c): CompressionMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new CompressionMiddleware(
                    minSize: $mlc->getInt('compression.min_size', 1024) ?? 1024,
                    level: $mlc->getInt('compression.level', 6) ?? 6,
                );
            },

            /* Conditional GET (ETag, Last-Modified) */
            ConditionalMiddleware::class => fn(): ConditionalMiddleware => new ConditionalMiddleware(),

            /* Correlation ID for distributed tracing */
            CorrelationIdMiddleware::class => fn(): CorrelationIdMiddleware => new CorrelationIdMiddleware(),

            /* API Deprecation headers */
            DeprecationMiddleware::class => static function ($c): DeprecationMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new DeprecationMiddleware(
                    sunset: $mlc->getString('api.deprecation.sunset'),
                    link: $mlc->getString('api.deprecation.link'),
                );
            },

            /* Signed URL verification */
            SignedUrlMiddleware::class => static function ($c): SignedUrlMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new SignedUrlMiddleware(
                    key: $mlc->getString('app.key', '') ?? '',
                );
            },

            /* SAPI emitter */
            SapiEmitter::class => fn(): SapiEmitter => new SapiEmitter(),

            /* PSR-15 pipeline */
            MiddlewareDispatcher::class => static function ($c): MiddlewareDispatcher {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                /** @var array<string> $ids */
                $ids = $mlc->getArray('middleware.global', []) ?? [];

                // Resolve each middleware class from the container
                $stack = [];

                foreach ($ids as $middlewareClass) {
                    if ($c->has($middlewareClass)) {
                        $stack[] = $c->get($middlewareClass);
                    }
                }

                return new MiddlewareDispatcher(
                    $stack,
                    $c->get(CoreRequestHandler::class),
                );
            },
        ];
    }
}
