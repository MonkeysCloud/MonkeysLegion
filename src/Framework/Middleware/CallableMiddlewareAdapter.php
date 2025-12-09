<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Adapts a callable middleware (signature: fn($request, $next))
 * to PSR-15 MiddlewareInterface.
 */
final class CallableMiddlewareAdapter implements MiddlewareInterface
{
    private $middleware;

    /**
     * @param object|callable $middleware Must provide a handle($request, $next) method or be callable
     */
    public function __construct(object|callable $middleware)
    {
        $this->middleware = $middleware;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $next = function ($req) use ($handler) {
            return $handler->handle($req);
        };

        if (is_object($this->middleware) && method_exists($this->middleware, 'handle')) {
            return $this->middleware->handle($request, $next);
        }

        return ($this->middleware)($request, $next);
    }
}
