<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use MonkeysLegion\Http\MiddlewareDispatcher;
use MonkeysLegion\Router\ControllerScanner;
use Psr\Http\Message\ServerRequestInterface;

/**
 * HTTP Kernel — manages the full request → response lifecycle.
 *
 * Uses the Router package's ControllerScanner for route discovery.
 */
final class Kernel
{
    public function __construct(
        private readonly Container $container,
        private readonly Application $app,
    ) {}

    public function handle(): void
    {
        try {
            $this->loadRoutes();
            $this->dispatch();
        } catch (\Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * Scan controller directories for route attributes and register them.
     */
    private function loadRoutes(): void
    {
        if (!$this->container->has(ControllerScanner::class)) {
            return;
        }

        /** @var ControllerScanner $scanner */
        $scanner = $this->container->get(ControllerScanner::class);

        $controllerDir = $this->app->basePath . '/app/Controller';

        if (is_dir($controllerDir)) {
            $scanner->scan($controllerDir, 'App\\Controller');
        }
    }

    /**
     * Build the middleware pipeline, create the request, dispatch, and emit.
     */
    private function dispatch(): void
    {
        /** @var ServerRequestInterface $request */
        $request = $this->container->get(ServerRequestInterface::class);

        /** @var MiddlewareDispatcher $dispatcher */
        $dispatcher = $this->container->get(MiddlewareDispatcher::class);

        $response = $dispatcher->handle($request);

        /** @var SapiEmitter $emitter */
        $emitter = $this->container->get(SapiEmitter::class);
        $emitter->emit($response);
    }

    private function handleException(\Throwable $e): void
    {
        $handler = new ExceptionHandler($this->container, $this->app);
        $handler->handle($e);
    }
}
