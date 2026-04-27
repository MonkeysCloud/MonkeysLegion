<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\DevTools\DevToolsServiceProvider as PackageProvider;
use MonkeysLegion\DevTools\Middleware\DevToolsMiddleware;
use MonkeysLegion\DevTools\Profiler\Profiler;
use MonkeysLegion\DevTools\Toolbar\ToolbarInjector;
use MonkeysLegion\DevTools\Toolbar\ToolbarRenderer;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Container\ContainerInterface;

/**
 * DevTools integration provider.
 *
 * Bridges the `monkeyslegion-devtools` package into the framework's DI system.
 * Only active in HTTP context (toolbar injection + middleware).
 */
final class DevToolsProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            // The package-level provider (singleton — booted once)
            PackageProvider::class => static function (ContainerInterface $c): PackageProvider {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->get('devtools', []);

                $provider = new PackageProvider();
                $provider->boot(is_array($config) ? $config : []);

                return $provider;
            },

            // Profiler — extracted from the booted provider
            Profiler::class => static fn(ContainerInterface $c): Profiler => $c->get(PackageProvider::class)->profiler
                ?? throw new \RuntimeException('DevTools profiler not available. Ensure devtools is enabled.'),

            // DevTools PSR-15 Middleware
            DevToolsMiddleware::class => static fn(ContainerInterface $c): DevToolsMiddleware => $c->get(PackageProvider::class)->createMiddleware(),

            // Toolbar Renderer (nullable — only when toolbar is enabled)
            ToolbarRenderer::class => static fn(ContainerInterface $c): ?ToolbarRenderer => $c->get(PackageProvider::class)->toolbar,

            // Toolbar Injector (nullable — only when toolbar is enabled)
            ToolbarInjector::class => static fn(ContainerInterface $c): ?ToolbarInjector => $c->get(PackageProvider::class)->injector,
        ];
    }
}
