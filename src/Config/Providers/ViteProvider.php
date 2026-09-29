<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Template\Renderer;
use MonkeysLegion\Vite\RouteExporter;
use MonkeysLegion\Vite\ViteDirective;
use MonkeysLegion\Vite\ViteManifest;
use MonkeysLegion\Vite\ViteService;

/**
 * Vite asset pipeline service provider.
 *
 * Registers the Vite manifest, service, directive, and route exporter.
 * In development, assets are served from the Vite dev server.
 * In production, assets are resolved from the built manifest.
 *
 * Required MLC block (config/app.mlc):
 *   vite {
 *       dev_server = "http://localhost:5173"
 *       build_path = "public/build"
 *       manifest   = "manifest.json"
 *   }
 */
final class ViteProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            ViteManifest::class => static function ($c): ViteManifest {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $buildPath = $mlc->getString('vite.build_path', 'public/build') ?? 'public/build';
                $manifestFile = $mlc->getString('vite.manifest', 'manifest.json') ?? 'manifest.json';

                $basePath = defined('ML_BASE_PATH') ? ML_BASE_PATH : getcwd();
                $manifestPath = $basePath . '/' . $buildPath . '/' . $manifestFile;

                return new ViteManifest($manifestPath);
            },

            ViteService::class => static function ($c): ViteService {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $basePath = defined('ML_BASE_PATH') ? ML_BASE_PATH : getcwd();

                return new ViteService(
                    manifest: $c->get(ViteManifest::class),
                    devServerUrl: $mlc->getString('vite.dev_server', 'http://localhost:5173') ?? 'http://localhost:5173',
                    basePath: $basePath,
                    hotFile: $basePath . '/hot',
                );
            },

            ViteDirective::class => static fn($c): ViteDirective => new ViteDirective(
                $c->get(ViteService::class),
            ),

            RouteExporter::class => static fn($c): RouteExporter => new RouteExporter(
                $c->get(\MonkeysLegion\Router\Router::class),
            ),
        ];
    }
}
