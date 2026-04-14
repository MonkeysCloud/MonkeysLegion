<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\OpenApi\OpenApiGenerator;
use MonkeysLegion\OpenApi\OpenApiMiddleware;
use MonkeysLegion\Router\RouteCollection;
use MonkeysLegion\Mlc\Config as MlcConfig;

final class OpenApiProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            OpenApiGenerator::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new OpenApiGenerator(
                    routes:          $c->get(RouteCollection::class),
                    title:           (string) $mlc->get('openapi.title', 'MonkeysLegion API'),
                    version:         (string) $mlc->get('openapi.version', '1.0.0'),
                    description:     (string) $mlc->get('openapi.description', ''),
                    servers:         (array)  $mlc->get('openapi.servers', []),
                    securitySchemes: (array)  $mlc->get('openapi.security_schemes', [])
                );
            },

            OpenApiMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new OpenApiMiddleware(
                    generator: $c->get(OpenApiGenerator::class),
                    jsonPath:  (string) $mlc->get('openapi.json_path', '/openapi.json'),
                    uiPath:    (string) $mlc->get('openapi.ui_path', '/docs'),
                    uiTheme:   (string) $mlc->get('openapi.ui_theme', 'swagger'),
                    darkMode:  (bool)   $mlc->get('openapi.dark_mode', false),
                    enabled:   (bool)   $mlc->get('openapi.enabled', true)
                );
            },

            /* B.C. Alias for old OpenApiMiddleware namespace */
            'MonkeysLegion\Http\OpenApi\OpenApiMiddleware' => fn($c) => $c->get(OpenApiMiddleware::class),
        ];
    }
}
