<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\OpenApi\OpenApiGenerator;
use MonkeysLegion\OpenApi\OpenApiMiddleware;
use MonkeysLegion\Router\RouteCollection;

/**
 * OpenAPI v3 document generator and Swagger UI middleware provider.
 *
 * HTTP-only context. Uses the OpenApi package's actual classes.
 */
final class OpenApiProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            OpenApiGenerator::class => static function ($c): OpenApiGenerator {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new OpenApiGenerator(
                    routes: $c->get(RouteCollection::class),
                    title: $mlc->getString('app.name', 'MonkeysLegion API') ?? 'MonkeysLegion API',
                    version: $mlc->getString('app.version', '1.0.0') ?? '1.0.0',
                    description: $mlc->getString('openapi.description', '') ?? '',
                    servers: $mlc->getArray('openapi.servers', []) ?? [],
                );
            },

            OpenApiMiddleware::class => static function ($c): OpenApiMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new OpenApiMiddleware(
                    generator: $c->get(OpenApiGenerator::class),
                    jsonPath: $mlc->getString('openapi.doc_path', '/openapi.json') ?? '/openapi.json',
                    uiPath: $mlc->getString('openapi.ui_path', '/docs') ?? '/docs',
                    enabled: $mlc->getBool('openapi.enabled', true) ?? true,
                );
            },
        ];
    }
}
