<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Http\OpenApi\OpenApiGenerator;
use MonkeysLegion\Http\OpenApi\OpenApiMiddleware;
use MonkeysLegion\Router\RouteCollection;
use Psr\Http\Message\ResponseFactoryInterface;

final class OpenApiProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            OpenApiGenerator::class => fn($c) => new OpenApiGenerator(
                $c->get(RouteCollection::class)
            ),

            OpenApiMiddleware::class => fn($c) => new OpenApiMiddleware(
                $c->get(OpenApiGenerator::class),
                $c->get(ResponseFactoryInterface::class)
            ),
        ];
    }
}
