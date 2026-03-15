<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use Laminas\Diactoros\ServerRequestFactory;
use MonkeysLegion\Http\Factory\HttpFactory;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

final class HttpFactoryProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* PSR-17 factories */
            HttpFactory::class                  => fn() => new HttpFactory(),
            ResponseFactoryInterface::class     => fn($c) => $c->get(HttpFactory::class),
            StreamFactoryInterface::class       => fn($c) => $c->get(HttpFactory::class),
            UploadedFileFactoryInterface::class => fn($c) => $c->get(HttpFactory::class),
            UriFactoryInterface::class          => fn($c) => $c->get(HttpFactory::class),

            /* PSR-7 ServerRequest */
            ServerRequestInterface::class       => fn() => (new ServerRequestFactory())->fromGlobals(),
        ];
    }
}
