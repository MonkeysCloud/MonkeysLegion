<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Http\Factory\HttpFactory;
use MonkeysLegion\Http\Message\ServerRequest;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;

/**
 * PSR-17 HTTP factory and PSR-7 ServerRequest provider.
 *
 * Uses the ML HTTP package's own HttpFactory and ServerRequest::fromGlobals().
 */
final class HttpFactoryProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            HttpFactory::class => fn(): HttpFactory => new HttpFactory(),

            ResponseFactoryInterface::class => fn($c): HttpFactory => $c->get(HttpFactory::class),
            StreamFactoryInterface::class   => fn($c): HttpFactory => $c->get(HttpFactory::class),
            UriFactoryInterface::class      => fn($c): HttpFactory => $c->get(HttpFactory::class),

            ServerRequestInterface::class => static fn(): ServerRequestInterface => ServerRequest::fromGlobals(),
        ];
    }
}
