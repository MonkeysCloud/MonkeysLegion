<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Handshake;

use MonkeysLegion\Sockets\Contracts\HandshakeMiddlewareInterface;
use MonkeysLegion\Sockets\Handshake\MiddlewarePipeline;
use MonkeysLegion\Sockets\Handshake\MinimalServerRequest;
use MonkeysLegion\Sockets\Handshake\ResponseFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \MonkeysLegion\Sockets\Handshake\MiddlewarePipeline
 */
final class MiddlewarePipelineTest extends TestCase
{
    public function testEmptyPipelineCallsCore(): void
    {
        $pipeline = new MiddlewarePipeline();
        $request = new MinimalServerRequest('GET', '/ws');
        $factory = new ResponseFactory();

        $response = $pipeline->process($request, fn($r) => $factory->createResponse(101));
        $this->assertSame(101, $response->getStatusCode());
    }

    public function testMiddlewareExecutedInOrder(): void
    {
        $log = [];

        $mw1 = new class($log) implements HandshakeMiddlewareInterface {
            public function __construct(private array &$log) {}
            public function handle(ServerRequestInterface $r, callable $next): ResponseInterface {
                $this->log[] = 'mw1-before';
                $resp = $next($r);
                $this->log[] = 'mw1-after';
                return $resp;
            }
        };

        $mw2 = new class($log) implements HandshakeMiddlewareInterface {
            public function __construct(private array &$log) {}
            public function handle(ServerRequestInterface $r, callable $next): ResponseInterface {
                $this->log[] = 'mw2-before';
                $resp = $next($r);
                $this->log[] = 'mw2-after';
                return $resp;
            }
        };

        $pipeline = new MiddlewarePipeline([$mw1, $mw2]);
        $factory = new ResponseFactory();
        $request = new MinimalServerRequest('GET', '/ws');

        $pipeline->process($request, function ($r) use (&$log, $factory) {
            $log[] = 'core';
            return $factory->createResponse(101);
        });

        $this->assertSame(['mw1-before', 'mw2-before', 'core', 'mw2-after', 'mw1-after'], $log);
    }

    public function testMiddlewareCanShortCircuit(): void
    {
        $factory = new ResponseFactory();

        $blocker = new class($factory) implements HandshakeMiddlewareInterface {
            public function __construct(private ResponseFactory $f) {}
            public function handle(ServerRequestInterface $r, callable $next): ResponseInterface {
                return $this->f->createResponse(403, 'Blocked');
            }
        };

        $pipeline = new MiddlewarePipeline([$blocker]);
        $request = new MinimalServerRequest('GET', '/ws');

        $response = $pipeline->process($request, fn($r) => $factory->createResponse(101));
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testAddMiddleware(): void
    {
        $factory = new ResponseFactory();
        $pipeline = new MiddlewarePipeline();

        $mw = new class($factory) implements HandshakeMiddlewareInterface {
            public function __construct(private ResponseFactory $f) {}
            public function handle(ServerRequestInterface $r, callable $next): ResponseInterface {
                return $next($r)->withHeader('X-Test', 'added');
            }
        };

        $pipeline->add($mw);
        $request = new MinimalServerRequest('GET', '/ws');
        $response = $pipeline->process($request, fn($r) => $factory->createResponse(101));

        $this->assertSame('added', $response->getHeaderLine('X-Test'));
    }
}
