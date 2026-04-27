<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Handshake;

use MonkeysLegion\Sockets\Contracts\AuthenticatorInterface;
use MonkeysLegion\Sockets\Handshake\HandshakeException;
use MonkeysLegion\Sockets\Handshake\HandshakeNegotiator;
use MonkeysLegion\Sockets\Handshake\MinimalServerRequest;
use MonkeysLegion\Sockets\Handshake\ResponseFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \MonkeysLegion\Sockets\Handshake\HandshakeNegotiator
 */
final class HandshakeNegotiatorTest extends TestCase
{
    private HandshakeNegotiator $negotiator;

    protected function setUp(): void
    {
        $this->negotiator = new HandshakeNegotiator(new ResponseFactory());
    }

    private function validRequest(array $overrides = []): MinimalServerRequest
    {
        $headers = array_merge([
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => base64_encode(random_bytes(16)),
            'Sec-WebSocket-Version' => '13',
        ], $overrides);

        return new MinimalServerRequest('GET', '/ws', $headers);
    }

    public function testSuccessfulNegotiationReturns101(): void
    {
        $request = $this->validRequest();
        $response = $this->negotiator->negotiate($request);

        $this->assertSame(101, $response->getStatusCode());
        $this->assertSame('websocket', $response->getHeaderLine('Upgrade'));
        $this->assertSame('Upgrade', $response->getHeaderLine('Connection'));
        $this->assertNotEmpty($response->getHeaderLine('Sec-WebSocket-Accept'));
    }

    public function testSecWebSocketAcceptIsCorrect(): void
    {
        $key = base64_encode(random_bytes(16));
        $request = $this->validRequest(['Sec-WebSocket-Key' => $key]);

        $response = $this->negotiator->negotiate($request);

        $expectedAccept = base64_encode(
            sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true)
        );

        $this->assertSame($expectedAccept, $response->getHeaderLine('Sec-WebSocket-Accept'));
    }

    public function testRejectsNonGetRequest(): void
    {
        $request = new MinimalServerRequest('POST', '/ws', [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Key'     => base64_encode(random_bytes(16)),
            'Sec-WebSocket-Version' => '13',
        ]);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('GET request');

        $this->negotiator->negotiate($request);
    }

    public function testRejectsMissingUpgradeHeader(): void
    {
        $request = $this->validRequest(['Upgrade' => 'http']);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('Upgrade: websocket');

        $this->negotiator->negotiate($request);
    }

    public function testRejectsMissingConnectionHeader(): void
    {
        $request = $this->validRequest(['Connection' => 'keep-alive']);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('Connection: Upgrade');

        $this->negotiator->negotiate($request);
    }

    public function testRejectsMissingSecWebSocketKey(): void
    {
        $headers = [
            'Upgrade'               => 'websocket',
            'Connection'            => 'Upgrade',
            'Sec-WebSocket-Version' => '13',
        ];

        $request = new MinimalServerRequest('GET', '/ws', $headers);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('Sec-WebSocket-Key');

        $this->negotiator->negotiate($request);
    }

    public function testRejectsWrongVersion(): void
    {
        $request = $this->validRequest(['Sec-WebSocket-Version' => '8']);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('version 13');

        $this->negotiator->negotiate($request);
    }

    public function testAuthenticatorFailureThrows(): void
    {
        $auth = $this->createMock(AuthenticatorInterface::class);
        $auth->method('authenticate')->willReturn(null);

        $negotiator = new HandshakeNegotiator(new ResponseFactory(), $auth);

        $this->expectException(HandshakeException::class);
        $this->expectExceptionMessage('Authentication failed');

        $negotiator->negotiate($this->validRequest());
    }

    public function testAuthenticatorSuccessProceeds(): void
    {
        $auth = $this->createMock(AuthenticatorInterface::class);
        $auth->method('authenticate')->willReturn('user-123');

        $negotiator = new HandshakeNegotiator(new ResponseFactory(), $auth);
        $response = $negotiator->negotiate($this->validRequest());

        $this->assertSame(101, $response->getStatusCode());
    }
}
