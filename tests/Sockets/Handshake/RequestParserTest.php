<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Handshake;

use MonkeysLegion\Sockets\Handshake\HandshakeException;
use MonkeysLegion\Sockets\Handshake\RequestParser;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Handshake\RequestParser
 */
final class RequestParserTest extends TestCase
{
    public function testParsesValidHttpRequest(): void
    {
        $raw = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n";
        $request = RequestParser::parse($raw);

        $this->assertSame('GET', $request->getMethod());
        $this->assertSame('/ws', $request->getRequestTarget());
        $this->assertSame('websocket', $request->getHeaderLine('Upgrade'));
    }

    public function testThrowsOnEmptyRequest(): void
    {
        $this->expectException(HandshakeException::class);
        RequestParser::parse('');
    }

    public function testThrowsOnInvalidRequestLine(): void
    {
        $this->expectException(HandshakeException::class);
        RequestParser::parse("INVALID\r\n\r\n");
    }

    public function testHeaderCaseInsensitiveLookup(): void
    {
        $raw = "GET / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        $request = RequestParser::parse($raw);
        $this->assertSame('application/json', $request->getHeaderLine('content-type'));
    }
}
