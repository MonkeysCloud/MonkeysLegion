<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Frame;

use MonkeysLegion\Sockets\Frame\Frame;
use MonkeysLegion\Sockets\Frame\FrameProcessor;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Frame\FrameProcessor
 */
final class FrameProcessorTest extends TestCase
{
    private FrameProcessor $processor;

    protected function setUp(): void
    {
        $this->processor = new FrameProcessor();
    }

    // ── Encode + Decode Round-Trip ─────────────────────────────────

    public function testEncodeDecodeSmallTextPayload(): void
    {
        $payload = 'Hello, WebSocket!';
        $encoded = $this->processor->encode($payload);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame($payload, $decoded->getPayload());
        $this->assertSame(0x1, $decoded->getOpcode());
        $this->assertTrue($decoded->isFinal());
        $this->assertFalse($decoded->isMasked());
    }

    public function testEncodeDecodeEmptyPayload(): void
    {
        $encoded = $this->processor->encode('');
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame('', $decoded->getPayload());
    }

    public function testEncodeDecodeBinaryOpcode(): void
    {
        $payload = "\x00\x01\x02\xFF";
        $encoded = $this->processor->encode($payload, opcode: 0x2);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame($payload, $decoded->getPayload());
        $this->assertTrue($decoded->isBinary());
    }

    public function testEncodeDecodeWithMasking(): void
    {
        $payload = 'Masked message';
        $encoded = $this->processor->encode($payload, mask: true);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame($payload, $decoded->getPayload());
        $this->assertTrue($decoded->isMasked());
        $this->assertNotNull($decoded->getMaskingKey());
        $this->assertSame(4, strlen($decoded->getMaskingKey()));
    }

    public function testEncodeDecodeNonFinalFrame(): void
    {
        $payload = 'fragment';
        $encoded = $this->processor->encode($payload, isFinal: false);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertFalse($decoded->isFinal());
    }

    // ── Payload Length Boundaries ──────────────────────────────────

    public function testEncodeDecodeMediumPayload(): void
    {
        $payload = str_repeat('A', 300); // > 125, uses 16-bit length
        $encoded = $this->processor->encode($payload);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame($payload, $decoded->getPayload());
    }

    public function testEncodeDecodeLargePayload(): void
    {
        $payload = str_repeat('B', 70000); // > 65535, uses 64-bit length
        $encoded = $this->processor->encode($payload);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(strlen($payload), strlen($decoded->getPayload()));
        $this->assertSame($payload, $decoded->getPayload());
    }

    public function testEncodeDecodeExactly125Bytes(): void
    {
        $payload = str_repeat('C', 125);
        $encoded = $this->processor->encode($payload);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(125, strlen($decoded->getPayload()));
    }

    public function testEncodeDecodeExactly126Bytes(): void
    {
        $payload = str_repeat('D', 126);
        $encoded = $this->processor->encode($payload);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(126, strlen($decoded->getPayload()));
    }

    // ── Control Frames ────────────────────────────────────────────

    public function testEncodeDecodePingFrame(): void
    {
        $encoded = $this->processor->encode('ping-data', opcode: 0x9);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(0x9, $decoded->getOpcode());
        $this->assertSame('ping-data', $decoded->getPayload());
    }

    public function testEncodeDecodePongFrame(): void
    {
        $encoded = $this->processor->encode('', opcode: 0xA);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(0xA, $decoded->getOpcode());
    }

    public function testEncodeDecodeCloseFrame(): void
    {
        $encoded = $this->processor->encode('', opcode: 0x8);
        $decoded = $this->processor->decode($encoded);

        $this->assertNotNull($decoded);
        $this->assertSame(0x8, $decoded->getOpcode());
    }

    // ── Edge Cases ────────────────────────────────────────────────

    public function testDecodeReturnsNullForInsufficientData(): void
    {
        $this->assertNull($this->processor->decode(''));
        $this->assertNull($this->processor->decode("\x81"));
    }

    public function testDecodeReturnsNullForTruncatedPayload(): void
    {
        // A frame header indicating 10 bytes but only 2 provided
        $raw = "\x81\x0A" . "AB";
        $this->assertNull($this->processor->decode($raw));
    }

    public function testDecodeInvalidUtf8ThrowsException(): void
    {
        // Manually construct a text frame (opcode 0x1) with invalid UTF-8
        $invalidUtf8 = "\xC3\x28"; // Invalid UTF-8 sequence
        $header = "\x81" . chr(strlen($invalidUtf8));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionCode(1007);

        $this->processor->decode($header . $invalidUtf8);
    }

    public function testMaskedEncodeDecodeRoundTrip(): void
    {
        $payload = 'The quick brown fox jumps over the lazy dog';
        $encoded = $this->processor->encode($payload, mask: true);

        // Encoded should be different from plain payload
        $this->assertNotSame($payload, substr($encoded, 6));

        $decoded = $this->processor->decode($encoded);
        $this->assertNotNull($decoded);
        $this->assertSame($payload, $decoded->getPayload());
    }
}
