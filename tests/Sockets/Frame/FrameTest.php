<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Frame;

use MonkeysLegion\Sockets\Frame\Frame;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Frame\Frame
 */
final class FrameTest extends TestCase
{
    public function testDefaultsAreTextFinalUnmasked(): void
    {
        $frame = new Frame('Hello');

        $this->assertSame('Hello', $frame->getPayload());
        $this->assertSame(0x1, $frame->getOpcode());
        $this->assertTrue($frame->isFinal());
        $this->assertFalse($frame->isMasked());
        $this->assertNull($frame->getMaskingKey());
        $this->assertFalse($frame->isBinary());
    }

    public function testBinaryOpcode(): void
    {
        $frame = new Frame("\x00\xFF", opcode: 0x2);

        $this->assertTrue($frame->isBinary());
        $this->assertSame(0x2, $frame->getOpcode());
    }

    public function testNonFinalFrame(): void
    {
        $frame = new Frame('part1', isFinal: false);

        $this->assertFalse($frame->isFinal());
    }

    public function testMaskedFrameWithKey(): void
    {
        $key = "\xAB\xCD\xEF\x01";
        $frame = new Frame('masked', isMasked: true, maskingKey: $key);

        $this->assertTrue($frame->isMasked());
        $this->assertSame($key, $frame->getMaskingKey());
    }

    public function testPingOpcode(): void
    {
        $frame = new Frame('', opcode: 0x9);

        $this->assertSame(0x9, $frame->getOpcode());
        $this->assertFalse($frame->isBinary());
    }

    public function testCloseOpcode(): void
    {
        $frame = new Frame('', opcode: 0x8);

        $this->assertSame(0x8, $frame->getOpcode());
    }

    public function testConsumedLength(): void
    {
        $frame = new Frame('data', consumedLength: 42);

        $this->assertSame(42, $frame->getConsumedLength());
    }

    public function testEmptyPayload(): void
    {
        $frame = new Frame('');

        $this->assertSame('', $frame->getPayload());
        $this->assertSame(0, $frame->getConsumedLength());
    }
}
