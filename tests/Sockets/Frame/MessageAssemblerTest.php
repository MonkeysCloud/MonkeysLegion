<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Frame;

use MonkeysLegion\Sockets\Frame\Frame;
use MonkeysLegion\Sockets\Frame\MessageAssembler;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * @covers \MonkeysLegion\Sockets\Frame\MessageAssembler
 */
final class MessageAssemblerTest extends TestCase
{
    public function testFinalFrameReturnedImmediately(): void
    {
        $assembler = new MessageAssembler();
        $frame = new Frame('complete', opcode: 0x1, isFinal: true);

        $result = $assembler->assemble(1, $frame);

        $this->assertNotNull($result);
        $this->assertSame('complete', $result->getPayload());
    }

    public function testNonFinalFrameReturnsNull(): void
    {
        $assembler = new MessageAssembler();
        $frame = new Frame('part1', opcode: 0x1, isFinal: false);

        $result = $assembler->assemble(1, $frame);

        $this->assertNull($result);
    }

    public function testTwoFragmentsAssembledCorrectly(): void
    {
        $assembler = new MessageAssembler();

        // First fragment (text, non-final)
        $frag1 = new Frame('Hello, ', opcode: 0x1, isFinal: false);
        $this->assertNull($assembler->assemble(1, $frag1));

        // Continuation fragment (final)
        $frag2 = new Frame('World!', opcode: 0x0, isFinal: true);
        $result = $assembler->assemble(1, $frag2);

        $this->assertNotNull($result);
        $this->assertSame('Hello, World!', $result->getPayload());
        $this->assertSame(0x1, $result->getOpcode());
        $this->assertTrue($result->isFinal());
    }

    public function testThreeFragmentsAssembledCorrectly(): void
    {
        $assembler = new MessageAssembler();

        $assembler->assemble(1, new Frame('A', opcode: 0x1, isFinal: false));
        $assembler->assemble(1, new Frame('B', opcode: 0x0, isFinal: false));
        $result = $assembler->assemble(1, new Frame('C', opcode: 0x0, isFinal: true));

        $this->assertNotNull($result);
        $this->assertSame('ABC', $result->getPayload());
    }

    public function testMultipleStreamIdsIndependent(): void
    {
        $assembler = new MessageAssembler();

        $assembler->assemble(1, new Frame('Stream1-', opcode: 0x1, isFinal: false));
        $assembler->assemble(2, new Frame('Stream2-', opcode: 0x1, isFinal: false));

        $r1 = $assembler->assemble(1, new Frame('End', opcode: 0x0, isFinal: true));
        $r2 = $assembler->assemble(2, new Frame('Done', opcode: 0x0, isFinal: true));

        $this->assertSame('Stream1-End', $r1->getPayload());
        $this->assertSame('Stream2-Done', $r2->getPayload());
    }

    public function testMaxMessageSizeExceeded(): void
    {
        $assembler = new MessageAssembler(maxMessageSize: 10);

        $assembler->assemble(1, new Frame('12345', opcode: 0x1, isFinal: false));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Message size exceeded limit');

        $assembler->assemble(1, new Frame('123456', opcode: 0x0, isFinal: true));
    }

    public function testContinuationWithoutStartThrows(): void
    {
        $assembler = new MessageAssembler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('continuation frame without a starting message');

        $assembler->assemble(1, new Frame('data', opcode: 0x0, isFinal: true));
    }

    public function testNewMessageBeforeFinishThrows(): void
    {
        $assembler = new MessageAssembler();

        $assembler->assemble(1, new Frame('start', opcode: 0x1, isFinal: false));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('new message frame before finishing');

        $assembler->assemble(1, new Frame('another', opcode: 0x1, isFinal: true));
    }

    public function testClearRemovesBufferedData(): void
    {
        $assembler = new MessageAssembler();

        $assembler->assemble(1, new Frame('start', opcode: 0x1, isFinal: false));
        $assembler->clear(1);

        // Now continuation should fail since we cleared the buffer
        $this->expectException(RuntimeException::class);
        $assembler->assemble(1, new Frame('cont', opcode: 0x0, isFinal: true));
    }

    public function testStringStreamId(): void
    {
        $assembler = new MessageAssembler();

        $assembler->assemble('conn-abc', new Frame('frag1', opcode: 0x1, isFinal: false));
        $result = $assembler->assemble('conn-abc', new Frame('frag2', opcode: 0x0, isFinal: true));

        $this->assertSame('frag1frag2', $result->getPayload());
    }
}
