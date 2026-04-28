<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Serialization;

use MonkeysLegion\Sockets\Serialization\JsonMessageSerializer;
use MonkeysLegion\Sockets\Serialization\MessageEnvelope;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Serialization\JsonMessageSerializer
 * @covers \MonkeysLegion\Sockets\Serialization\MessageEnvelope
 */
final class JsonMessageSerializerTest extends TestCase
{
    private JsonMessageSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JsonMessageSerializer();
    }

    public function testSerializeProducesValidJson(): void
    {
        $json = $this->serializer->serialize('chat.message', ['text' => 'hello']);
        $decoded = json_decode($json, true);

        $this->assertIsArray($decoded);
        $this->assertSame('chat.message', $decoded['event']);
        $this->assertSame(['text' => 'hello'], $decoded['data']);
        $this->assertArrayHasKey('timestamp', $decoded);
        $this->assertArrayHasKey('metadata', $decoded);
    }

    public function testSerializeWithMetadata(): void
    {
        $json = $this->serializer->serialize('evt', 'data', ['user' => 42]);
        $decoded = json_decode($json, true);

        $this->assertSame(42, $decoded['metadata']['user']);
    }

    public function testUnserializeReturnsEnvelope(): void
    {
        $json = $this->serializer->serialize('ping', ['ts' => 123]);
        $envelope = $this->serializer->unserialize($json);

        $this->assertInstanceOf(MessageEnvelope::class, $envelope);
        $this->assertSame('ping', $envelope->event);
        $this->assertSame(123, $envelope->data['ts']);
    }

    public function testRoundTrip(): void
    {
        $json = $this->serializer->serialize('test', ['key' => 'value'], ['source' => 'unit']);
        $envelope = $this->serializer->unserialize($json);

        $this->assertSame('test', $envelope->event);
        $this->assertSame('value', $envelope->data['key']);
        $this->assertSame('unit', $envelope->metadata['source']);
    }

    public function testUnserializeInvalidJsonThrows(): void
    {
        $this->expectException(\JsonException::class);
        $this->serializer->unserialize('not-json');
    }

    public function testUnserializeMissingEventThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->serializer->unserialize('{"data": "hello"}');
    }

    public function testUnserializeMissingDataThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->serializer->unserialize('{"event": "test"}');
    }

    public function testPreservesZeroFraction(): void
    {
        $json = $this->serializer->serialize('num', ['val' => 1.0]);
        $this->assertStringContainsString('1.0', $json);
    }
}
