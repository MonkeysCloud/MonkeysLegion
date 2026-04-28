<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Protocol;

use MonkeysLegion\Sockets\Protocol\JsonFormatter;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Protocol\JsonFormatter
 */
final class JsonFormatterTest extends TestCase
{
    private JsonFormatter $formatter;

    protected function setUp(): void
    {
        $this->formatter = new JsonFormatter();
    }

    public function testFormatProducesValidJson(): void
    {
        $output = $this->formatter->format('chat.msg', ['text' => 'hi']);
        $decoded = json_decode($output, true);

        $this->assertSame('chat.msg', $decoded['event']);
        $this->assertSame(['text' => 'hi'], $decoded['data']);
        $this->assertArrayHasKey('t', $decoded['meta']);
    }

    public function testFormatWithMetadata(): void
    {
        $output = $this->formatter->format('evt', 'data', ['source' => 'test']);
        $decoded = json_decode($output, true);

        $this->assertSame('test', $decoded['meta']['source']);
        $this->assertArrayHasKey('t', $decoded['meta']);
    }

    public function testParseReturnsStructuredArray(): void
    {
        $json = json_encode(['event' => 'ping', 'data' => null, 'meta' => []]);
        $parsed = $this->formatter->parse($json);

        $this->assertSame('ping', $parsed['event']);
        $this->assertNull($parsed['data']);
        $this->assertIsArray($parsed['meta']);
    }

    public function testRoundTrip(): void
    {
        $formatted = $this->formatter->format('test', ['key' => 'val']);
        $parsed = $this->formatter->parse($formatted);

        $this->assertSame('test', $parsed['event']);
        $this->assertSame('val', $parsed['data']['key']);
    }

    public function testParseInvalidJsonThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->formatter->parse('not valid json');
    }

    public function testParseMissingEventDefaultsToUnknown(): void
    {
        $json = json_encode(['data' => 'hello']);
        $parsed = $this->formatter->parse($json);

        $this->assertSame('unknown', $parsed['event']);
    }
}
