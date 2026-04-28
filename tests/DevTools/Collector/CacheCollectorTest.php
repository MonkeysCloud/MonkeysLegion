<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Collector;

use MonkeysLegion\DevTools\Collector\CacheCollector;
use MonkeysLegion\DevTools\Profiler\ProfileContext;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Collector\CacheCollector
 */
final class CacheCollectorTest extends TestCase
{
    private function context(): ProfileContext
    {
        return ProfileContext::create('testing', true);
    }

    public function testNameAndMetadata(): void
    {
        $c = new CacheCollector();
        $this->assertSame('cache', $c->name());
        $this->assertSame('Cache', $c->label());
        $this->assertSame('⚡', $c->icon());
    }

    public function testRecordHitsAndMisses(): void
    {
        $c = new CacheCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordOperation('redis', 'user:1', 'get', hit: true, durationMs: 0.5);
        $c->recordOperation('redis', 'user:2', 'get', hit: false, durationMs: 0.3);
        $c->recordOperation('redis', 'user:3', 'get', hit: true, durationMs: 0.4);

        $this->assertSame(3, $c->operationCount);
        $this->assertSame(2, $c->hitCount);
        $this->assertSame(1, $c->missCount);
        $this->assertEqualsWithDelta(0.667, $c->hitRatio, 0.01);
    }

    public function testHitRatioFormatted(): void
    {
        $c = new CacheCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordOperation('redis', 'k1', 'get', hit: true);
        $c->recordOperation('redis', 'k2', 'get', hit: true);

        $this->assertSame('100.0%', $c->hitRatioFormatted);
    }

    public function testZeroOperationsHitRatio(): void
    {
        $c = new CacheCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $this->assertSame(0.0, $c->hitRatio);
    }

    public function testHotKeyDetection(): void
    {
        $c = new CacheCollector(hotKeyThreshold: 3);
        $ctx = $this->context();
        $c->start($ctx);

        for ($i = 0; $i < 5; $i++) {
            $c->recordOperation('redis', 'hot_key', 'get', hit: true);
        }
        $c->recordOperation('redis', 'cold_key', 'get', hit: true);

        $c->stop($ctx);
        $data = $c->collect($ctx);

        $this->assertCount(1, $data['hot_keys']);
        $this->assertSame('hot_key', $data['hot_keys'][0]['key']);
        $this->assertSame(5, $data['hot_keys'][0]['count']);
    }

    public function testCollectPerStoreStats(): void
    {
        $c = new CacheCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordOperation('redis', 'k1', 'get', hit: true, durationMs: 1.0);
        $c->recordOperation('file', 'k2', 'get', hit: false, durationMs: 5.0);

        $c->stop($ctx);
        $data = $c->collect($ctx);

        $this->assertArrayHasKey('redis', $data['stores']);
        $this->assertArrayHasKey('file', $data['stores']);
        $this->assertSame(1, $data['stores']['redis']['hits']);
        $this->assertSame(1, $data['stores']['file']['misses']);
    }

    public function testStartResetsState(): void
    {
        $c = new CacheCollector();
        $ctx = $this->context();

        $c->start($ctx);
        $c->recordOperation('redis', 'k', 'get', hit: true);
        $this->assertSame(1, $c->operationCount);

        $c->start($ctx);
        $this->assertSame(0, $c->operationCount);
    }
}
