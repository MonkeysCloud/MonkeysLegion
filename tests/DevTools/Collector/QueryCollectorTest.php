<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Collector;

use MonkeysLegion\DevTools\Collector\QueryCollector;
use MonkeysLegion\DevTools\Profiler\ProfileContext;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Collector\QueryCollector
 */
final class QueryCollectorTest extends TestCase
{
    private function context(): ProfileContext
    {
        return ProfileContext::create('testing', true);
    }

    public function testNameAndMetadata(): void
    {
        $collector = new QueryCollector();

        $this->assertSame('query', $collector->name());
        $this->assertSame('Queries', $collector->label());
        $this->assertTrue($collector->isEnabled());
    }

    public function testRecordQueryIncreasesCount(): void
    {
        $collector = new QueryCollector();
        $ctx = $this->context();
        $collector->start($ctx);

        $collector->recordQuery('SELECT * FROM users', durationMs: 5.0);
        $collector->recordQuery('SELECT * FROM posts', durationMs: 3.0);

        $this->assertSame(2, $collector->queryCount);
        $this->assertEqualsWithDelta(8.0, $collector->totalDurationMs, 0.01);
    }

    public function testDuplicateDetection(): void
    {
        $collector = new QueryCollector();
        $ctx = $this->context();
        $collector->start($ctx);

        $collector->recordQuery('SELECT * FROM users WHERE id = 1');
        $collector->recordQuery('SELECT * FROM users WHERE id = 2');
        $collector->recordQuery('SELECT * FROM users WHERE id = 3');

        $this->assertSame(2, $collector->duplicateCount); // 3 - 1 = 2 duplicates
    }

    public function testNPlusOneDetection(): void
    {
        $collector = new QueryCollector(nPlusOneThreshold: 3);
        $ctx = $this->context();
        $collector->start($ctx);

        for ($i = 0; $i < 5; $i++) {
            $collector->recordQuery("SELECT * FROM comments WHERE post_id = $i");
        }

        $this->assertTrue($collector->hasNPlusOne);
    }

    public function testNoNPlusOneWhenBelowThreshold(): void
    {
        $collector = new QueryCollector(nPlusOneThreshold: 10);
        $ctx = $this->context();
        $collector->start($ctx);

        $collector->recordQuery('SELECT * FROM users WHERE id = 1');
        $collector->recordQuery('SELECT * FROM users WHERE id = 2');

        $this->assertFalse($collector->hasNPlusOne);
    }

    public function testSlowestQueryMs(): void
    {
        $collector = new QueryCollector();
        $ctx = $this->context();
        $collector->start($ctx);

        $collector->recordQuery('SELECT 1', durationMs: 1.0);
        $collector->recordQuery('SELECT 2', durationMs: 150.0);
        $collector->recordQuery('SELECT 3', durationMs: 50.0);

        $this->assertEqualsWithDelta(150.0, $collector->slowestQueryMs, 0.01);
    }

    public function testCollectReturnsStructuredData(): void
    {
        $collector = new QueryCollector(slowQueryThresholdMs: 100.0);
        $ctx = $this->context();
        $collector->start($ctx);

        $collector->recordQuery('SELECT * FROM users', durationMs: 5.0);
        $collector->recordQuery('SELECT * FROM heavy_table', durationMs: 150.0);

        $collector->stop($ctx);
        $data = $collector->collect($ctx);

        $this->assertSame(2, $data['count']);
        $this->assertCount(2, $data['queries']);
        $this->assertCount(1, $data['slow_queries']);
        $this->assertFalse($data['has_n_plus_one']);
    }

    public function testMaxQueriesLimit(): void
    {
        $collector = new QueryCollector(maxQueries: 3);
        $ctx = $this->context();
        $collector->start($ctx);

        for ($i = 0; $i < 10; $i++) {
            $collector->recordQuery("SELECT $i", durationMs: 1.0);
        }

        $this->assertSame(3, $collector->queryCount);
    }

    public function testStartResetsState(): void
    {
        $collector = new QueryCollector();
        $ctx = $this->context();

        $collector->start($ctx);
        $collector->recordQuery('SELECT 1');
        $this->assertSame(1, $collector->queryCount);

        $collector->start($ctx);
        $this->assertSame(0, $collector->queryCount);
    }

    public function testDisabledCollector(): void
    {
        $collector = new QueryCollector(enabled: false);
        $this->assertFalse($collector->isEnabled());
    }
}
