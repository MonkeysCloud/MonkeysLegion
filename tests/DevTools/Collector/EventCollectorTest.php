<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Collector;

use MonkeysLegion\DevTools\Collector\EventCollector;
use MonkeysLegion\DevTools\Profiler\ProfileContext;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Collector\EventCollector
 */
final class EventCollectorTest extends TestCase
{
    private function context(): ProfileContext
    {
        return ProfileContext::create('testing', true);
    }

    public function testNameAndMetadata(): void
    {
        $c = new EventCollector();
        $this->assertSame('event', $c->name());
        $this->assertSame('Events', $c->label());
        $this->assertSame('📡', $c->icon());
    }

    public function testRecordDispatch(): void
    {
        $c = new EventCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordDispatch('App\\Events\\UserCreated', [
            ['name' => 'SendWelcomeEmail', 'duration_ms' => 5.0],
            ['name' => 'UpdateStats', 'duration_ms' => 2.0],
        ]);

        $this->assertSame(1, $c->eventCount);
        $this->assertSame(2, $c->listenerCount);
        $this->assertEqualsWithDelta(7.0, $c->totalListenerMs, 0.01);
    }

    public function testStormDetection(): void
    {
        $c = new EventCollector(stormThreshold: 3);
        $ctx = $this->context();
        $c->start($ctx);

        for ($i = 0; $i < 5; $i++) {
            $c->recordDispatch('App\\Events\\Frequent', []);
        }

        $this->assertTrue($c->hasStorm);
    }

    public function testNoStormBelowThreshold(): void
    {
        $c = new EventCollector(stormThreshold: 10);
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordDispatch('App\\Events\\Normal', []);
        $c->recordDispatch('App\\Events\\Normal', []);

        $this->assertFalse($c->hasStorm);
    }

    public function testFailedListenerCount(): void
    {
        $c = new EventCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordDispatch('evt', [
            ['name' => 'OkListener', 'duration_ms' => 1.0, 'failed' => false],
            ['name' => 'BadListener', 'duration_ms' => 0.0, 'failed' => true],
        ]);

        $this->assertSame(1, $c->failedListenerCount);
    }

    public function testCollectReturnsTimeline(): void
    {
        $c = new EventCollector();
        $ctx = $this->context();
        $c->start($ctx);

        $c->recordDispatch('App\\Events\\Test', [
            ['name' => 'Listener1', 'duration_ms' => 10.0],
        ]);

        $c->stop($ctx);
        $data = $c->collect($ctx);

        $this->assertArrayHasKey('timeline', $data);
        $this->assertSame(1, $data['event_count']);
        $this->assertSame(1, $data['listener_count']);
    }

    public function testStartResetsState(): void
    {
        $c = new EventCollector();
        $ctx = $this->context();

        $c->start($ctx);
        $c->recordDispatch('E1', []);
        $this->assertSame(1, $c->eventCount);

        $c->start($ctx);
        $this->assertSame(0, $c->eventCount);
    }
}
