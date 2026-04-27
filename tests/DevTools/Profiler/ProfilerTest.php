<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Profiler;

use MonkeysLegion\DevTools\Contract\CollectorInterface;
use MonkeysLegion\DevTools\Profiler\ProfileContext;
use MonkeysLegion\DevTools\Profiler\Profiler;
use MonkeysLegion\DevTools\Redaction\KeyBasedRedactor;
use MonkeysLegion\DevTools\Sampler\RateSampler;
use MonkeysLegion\DevTools\Storage\MemoryProfileStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Profiler\Profiler
 * @covers \MonkeysLegion\DevTools\Profiler\Profile
 * @covers \MonkeysLegion\DevTools\Profiler\ProfileContext
 */
final class ProfilerTest extends TestCase
{
    private function createProfiler(bool $enabled = true, float $sampleRate = 1.0): Profiler
    {
        return new Profiler(
            storage: new MemoryProfileStorage(),
            redactor: new KeyBasedRedactor(sensitiveKeys: []),
            sampler: new RateSampler(defaultRate: $sampleRate),
            environment: 'testing',
            enabled: $enabled,
        );
    }

    public function testStartReturnsContextWhenEnabled(): void
    {
        $profiler = $this->createProfiler();
        $ctx = $profiler->start();

        $this->assertInstanceOf(ProfileContext::class, $ctx);
        $this->assertTrue($profiler->isActive);
    }

    public function testStartReturnsNullWhenDisabled(): void
    {
        $profiler = $this->createProfiler(enabled: false);

        $this->assertNull($profiler->start());
        $this->assertFalse($profiler->isActive);
    }

    public function testStartReturnsNullWhenNotSampled(): void
    {
        $profiler = $this->createProfiler(sampleRate: 0.0);

        $this->assertNull($profiler->start());
    }

    public function testStopReturnsProfile(): void
    {
        $profiler = $this->createProfiler();
        $profiler->start();

        $profile = $profiler->stop(method: 'GET', uri: '/test', statusCode: 200);

        $this->assertNotNull($profile);
        $this->assertSame('GET', $profile->method);
        $this->assertSame('/test', $profile->uri);
        $this->assertSame(200, $profile->statusCode);
        $this->assertFalse($profiler->isActive);
    }

    public function testStopWithoutStartReturnsNull(): void
    {
        $profiler = $this->createProfiler();
        $this->assertNull($profiler->stop());
    }

    public function testAddAndGetCollector(): void
    {
        $profiler = $this->createProfiler();
        $collector = $this->createStub(CollectorInterface::class);
        $collector->method('name')->willReturn('test');
        $collector->method('isEnabled')->willReturn(true);
        $collector->method('priority')->willReturn(100);
        $collector->method('collect')->willReturn(['key' => 'value']);

        $profiler->addCollector($collector);

        $this->assertTrue($profiler->hasCollector('test'));
        $this->assertSame(1, $profiler->collectorCount);
        $this->assertContains('test', $profiler->collectorNames);
    }

    public function testRemoveCollector(): void
    {
        $profiler = $this->createProfiler();
        $collector = $this->createStub(CollectorInterface::class);
        $collector->method('name')->willReturn('test');

        $profiler->addCollector($collector);
        $profiler->removeCollector('test');

        $this->assertFalse($profiler->hasCollector('test'));
    }

    public function testCollectorDataAppearsInProfile(): void
    {
        $profiler = $this->createProfiler();

        $collector = $this->createStub(CollectorInterface::class);
        $collector->method('name')->willReturn('test');
        $collector->method('isEnabled')->willReturn(true);
        $collector->method('priority')->willReturn(100);
        $collector->method('collect')->willReturn(['metric' => 42]);

        $profiler->addCollector($collector);
        $profiler->start();
        $profile = $profiler->stop();

        $this->assertNotNull($profile);
        $this->assertTrue($profile->hasCollector('test'));
        $this->assertSame(42, $profile->collector('test')['metric']);
    }

    public function testProfileIsSlow(): void
    {
        $profiler = new Profiler(
            storage: new MemoryProfileStorage(),
            redactor: new KeyBasedRedactor(sensitiveKeys: []),
            sampler: new RateSampler(),
            slowThresholdMs: 0.001,
            enabled: true,
        );

        $profiler->start();
        usleep(100); // Small delay
        $profile = $profiler->stop(statusCode: 200);

        // Duration should be > 0
        $this->assertGreaterThan(0, $profile->durationMs);
    }

    public function testProfileIsError(): void
    {
        $profiler = $this->createProfiler();
        $profiler->start();
        $profile = $profiler->stop(statusCode: 500);

        $this->assertTrue($profile->isError);
    }

    public function testProfileIsNotError(): void
    {
        $profiler = $this->createProfiler();
        $profiler->start();
        $profile = $profiler->stop(statusCode: 200);

        $this->assertFalse($profile->isError);
    }

    public function testSetEnabled(): void
    {
        $profiler = $this->createProfiler(enabled: true);
        $this->assertTrue($profiler->isEnabled());

        $profiler->setEnabled(false);
        $this->assertFalse($profiler->isEnabled());
        $this->assertNull($profiler->start());
    }

    public function testProfileStoragePersistence(): void
    {
        $storage = new MemoryProfileStorage();
        $profiler = new Profiler(
            storage: $storage,
            redactor: new KeyBasedRedactor(sensitiveKeys: []),
            sampler: new RateSampler(),
            enabled: true,
        );

        $profiler->start();
        $profile = $profiler->stop(method: 'POST', uri: '/api/data');

        $found = $storage->find($profile->id);
        $this->assertNotNull($found);
        $this->assertSame('/api/data', $found->uri);
    }
}
