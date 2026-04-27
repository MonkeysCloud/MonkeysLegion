<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools;

use MonkeysLegion\DevTools\DevToolsServiceProvider;
use MonkeysLegion\DevTools\Profiler\Profiler;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\DevToolsServiceProvider
 */
final class DevToolsServiceProviderTest extends TestCase
{
    public function testBootReturnsProfiler(): void
    {
        $provider = new DevToolsServiceProvider();
        $profiler = $provider->boot(['enabled' => true]);

        $this->assertInstanceOf(Profiler::class, $profiler);
        $this->assertTrue($provider->booted);
        $this->assertSame($profiler, $provider->profiler);
    }

    public function testBootRegistersDefaultCollectors(): void
    {
        $provider = new DevToolsServiceProvider();
        $profiler = $provider->boot();

        $collectors = $provider->getCollectors();

        $this->assertArrayHasKey('request', $collectors);
        $this->assertArrayHasKey('query', $collectors);
        $this->assertArrayHasKey('cache', $collectors);
        $this->assertArrayHasKey('event', $collectors);
        $this->assertArrayHasKey('exception', $collectors);
    }

    public function testBootWithDisabledCollectors(): void
    {
        $provider = new DevToolsServiceProvider();
        $provider->boot([
            'collectors' => [
                'cache' => false,
                'event' => false,
            ],
        ]);

        $collectors = $provider->getCollectors();

        $this->assertArrayNotHasKey('cache', $collectors);
        $this->assertArrayNotHasKey('event', $collectors);
        $this->assertArrayHasKey('request', $collectors);
    }

    public function testToolbarEnabledCreatesRenderer(): void
    {
        $provider = new DevToolsServiceProvider();
        $provider->boot([
            'toolbar' => ['enabled' => true],
        ]);

        $this->assertNotNull($provider->toolbar);
        $this->assertNotNull($provider->injector);
    }

    public function testToolbarDisabledByDefault(): void
    {
        $provider = new DevToolsServiceProvider();
        $provider->boot();

        $this->assertNull($provider->toolbar);
        $this->assertNull($provider->injector);
    }

    public function testCreateMiddlewareRequiresBoot(): void
    {
        $provider = new DevToolsServiceProvider();

        $this->expectException(\RuntimeException::class);
        $provider->createMiddleware();
    }

    public function testCreateMiddlewareAfterBoot(): void
    {
        $provider = new DevToolsServiceProvider();
        $provider->boot();

        $middleware = $provider->createMiddleware();
        $this->assertNotNull($middleware);
    }

    public function testNullStorageDriver(): void
    {
        $provider = new DevToolsServiceProvider();
        $provider->boot([
            'storage' => ['driver' => 'null'],
        ]);

        $this->assertTrue($provider->booted);
    }

    public function testCustomSampleRate(): void
    {
        $provider = new DevToolsServiceProvider();
        $profiler = $provider->boot([
            'sample_rate' => 0.5,
        ]);

        $this->assertInstanceOf(Profiler::class, $profiler);
    }

    public function testGetCollectorsBeforeBootReturnsEmpty(): void
    {
        $provider = new DevToolsServiceProvider();

        $this->assertSame([], $provider->getCollectors());
    }
}
