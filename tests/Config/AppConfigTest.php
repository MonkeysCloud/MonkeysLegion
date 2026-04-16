<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Config;

use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Config\Providers\ServiceProviderInterface;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Config\AppConfig
 */
final class AppConfigTest extends TestCase
{
    public function testInvokeReturnsArrayOfDefinitions(): void
    {
        $config = new AppConfig();

        $definitions = $config('http');

        $this->assertIsArray($definitions);
        $this->assertNotEmpty($definitions);
    }

    public function testInvokeHttpContextIncludesRoutingDefinitions(): void
    {
        $config = new AppConfig();

        $definitions = $config('http');

        // Router should be in HTTP definitions
        $this->assertArrayHasKey(\MonkeysLegion\Router\Router::class, $definitions);
    }

    public function testInvokeCliContextExcludesHttpOnlyProviders(): void
    {
        $config = new AppConfig();

        $definitions = $config('cli');

        // Router is HTTP-only, should NOT be in CLI definitions
        $this->assertArrayNotHasKey(\MonkeysLegion\Router\Router::class, $definitions);
    }

    public function testInvokeCliContextIncludesScheduleDefinitions(): void
    {
        $config = new AppConfig();

        $definitions = $config('cli');

        // Schedule is CLI-only
        $this->assertArrayHasKey(\MonkeysLegion\Schedule\Schedule::class, $definitions);
    }

    public function testInvokeIncludesCoreProviders(): void
    {
        $config = new AppConfig();

        $definitions = $config('http');

        // Logger and EventDispatcher are 'all' context
        $this->assertArrayHasKey(\MonkeysLegion\Logger\Logger::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Events\EventDispatcher::class, $definitions);
    }

    public function testGetProvidersReturnsAllProviderClasses(): void
    {
        $providers = AppConfig::getProviders();

        $this->assertIsArray($providers);
        $this->assertNotEmpty($providers);

        foreach ($providers as $class) {
            $this->assertTrue(
                class_exists($class),
                "Provider class {$class} does not exist.",
            );
            $this->assertTrue(
                is_subclass_of($class, ServiceProviderInterface::class),
                "Provider {$class} does not implement ServiceProviderInterface.",
            );
        }
    }

    public function testAllProvidersReturnValidDefinitions(): void
    {
        $providers = AppConfig::getProviders();

        foreach ($providers as $providerClass) {
            $provider = new $providerClass();
            $definitions = $provider->getDefinitions();

            $this->assertIsArray(
                $definitions,
                "{$providerClass}::getDefinitions() must return an array.",
            );
        }
    }

    public function testEachProviderHasValidContext(): void
    {
        $providers = AppConfig::getProviders();
        $validContexts = ['all', 'http', 'cli'];

        foreach ($providers as $providerClass) {
            $provider = new $providerClass();
            $context = $provider->context();

            $this->assertContains(
                $context,
                $validContexts,
                "{$providerClass}::context() returned '{$context}', expected one of: " . implode(', ', $validContexts),
            );
        }
    }
}
