<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cache\CacheManager;
use MonkeysLegion\Cache\CacheStoreInterface;
use MonkeysLegion\Collection\Cache\Bridge\FileCacheAdapter;
use MonkeysLegion\Schedule\Contracts\ScheduleDriver;
use MonkeysLegion\Schedule\Discovery\AttributeScanner;
use MonkeysLegion\Schedule\Driver\DriverFactory;
use MonkeysLegion\Schedule\Schedule;
use MonkeysLegion\Schedule\ScheduleManager;

/**
 * Task scheduler provider.
 *
 * CLI-only context. Uses Schedule + ScheduleManager from the schedule package.
 */
final class ScheduleProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'cli';
    }

    public function getDefinitions(): array
    {
        return [
            ScheduleDriver::class => static function ($c): ScheduleDriver {
                $factory = new DriverFactory(
                    cache: new FileCacheAdapter(
                        cacheStore: $c->get(CacheStoreInterface::class),
                        cacheManager: $c->get(CacheManager::class),
                    ),
                    redis: $c->has(\Redis::class) ? $c->get(\Redis::class) : null,
                );

                return $factory->make('cache');
            },

            ScheduleManager::class => static function ($c): ScheduleManager {
                $cache = $c->has(CacheStoreInterface::class)
                    ? new FileCacheAdapter(
                        cacheStore: $c->get(CacheStoreInterface::class),
                        cacheManager: $c->get(CacheManager::class),
                    )
                    : null;

                return new ScheduleManager(
                    cache: $cache,
                    scanner: new AttributeScanner(),
                    driver: $c->get(ScheduleDriver::class),
                );
            },

            Schedule::class => fn($c): Schedule => new Schedule(
                manager: $c->get(ScheduleManager::class),
            ),
        ];
    }
}
