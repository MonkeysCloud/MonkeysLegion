<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Schedule\Contracts\ScheduleDriver;
use MonkeysLegion\Schedule\Discovery\AttributeScanner;
use MonkeysLegion\Schedule\Driver\DriverFactory;
use MonkeysLegion\Schedule\Schedule;
use MonkeysLegion\Schedule\ScheduleManager;
use Psr\SimpleCache\CacheInterface;

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
                    cache: $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null,
                    redis: $c->has(\Redis::class) ? $c->get(\Redis::class) : null,
                );

                return $factory->make('cache');
            },

            ScheduleManager::class => static function ($c): ScheduleManager {
                return new ScheduleManager(
                    cache: $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null,
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
