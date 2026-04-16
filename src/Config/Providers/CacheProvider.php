<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cache\CacheManager;
use MonkeysLegion\Cache\CacheStoreInterface;
use MonkeysLegion\Cache\Stores\FileStore;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\SimpleCache\CacheInterface;

/**
 * PSR-16 cache and Redis client provider.
 *
 * Uses the Cache package's FileStore, CacheManager, and CacheStoreInterface.
 */
final class CacheProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            CacheStoreInterface::class => static function ($c): CacheStoreInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $cachePath = $mlc->getString('cache.stores.file.path', 'var/cache/data') ?? 'var/cache/data';

                if (!str_starts_with($cachePath, '/')) {
                    $cachePath = base_path($cachePath);
                }

                if (!is_dir($cachePath)) {
                    mkdir($cachePath, 0755, true);
                }

                return new FileStore(
                    directory: $cachePath,
                    prefix: $mlc->getString('cache.prefix', '') ?? '',
                );
            },

            CacheInterface::class => fn($c): CacheStoreInterface => $c->get(CacheStoreInterface::class),

            CacheManager::class => static function ($c): CacheManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new CacheManager(
                    config: $mlc->getArray('cache', []) ?? [],
                );
            },

            \Redis::class => static function ($c): \Redis {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $redis = new \Redis();

                $host    = $mlc->getString('redis.host', '127.0.0.1') ?? '127.0.0.1';
                $port    = $mlc->getInt('redis.port', 6379) ?? 6379;
                $timeout = $mlc->getFloat('redis.timeout', 0.0) ?? 0.0;

                $redis->connect($host, $port, $timeout);

                $password = $mlc->getString('redis.password');

                if ($password !== null && $password !== '') {
                    $redis->auth($password);
                }

                $database = $mlc->getInt('redis.database', 0) ?? 0;

                if ($database > 0) {
                    $redis->select($database);
                }

                $prefix = $mlc->getString('redis.prefix');

                if ($prefix !== null && $prefix !== '') {
                    $redis->setOption(\Redis::OPT_PREFIX, $prefix);
                }

                return $redis;
            },
        ];
    }
}
