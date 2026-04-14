<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Cache\CompiledPhpCache;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\SimpleCache\CacheInterface;

final class CacheProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* PSR-16 Cache (file-based fallback for rate-limiting) */
            CacheInterface::class => fn() => new CompiledPhpCache(
                base_path('var/cache/rate_limit')
            ),

            /* Redis Client */
            \Redis::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $redis = new \Redis();

                $host     = $mlc->get('redis.host', '127.0.0.1');
                $port     = (int) $mlc->get('redis.port', 6379);
                $timeout  = (float) $mlc->get('redis.timeout', 0.0);
                $database = (int) $mlc->get('redis.database', 0);

                $connected = $redis->connect($host, $port, $timeout);

                if (!$connected) {
                    throw new \RuntimeException("Failed to connect to Redis at {$host}:{$port}");
                }

                $password = $mlc->get('redis.password', null);
                if ($password !== null && $password !== '') {
                    $redis->auth($password);
                }

                if ($database > 0) {
                    $redis->select($database);
                }

                $prefix = $mlc->get('redis.prefix', null);
                if ($prefix !== null && $prefix !== '') {
                    $redis->setOption(\Redis::OPT_PREFIX, $prefix);
                }

                return $redis;
            },
        ];
    }
}
