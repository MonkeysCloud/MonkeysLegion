<?php

declare(strict_types=1);

namespace MonkeysLegion\Collection\Cache\Bridge;

use MonkeysLegion\Cache\CacheStats;
use MonkeysLegion\Cache\CacheStoreInterface;
use MonkeysLegion\Cache\Lock\LockInterface;
use MonkeysLegion\Database\Cache\Contracts\CacheInterface as DatabaseCacheInterface;
use MonkeysLegion\Cache\CacheManager;

// Make sure it implements the one the factory is asking for

/**
 * Adapts any PSR-16 cache to the custom Database Cache contract.
 */
final class FileCacheAdapter implements DatabaseCacheInterface
{
    public function __construct(private CacheStoreInterface $cacheStore, private CacheManager $cacheManager) {}

    public function getCacheManager(): CacheManager
    {
        return $this->cacheManager;
    }

    public function store(?string $name = null): CacheStoreInterface
    {
        return $this->cacheStore; // File cache doesn't support multiple stores, so we ignore $name
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->cacheStore->get($key, $default);
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        return $this->cacheStore->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        return $this->cacheStore->delete($key);
    }

    public function clear(): bool
    {
        return $this->cacheStore->clear();
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        return $this->cacheStore->getMultiple($keys, $default);
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        return $this->cacheStore->setMultiple($values, $ttl);
    }

    public function deleteMultiple(iterable $keys): bool
    {
        return $this->cacheStore->deleteMultiple($keys);
    }

    public function has(string $key): bool
    {
        return $this->cacheStore->has($key);
    }

    public function remember(string $key, int|\DateInterval|null $ttl, callable $callback): mixed
    {
        $closure = \Closure::fromCallable($callback);
        return $this->cacheStore->remember($key, $ttl, $closure);
    }

    public function rememberForever(string $key, \Closure $callback): mixed
    {
        return $this->cacheStore->rememberForever($key, $callback);
    }

    public function forever(string $key, mixed $value): bool
    {
        return $this->cacheStore->forever($key, $value);
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        return $this->cacheStore->pull($key, $default);
    }

    public function add(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        return $this->cacheStore->add($key, $value, $ttl);
    }

    public function touch(string $key, \DateInterval|int $ttl): bool
    {
        return $this->cacheStore->touch($key, $ttl);
    }

    public function increment(string $key, int $value = 1): int|false
    {
        return $this->cacheStore->increment($key, $value);
    }

    public function decrement(string $key, int $value = 1): int|false
    {
        return $this->cacheStore->decrement($key, $value);
    }

    public function integer(string $key, int $default = 0): int
    {
        return $this->cacheStore->integer($key, $default);
    }

    public function boolean(string $key, bool $default = false): bool
    {
        return $this->cacheStore->boolean($key, $default);
    }

    public function float(string $key, float $default = 0.0): float
    {
        return $this->cacheStore->float($key, $default);
    }

    public function string(string $key, string $default = ''): string
    {
        return $this->cacheStore->string($key, $default);
    }

    public function array(string $key, array $default = []): array
    {
        return $this->cacheStore->array($key, $default);
    }

    public function flexible(string $key, array $ttl, \Closure $callback, float $beta = 1.0): mixed
    {
        return $this->cacheStore->flexible($key, $ttl, $callback, $beta);
    }

    public function tags(array|string $tags): CacheStoreInterface
    {
        $this->cacheStore->tags($tags);
        return $this->cacheStore;
    }

    public function lock(string $name, int $seconds = 0, ?string $owner = null): LockInterface
    {
        return $this->cacheStore->lock($name, $seconds, $owner);
    }

    public function getPrefix(): string
    {
        return $this->cacheStore->getPrefix();
    }

    public function getStats(): CacheStats
    {
        return $this->cacheStore->getStats();
    }

    public function clearByPrefix(string $prefix): bool
    {
        return false; // Not supported by file cache, could be implemented with a custom method if needed
    }

    public function isConnected(): bool
    {
        return true; // File cache is always "connected" as it's just the filesystem
    }

    public function getStatistics(): array
    {
        return [
            'deletes' => $this->cacheStore->getStats()->deletes,
            'hit_rate' => $this->cacheStore->getStats()->hitRate,
            'hits' => $this->cacheStore->getStats()->hits,
            'misses' => $this->cacheStore->getStats()->misses,
            'item_count' => $this->cacheStore->getStats()->itemCount,
            'memory_formatted' => $this->cacheStore->getStats()->memoryFormatted,
            'memory_usage' => $this->cacheStore->getStats()->memoryUsage,
        ];
    }
}
