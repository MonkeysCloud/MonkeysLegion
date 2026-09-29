<?php

/**
 * Redis Stub File
 *
 * This file provides IDE hints for the Redis PHP extension (phpredis).
 * The actual Redis class is provided by the ext-redis extension.
 * Install it with: pecl install redis
 *
 * @link https://github.com/phpredis/phpredis
 *
 * This stub covers all methods used across the MonKeysLegion framework:
 * - Core: connect, auth, select, setOption, getOption, ping, info
 * - Strings: get, set, setex, del, exists, incr, decr, append, strlen
 * - Keys: keys, expire, expireAt, persist, ttl, type
 * - Hashes: hGetAll, hMSet, hMGet, hGet, hSet, hDel, hExists, hIncrBy
 * - Sets: sAdd, sRem, sMembers, sIsMember, sCard
 * - Sorted Sets: zAdd, zRange, zRem, zScore, zCard, zRevRange
 * - Lists: lPush, rPush, lPop, rPop, lRange, lLen
 * - Server: flushDB, flushAll, dbSize
 * - Scripting: eval, script
 * - Transactions: multi, exec, discard, watch, unwatch
 * - Pipeline: pipeline
 */

if (!extension_loaded('redis')) {
    /**
     * Stub class for IDE support when Redis extension is not loaded.
     * This is only for static analysis — the real class comes from the extension.
     */
    class Redis
    {
        // ── Options ──────────────────────────────────────────────
        public const OPT_PREFIX              = 2;
        public const OPT_SERIALIZER          = 1;
        public const OPT_READ_TIMEOUT        = 3;
        public const OPT_SCAN                = 4;
        public const OPT_SLAVE_FAILOVER      = 5;
        public const SERIALIZER_NONE         = 0;
        public const SERIALIZER_PHP          = 1;
        public const SERIALIZER_IGBINARY     = 2;
        public const SERIALIZER_MSGPACK      = 3;
        public const SERIALIZER_JSON         = 4;

        // ── Connection ───────────────────────────────────────────
        public function connect(string $host, int $port = 6379, float $timeout = 0.0, ?string $persistent_id = null, int $retry_interval = 0, float $read_timeout = 0.0): bool { return false; }
        public function pconnect(string $host, int $port = 6379, float $timeout = 0.0, ?string $persistent_id = null, int $retry_interval = 0, float $read_timeout = 0.0): bool { return false; }
        public function auth(\Redis|string $password): bool { return false; }
        public function select(int $database): bool { return false; }
        public function ping(?string $key = null): mixed { return false; }
        public function close(): bool { return false; }
        public function quit(): bool { return false; }

        // ── Server ───────────────────────────────────────────────
        public function flushDB(bool $async = false): bool { return false; }
        public function flushAll(bool $async = false): bool { return false; }
        public function dbSize(): int { return 0; }
        public function info(?string $option = null): array { return []; }
        public function time(): array { return [0, 0]; }

        // ── Options ──────────────────────────────────────────────
        public function setOption(int $option, mixed $value): bool { return false; }
        public function getOption(int $option): mixed { return 0; }

        // ── Strings ──────────────────────────────────────────────
        public function get(string $key): mixed { return null; }
        public function set(string $key, mixed $value, mixed $options = null): \Redis|string|bool { return false; }
        public function setex(string $key, int $ttl, mixed $value): bool { return false; }
        public function psetex(string $key, int $ttl, mixed $value): bool { return false; }
        public function setnx(string $key, mixed $value): bool { return false; }
        public function del(array|string $key, string ...$other_keys): int { return 0; }
        public function unlink(array|string $key, string ...$other_keys): int { return 0; }
        public function exists(string $key, string ...$other_keys): int { return 0; }
        public function incr(string $key): int { return 0; }
        public function incrBy(string $key, int $value): int { return 0; }
        public function incrByFloat(string $key, float $value): float { return 0.0; }
        public function decr(string $key): int { return 0; }
        public function decrBy(string $key, int $value): int { return 0; }
        public function append(string $key, string $value): int { return 0; }
        public function strlen(string $key): int|false { return 0; }
        public function mget(array $keys): array { return []; }
        public function mset(array $key_values): bool { return false; }
        public function msetnx(array $key_values): bool { return false; }
        public function getSet(string $key, mixed $value): mixed { return null; }

        // ── Keys ─────────────────────────────────────────────────
        public function keys(string $pattern): array { return []; }
        public function type(string $key): int { return 0; }
        public function expire(string $key, int $ttl): bool { return false; }
        public function pexpire(string $key, int $ttl): bool { return false; }
        public function expireAt(string $key, int $timestamp): bool { return false; }
        public function pexpireAt(string $key, int $timestamp): bool { return false; }
        public function ttl(string $key): int { return 0; }
        public function pttl(string $key): int { return 0; }
        public function persist(string $key): bool { return false; }
        public function rename(string $key, string $newkey): bool { return false; }
        public function renameNx(string $key, string $newkey): bool { return false; }
        public function randomKey(): ?string { return null; }

        // ── Hashes ───────────────────────────────────────────────
        public function hGetAll(string $key): array { return []; }
        public function hMSet(string $key, array $key_values): bool { return false; }
        public function hMGet(string $key, array $keys): array { return []; }
        public function hGet(string $key, string $member): mixed { return null; }
        public function hSet(string $key, string $member, mixed $value): int|false { return 0; }
        public function hSetNx(string $key, string $member, mixed $value): bool { return false; }
        public function hDel(string $key, string $member, string ...$other_members): int { return 0; }
        public function hExists(string $key, string $member): bool { return false; }
        public function hIncrBy(string $key, string $member, int $value): int { return 0; }
        public function hIncrByFloat(string $key, string $member, float $value): float { return 0.0; }
        public function hLen(string $key): int|false { return 0; }
        public function hKeys(string $key): array { return []; }
        public function hVals(string $key): array { return []; }

        // ── Sets ─────────────────────────────────────────────────
        public function sAdd(string $key, mixed $value, mixed ...$other_values): int { return 0; }
        public function sRem(string $key, mixed $value, mixed ...$other_values): int { return 0; }
        public function sMembers(string $key): array { return []; }
        public function sIsMember(string $key, string $value): bool { return false; }
        public function sCard(string $key): int { return 0; }
        public function sPop(string $key, int $count = 1): mixed { return false; }

        // ── Sorted Sets ──────────────────────────────────────────
        public function zAdd(string $key, float $score, string $value, mixed ...$extra_args): int { return 0; }
        public function zRange(string $key, int $start, int $end, bool $scores = false): array { return []; }
        public function zRevRange(string $key, int $start, int $end, bool $scores = false): array { return []; }
        public function zRem(string $key, string $member, string ...$other_members): int { return 0; }
        public function zScore(string $key, mixed $member): float|false { return false; }
        public function zCard(string $key): int { return 0; }
        public function zIncrBy(string $key, float $value, mixed $member): float { return 0.0; }

        // ── Lists ────────────────────────────────────────────────
        public function lPush(string $key, mixed $value, mixed ...$other_values): int|false { return 0; }
        public function rPush(string $key, mixed $value, mixed ...$other_values): int|false { return 0; }
        public function lPop(string $key, int $count = 0): mixed { return false; }
        public function rPop(string $key, int $count = 0): mixed { return false; }
        public function lRange(string $key, int $start, int $end): array { return []; }
        public function lLen(string $key): int|false { return 0; }

        // ── Pub/Sub ──────────────────────────────────────────────
        public function publish(string $channel, string $message): int { return 0; }
        public function subscribe(array $channels, callable $callback): bool { return false; }
        public function psubscribe(array $patterns, callable $callback): bool { return false; }

        // ── Scripting ────────────────────────────────────────────
        public function eval(string $script, array $args = [], int $num_keys = 0): mixed { return null; }
        public function evalSha(string $sha1, array $args = [], int $num_keys = 0): mixed { return null; }
        public function script(string $command, string ...$args): mixed { return false; }

        // ── Transactions ─────────────────────────────────────────
        public function multi(int $value = \Redis::MULTI): \Redis|bool { return false; }
        public function exec(): array|bool { return false; }
        public function discard(): bool { return false; }
        public function watch(string $key, string ...$other_keys): bool { return false; }
        public function unwatch(): bool { return false; }

        // ── Pipeline ─────────────────────────────────────────────
        public function pipeline(): \Redis|bool { return false; }

        // ── Scan ─────────────────────────────────────────────────
        public function scan(?int $iterator, ?string $pattern = null, int $count = 0): array|false { return false; }
        public function hScan(string $key, ?int $iterator, ?string $pattern = null, int $count = 0): array|false { return false; }
        public function sScan(string $key, ?int $iterator, ?string $pattern = null, int $count = 0): array|false { return false; }
        public function zScan(string $key, ?int $iterator, ?string $pattern = null, int $count = 0): array|false { return false; }
    }
}
