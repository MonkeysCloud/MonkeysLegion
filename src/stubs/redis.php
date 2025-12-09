<?php

/**
 * Redis Stub File
 * 
 * This file provides IDE hints for the Redis PHP extension.
 * The actual Redis class is provided by the php-redis extension.
 * Install it with: pecl install redis
 * 
 * @link https://github.com/phpredis/phpredis
 */

if (!extension_loaded('redis')) {
    /**
     * Stub class for IDE support when Redis extension is not loaded
     * This is only for static analysis - the real class comes from the extension
     */
    class Redis
    {
        public const OPT_PREFIX = 2;

        public function connect(string $host, int $port = 6379, float $timeout = 0.0): bool
        {
            return false;
        }
        public function auth(string $password): bool
        {
            return false;
        }
        public function select(int $database): bool
        {
            return false;
        }
        public function setOption(int $option, mixed $value): bool
        {
            return false;
        }
        public function get(string $key): mixed
        {
            return null;
        }
        public function set(string $key, mixed $value, mixed $timeout = null): bool
        {
            return false;
        }
        public function del(array|string $key): int
        {
            return 0;
        }
        public function exists(string $key): bool
        {
            return false;
        }
        public function incr(string $key): int
        {
            return 0;
        }
        public function decr(string $key): int
        {
            return 0;
        }
        public function expire(string $key, int $seconds): bool
        {
            return false;
        }
        public function ttl(string $key): int
        {
            return 0;
        }
    }
}
