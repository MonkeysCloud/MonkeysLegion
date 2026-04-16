<?php

declare(strict_types=1);

namespace MonkeysLegion\DI;

/**
 * Compiled container cache for production environments.
 *
 * Serializes DI definitions (excluding closures) to a PHP file
 * for zero-overhead container building in production.
 */
final class CompiledContainerCache
{
    /**
     * Check if a compiled cache file exists.
     */
    public static function exists(string $path): bool
    {
        return is_file($path) && is_readable($path);
    }

    /**
     * Load the compiled definitions from cache.
     *
     * @return array<string, mixed>|null
     */
    public static function load(string $path): ?array
    {
        if (!self::exists($path)) {
            return null;
        }

        try {
            $data = require $path;

            return is_array($data) ? $data : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Compile and write definitions to cache.
     *
     * Closures are stripped — only scalar and array definitions are cached.
     * Providers with closures will be re-resolved at runtime.
     *
     * @param array<string, mixed> $definitions
     */
    public static function compile(string $path, array $definitions): void
    {
        $cacheable = [];

        foreach ($definitions as $id => $definition) {
            // Skip closures — they can't be serialized
            if ($definition instanceof \Closure) {
                continue;
            }

            // Skip callable arrays (e.g. [$object, 'method'])
            if (is_array($definition) && is_callable($definition)) {
                continue;
            }

            // Skip objects that aren't serializable
            if (is_object($definition)) {
                continue;
            }

            $cacheable[$id] = $definition;
        }

        if ($cacheable === []) {
            return;
        }

        $dir = dirname($path);

        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $content = '<?php declare(strict_types=1);' . "\n\n"
            . '// MonkeysLegion v2 — Compiled Container Cache' . "\n"
            . '// Generated: ' . date('Y-m-d H:i:s T') . "\n"
            . '// DO NOT EDIT — regenerated automatically in production.' . "\n\n"
            . 'return ' . var_export($cacheable, true) . ";\n";

        // Atomic write with error handling
        $tmpPath = $path . '.tmp.' . bin2hex(random_bytes(4));

        $written = file_put_contents($tmpPath, $content, LOCK_EX);

        if ($written === false) {
            @unlink($tmpPath);
            return;
        }

        if (!@rename($tmpPath, $path)) {
            @unlink($tmpPath);
            return;
        }

        // Invalidate OPcache for the target path
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($path, true);
        }
    }

    /**
     * Remove the compiled cache.
     */
    public static function clear(string $path): void
    {
        if (is_file($path)) {
            unlink($path);
        }
    }

    /**
     * Validate the integrity of a compiled cache file.
     */
    public static function isValid(string $path): bool
    {
        if (!self::exists($path)) {
            return false;
        }

        $data = self::load($path);

        return $data !== null && $data !== [];
    }
}
