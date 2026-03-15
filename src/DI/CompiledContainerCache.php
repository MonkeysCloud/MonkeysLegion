<?php

declare(strict_types=1);

namespace MonkeysLegion\DI;

/**
 * Compiled container cache for production environments.
 *
 * Serializes the resolved provider definitions to a PHP file that can be
 * loaded via `require` on subsequent requests — zero reflection, zero glob,
 * fully opcache-friendly.
 */
final class CompiledContainerCache
{
    /**
     * Attempt to load cached definitions.
     *
     * @param string $path Absolute path to the cache file
     * @return array<string, callable|object>|null Returns null if cache missing or corrupt
     */
    public static function load(string $path): ?array
    {
        if (!is_file($path)) {
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
     * Compile definitions to a PHP cache file.
     *
     * When possible, writes the resolved definitions array directly to a
     * self-contained PHP file using `var_export`, so subsequent requests can
     * simply `require` the file with no provider discovery or config rebuild.
     *
     * If the definitions contain closures (which cannot be safely exported),
     * we fall back to bootstrapping via `AppConfig` at runtime.
     *
     * @param string $path  Absolute path to write cache file
     * @param array  $definitions The DI definitions array
     */
    public static function compile(string $path, array $definitions): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        // Detect whether any definitions are closures; these cannot be
        // reliably exported with var_export().
        $hasClosures = false;
        foreach ($definitions as $value) {
            if ($value instanceof \Closure) {
                $hasClosures = true;
                break;
            }
        }

        $content = "<?php\n\n";
        $content .= "/**\n * Compiled container cache.\n *\n";
        $content .= " * Generated: " . date('Y-m-d H:i:s') . "\n";
        $content .= " * Entries: " . count($definitions) . "\n";
        $content .= " * DO NOT EDIT — regenerate with: ml config:cache\n */\n\n";

        if ($hasClosures) {
            // Fallback: rebuild definitions from providers at runtime.
            $content .= "return (static function () {\n";
            $content .= "    // Re-build definitions from providers (cached bootstrap)\n";
            $content .= "    \$config = new \\MonkeysLegion\\Config\\AppConfig();\n";
            $content .= "    return \$config();\n";
            $content .= "})();\n";
        } else {
            // Fast path: cache the resolved definitions array directly.
            $exported = var_export($definitions, true);
            $content .= "return " . $exported . ";\n";
        }

        file_put_contents($path, $content, LOCK_EX);

        // Make it writable for future cache clears
        chmod($path, 0644);

        // Invalidate opcache for this file if opcache is available
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($path, true);
        }
    }

    /**
     * Clear the compiled cache file.
     *
     * @param string $path Absolute path to the cache file
     * @return bool True if file was successfully removed
     */
    public static function clear(string $path): bool
    {
        if (!is_file($path)) {
            return false;
        }

        $result = unlink($path);

        // Invalidate opcache entry
        if ($result && function_exists('opcache_invalidate')) {
            opcache_invalidate($path, true);
        }

        return $result;
    }

    /**
     * Check if a valid compiled cache exists.
     *
     * @param string $path Absolute path to the cache file
     */
    public static function exists(string $path): bool
    {
        return is_file($path) && is_readable($path);
    }
}
