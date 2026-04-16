<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use MonkeysLegion\Env\Contracts\EnvBootstrapperInterface;
use MonkeysLegion\Env\EnvManager;
use MonkeysLegion\Env\Loaders\DotenvLoader;
use MonkeysLegion\Env\Repositories\NativeEnvRepository;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Mlc\Loader;
use MonkeysLegion\Mlc\Parsers\MlcParser;

/**
 * MLC configuration loader for MonkeysLegion v2.
 *
 * Uses the MLC package's Loader + MlcParser + Env package for full
 * env() resolution and file parsing.
 *
 * Loading cascade:
 *   1. Load all named configs (app, database, auth, etc.)
 *   2. Production: compile to PHP for OPcache optimization
 */
final class ConfigLoader
{
    /**
     * Load all MLC configuration files from the given directory.
     */
    public static function loadMlc(string $configDir): MlcConfig
    {
        if (!is_dir($configDir)) {
            return new MlcConfig([]);
        }

        $env = $_ENV['APP_ENV'] ?? 'production';
        $isProduction = $env === 'production';

        // ── Try compiled cache in production ─────────────────────────
        $cachePath = dirname($configDir) . '/var/cache/config.compiled.php';

        if ($isProduction && is_file($cachePath)) {
            $data = require $cachePath;

            if (is_array($data)) {
                return new MlcConfig($data);
            }
        }

        // ── Bootstrap env + parser ───────────────────────────────────
        $rootPath = dirname($configDir);

        $envManager = new EnvManager(
            loader: new DotenvLoader(),
            repository: new NativeEnvRepository(),
        );

        $parser = new MlcParser(
            envBootstrapper: $envManager,
            root: $rootPath,
        );

        $loader = new Loader(
            parser: $parser,
            baseDir: $configDir,
        );

        // ── Discover all .mlc files and load them ────────────────────
        $configNames = self::discoverConfigNames($configDir);

        if ($configNames === []) {
            return new MlcConfig([]);
        }

        $config = $loader->load($configNames);

        // ── Cache for production ─────────────────────────────────────
        if ($isProduction) {
            $cacheDir = dirname($cachePath);

            if (!is_dir($cacheDir)) {
                mkdir($cacheDir, 0755, true);
            }

            file_put_contents(
                $cachePath,
                '<?php return ' . var_export($config->toArray(), true) . ";\n",
                LOCK_EX,
            );
        }

        return $config;
    }

    /**
     * Discover config names from .mlc files in a directory.
     *
     * @return list<string>
     */
    private static function discoverConfigNames(string $configDir): array
    {
        $files = glob($configDir . '/*.mlc') ?: [];
        $names = [];

        foreach ($files as $file) {
            $basename = basename($file, '.mlc');

            // Skip examples
            if (str_ends_with($basename, '.example')) {
                continue;
            }

            $names[] = $basename;
        }

        sort($names);

        return array_values(array_unique($names));
    }
}
