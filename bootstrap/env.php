<?php

declare(strict_types=1);

/**
 * MonkeysLegion v2 — Environment Bootstrap
 *
 * Loads .env files using the cascade: .env → .env.local → .env.{APP_ENV} → .env.{APP_ENV}.local
 * Registers the base_path() helper and sets up error reporting.
 */

(static function (): void {
    // ── Define base_path() if not already defined ────────────────────
    if (!function_exists('base_path')) {
        /**
         * Return the application base path, optionally appending a sub-path.
         */
        function base_path(string $path = ''): string
        {
            static $basePath;
            $basePath ??= dirname(__DIR__);

            return $path !== '' ? $basePath . DIRECTORY_SEPARATOR . $path : $basePath;
        }
    }

    // ── Load .env cascade ────────────────────────────────────────────
    $basePath = base_path();
    $envFiles = [
        $basePath . '/.env',
        $basePath . '/.env.local',
    ];

    $appEnv = $_ENV['APP_ENV'] ?? $_SERVER['APP_ENV'] ?? null;

    if ($appEnv !== null && $appEnv !== '') {
        $envFiles[] = $basePath . '/.env.' . $appEnv;
        $envFiles[] = $basePath . '/.env.' . $appEnv . '.local';
    }

    foreach ($envFiles as $envFile) {
        if (!is_file($envFile) || !is_readable($envFile)) {
            continue;
        }

        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($lines === false) {
            continue;
        }

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip comments and empty lines
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Parse KEY=VALUE (supports quoted values)
            if (!str_contains($line, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $line, 2);
            $key   = trim($key);
            $value = trim($value);

            // Strip surrounding quotes
            if (
                (str_starts_with($value, '"') && str_ends_with($value, '"'))
                || (str_starts_with($value, "'") && str_ends_with($value, "'"))
            ) {
                $value = substr($value, 1, -1);
            }

            // Only set if not already defined by the real environment
            if (!isset($_ENV[$key])) {
                $_ENV[$key]    = $value;
                $_SERVER[$key] = $value;
                putenv("{$key}={$value}");
            }
        }
    }

    // ── Configure error reporting ────────────────────────────────────
    $debug = filter_var($_ENV['APP_DEBUG'] ?? 'false', FILTER_VALIDATE_BOOLEAN);

    error_reporting(E_ALL);
    ini_set('display_errors', $debug ? '1' : '0');
    ini_set('display_startup_errors', $debug ? '1' : '0');
    ini_set('log_errors', '1');

    // ── Set default timezone ─────────────────────────────────────────
    $timezone = $_ENV['APP_TIMEZONE'] ?? 'UTC';
    date_default_timezone_set($timezone);
})();
