<?php

declare(strict_types=1);

/**
 * MonkeysLegion v2 — Test Bootstrap
 *
 * Sets up autoloading and env for the test suite.
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Define base_path() for tests
if (!function_exists('base_path')) {
    function base_path(string $path = ''): string
    {
        static $basePath;
        $basePath ??= dirname(__DIR__);

        return $path !== '' ? $basePath . DIRECTORY_SEPARATOR . $path : $basePath;
    }
}

// Test-safe env defaults
$_ENV['APP_ENV']   = 'testing';
$_ENV['APP_DEBUG'] = 'true';
