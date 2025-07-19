<?php
// bootstrap/env.php

require __DIR__ . '/../vendor/autoload.php';

/**
 * Very simple .env file loader.
 * - Ignores blank lines & comments.
 * - Respects already-set real environment vars.
 * - Strips optional surrounding quotes.
 */
function loadEnvFile(string $path): void
{
    if (! is_readable($path)) {
        return;
    }
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        // skip comments
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        // only split on first “=”
        [$name, $value] = array_merge(explode('=', $line, 2), ['']);
        $name  = trim($name);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        // don't overwrite real env
        if (getenv($name) === false) {
            putenv("$name=$value");
            $_ENV[$name]    = $value;
            $_SERVER[$name] = $value;
        }
    }
}

$root = dirname(__DIR__);
$env  = $_SERVER['APP_ENV']
    ?? $_ENV['APP_ENV']
    ?? getenv('APP_ENV')
    ?? null;

$files = [
    $root . '/.env',
    $root . '/.env.local',
];
if ($env) {
    $files[] = "$root/.env.$env";
    $files[] = "$root/.env.$env.local";
}

// 3) Load them in order (later ones override earlier)
foreach ($files as $file) {
    loadEnvFile($file);
}