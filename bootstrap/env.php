<?php
/**
 * Loads env files in this order (highest priority last):
 *   1. .env                – baseline defaults (committed to VCS)
 *   2. .env.local          – machine-specific overrides (git-ignored)
 *   3. .env.${APP_ENV}     – per-environment (dev / staging / prod …)
 *   4. .env.${APP_ENV}.local
 *
 * Anything already set in the real environment wins over every file.
 * (That is Dotenv’s default behaviour with bootEnv/usePutenv.)
 */

use Symfony\Component\Dotenv\Dotenv;

$root = dirname(__DIR__);                  // adjust if the bootstrap lives elsewhere
$files = ['.env', '.env.local'];

if (isset($_SERVER['APP_ENV'])) {
    $files[] = ".env.{$_SERVER['APP_ENV']}";
    $files[] = ".env.{$_SERVER['APP_ENV']}.local";
}

$dotenv = new Dotenv();
$dotenv->usePutenv(true);                  // sets both $_ENV and getenv()

foreach ($files as $file) {
    $path = $root . '/' . $file;
    if (is_file($path) && is_readable($path)) {
        $dotenv->load($path);
    }
}