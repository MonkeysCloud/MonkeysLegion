<?php

use Dotenv\Dotenv;

$env = getenv('APP_ENV') ?: 'dev';

// Candidate roots depending on context
$roots = [
    dirname(__DIR__, 4),         // original relative guess (vendor usage)
    __DIR__ . '/../../my-app' // The relative path I use for development will only work in dev mode, when the package is symlinked
];

// Candidate .env files
$files = [
    '.env',
    '.env.local',
    ".env.$env",
    ".env.$env.local",
];

$dotenvLoaded = false;

foreach ($roots as $root) {
    $root = realpath($root); // normalize paths
    if (!$root) continue;

    $existingFiles = [];
    foreach ($files as $file) {
        $fullPath = $root . DIRECTORY_SEPARATOR . $file;
        if (file_exists($fullPath)) $existingFiles[] = $file;
    }

    if (!empty($existingFiles)) {
        $dotenv = Dotenv::createImmutable($root, $existingFiles);
        $dotenv->safeLoad();
        $dotenv->required(['DB_HOST', 'DB_DATABASE'])->notEmpty();
        $dotenvLoaded = true;
        break; // stop at first working root
    }
}

if (!$dotenvLoaded) {
    throw new \RuntimeException("No .env files found in candidate roots: " . implode(', ', $roots));
}
