<?php

use Dotenv\Dotenv;

$root = dirname(__DIR__, 4);
$env  = getenv('APP_ENV') ?: 'dev';

$files = [
    '.env',
    '.env.local',
    ".env.$env",
    ".env.$env.local",
];

// Keep only existing files
$existingFiles = [];
foreach ($files as $file) {
    $fullPath = $root . DIRECTORY_SEPARATOR . $file;
    if (file_exists($fullPath)) $existingFiles[] = $file;
}

if (empty($existingFiles)) {
    throw new \RuntimeException("No .env files found in: $root");
}

$dotenv = Dotenv::createImmutable($root, $existingFiles);
$dotenv->safeLoad();
$dotenv->required(['DB_HOST', 'DB_DATABASE'])->notEmpty();
