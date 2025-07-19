<?php

use Dotenv\Dotenv;

$root = dirname(__DIR__);

$env  = getenv('APP_ENV') ?: 'dev';
$dotenv = Dotenv::createImmutable($root, [
    '.env', '.env.local',
    ".env.$env",
    ".env.$env.local",
]);

$dotenv->safeLoad();
$dotenv->required(['DB_HOST', 'DB_DATABASE'])->notEmpty();