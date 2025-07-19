<?php
use Dotenv\Dotenv;

$root = dirname(__DIR__, 4);   // /var/www/html

$env  = getenv('APP_ENV') ?: 'dev';

Dotenv::createImmutable($root, [
    '.env', '.env.local',
    ".env.$env", ".env.$env.local",
])->safeLoad()
    ->required(['DB_HOST', 'DB_DATABASE'])->notEmpty();