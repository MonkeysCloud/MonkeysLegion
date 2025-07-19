<?php
require_once __DIR__.'/../vendor/autoload.php';

use Dotenv\Dotenv;

$root = dirname(__DIR__);

$dotenv = Dotenv::createImmutable($root, [
    '.env', '.env.local',
    '.env.'.($_ENV['APP_ENV'] ?? $_SERVER['APP_ENV'] ?? getenv('APP_ENV') ?: 'dev'),
    '.env.'.($_ENV['APP_ENV'] ?? getenv('APP_ENV') ?: 'dev').'.local',
]);

$dotenv->safeLoad();
$dotenv->required(['DB_HOST', 'DB_DATABASE'])->notEmpty();