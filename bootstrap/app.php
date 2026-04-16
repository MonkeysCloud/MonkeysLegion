<?php

declare(strict_types=1);

/**
 * MonkeysLegion v2 — Application Entry Point
 *
 * Usage from public/index.php:
 *   require __DIR__ . '/../vendor/autoload.php';
 *   $app = require __DIR__ . '/../bootstrap/app.php';
 *   $app->run();
 */

use MonkeysLegion\Framework\Application;

return Application::create(basePath: dirname(__DIR__));
