<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework;

use MonkeysLegion\Framework\HttpBootstrap;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\HttpBootstrap
 */
final class HttpBootstrapTest extends TestCase
{
    public function testRunTriggersDeprecationNotice(): void
    {
        // We expect a deprecation notice
        $this->expectException(\ErrorException::class);

        // Convert deprecation to exception for testing
        set_error_handler(static function (int $errno, string $errstr): never {
            throw new \ErrorException($errstr, 0, $errno);
        }, E_USER_DEPRECATED);

        try {
            HttpBootstrap::run('/fake/path');
        } finally {
            restore_error_handler();
        }
    }
}
