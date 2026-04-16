<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider;

use MonkeysLegion\Framework\Provider\ProviderScanner;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\Provider\ProviderScanner
 */
final class ProviderScannerTest extends TestCase
{
    public function testScanReturnsEmptyArrayForMissingDirectory(): void
    {
        $scanner = new ProviderScanner();

        $result = $scanner->scan('/nonexistent/path', 'Fake\\Namespace');

        $this->assertSame([], $result);
    }

    public function testScanReturnsEmptyArrayForEmptyDirectory(): void
    {
        $dir = sys_get_temp_dir() . '/ml_scanner_test_' . bin2hex(random_bytes(4));
        mkdir($dir, 0755, true);

        $scanner = new ProviderScanner();
        $result = $scanner->scan($dir, 'Test\\Providers');

        $this->assertSame([], $result);

        rmdir($dir);
    }

    public function testScanSkipsNonPhpFiles(): void
    {
        $dir = sys_get_temp_dir() . '/ml_scanner_test_' . bin2hex(random_bytes(4));
        mkdir($dir, 0755, true);

        // Create a non-PHP file
        file_put_contents($dir . '/readme.txt', 'Not a PHP file');

        $scanner = new ProviderScanner();
        $result = $scanner->scan($dir, 'Test\\Providers');

        $this->assertSame([], $result);

        unlink($dir . '/readme.txt');
        rmdir($dir);
    }

    public function testScanSkipsNonExistentClasses(): void
    {
        $dir = sys_get_temp_dir() . '/ml_scanner_test_' . bin2hex(random_bytes(4));
        mkdir($dir, 0755, true);

        // Create a PHP file without a matching class (namespace won't match)
        file_put_contents($dir . '/FakeProvider.php', '<?php // no class');

        $scanner = new ProviderScanner();
        $result = $scanner->scan($dir, 'NonExistent\\Providers');

        $this->assertSame([], $result);

        unlink($dir . '/FakeProvider.php');
        rmdir($dir);
    }
}
