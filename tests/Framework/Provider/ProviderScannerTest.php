<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider;

use MonkeysLegion\Framework\Provider\ProviderScanner;
use MonkeysLegion\Tests\Framework\Provider\Fixtures\AttributeOnlyProvider;
use MonkeysLegion\Tests\Framework\Provider\Fixtures\AttributeProvider;
use MonkeysLegion\Tests\Framework\Provider\Fixtures\InterfaceOnlyProvider;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\Provider\ProviderScanner
 */
final class ProviderScannerTest extends TestCase
{
    // ── Basic edge-case tests ───────────────────────────────────

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

    // ── attributeRequired=true (default) ────────────────────────

    public function testAttributeRequiredOnlyReturnsAttributedClasses(): void
    {
        $scanner = new ProviderScanner();
        $fixturesDir = __DIR__ . '/Fixtures';

        $result = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: true,
        );

        // Should include AttributeProvider and AttributeOnlyProvider (both have #[Provider])
        $this->assertContains(AttributeProvider::class, $result);
        $this->assertContains(AttributeOnlyProvider::class, $result);

        // Should NOT include InterfaceOnlyProvider (no attribute)
        $this->assertNotContains(InterfaceOnlyProvider::class, $result);
    }

    // ── attributeRequired=false (interface-based discovery) ─────

    public function testInterfaceDiscoveryIncludesInterfaceOnlyProviders(): void
    {
        $scanner = new ProviderScanner();
        $fixturesDir = __DIR__ . '/Fixtures';

        $result = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: false,
        );

        // Should include all three concrete providers
        $this->assertContains(AttributeProvider::class, $result);
        $this->assertContains(AttributeOnlyProvider::class, $result);
        $this->assertContains(InterfaceOnlyProvider::class, $result);
    }

    public function testScanExcludesPlainClasses(): void
    {
        $scanner = new ProviderScanner();
        $fixturesDir = __DIR__ . '/Fixtures';

        $result = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: false,
        );

        // PlainClass has neither attribute nor interface — must be excluded
        $this->assertNotContains(
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures\\PlainClass',
            $result,
        );
    }

    // ── Abstract class guard ────────────────────────────────────

    public function testScanSkipsAbstractClasses(): void
    {
        $scanner = new ProviderScanner();
        $fixturesDir = __DIR__ . '/Fixtures';

        $resultStrict = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: true,
        );

        $resultRelaxed = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: false,
        );

        $abstractClass = 'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures\\AbstractBaseProvider';

        // Abstract provider must be excluded in both modes
        $this->assertNotContains($abstractClass, $resultStrict);
        $this->assertNotContains($abstractClass, $resultRelaxed);
    }

    // ── Context and priority metadata ───────────────────────────

    public function testAttributeProviderHasHigherPriorityThanAttributeOnly(): void
    {
        $scanner = new ProviderScanner();
        $fixturesDir = __DIR__ . '/Fixtures';

        $result = $scanner->scan(
            $fixturesDir,
            'MonkeysLegion\\Tests\\Framework\\Provider\\Fixtures',
            attributeRequired: true,
        );

        // AttributeProvider has priority=10, AttributeOnlyProvider has priority=5
        // Higher priority should come first
        $attrIndex = array_search(AttributeProvider::class, $result, true);
        $attrOnlyIndex = array_search(AttributeOnlyProvider::class, $result, true);

        $this->assertNotFalse($attrIndex);
        $this->assertNotFalse($attrOnlyIndex);
        $this->assertLessThan($attrOnlyIndex, $attrIndex, 'Higher priority provider should appear first');
    }
}

