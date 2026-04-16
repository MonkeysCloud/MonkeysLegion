<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Attributes;

use MonkeysLegion\Framework\Attributes\BootAfter;
use MonkeysLegion\Framework\Attributes\Provider;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\Attributes\Provider
 * @covers \MonkeysLegion\Framework\Attributes\BootAfter
 */
final class AttributeTest extends TestCase
{
    // ── Provider ─────────────────────────────────────────────────

    public function testProviderDefaults(): void
    {
        $attr = new Provider();

        $this->assertSame(0, $attr->priority);
        $this->assertSame('all', $attr->context);
    }

    public function testProviderWithCustomValues(): void
    {
        $attr = new Provider(priority: 100, context: 'http');

        $this->assertSame(100, $attr->priority);
        $this->assertSame('http', $attr->context);
    }

    public function testProviderCliContext(): void
    {
        $attr = new Provider(context: 'cli');

        $this->assertSame('cli', $attr->context);
        $this->assertSame(0, $attr->priority);
    }

    public function testProviderIsReflectable(): void
    {
        $ref = new \ReflectionClass(Provider::class);
        $attrs = $ref->getAttributes(\Attribute::class);

        $this->assertNotEmpty($attrs);
    }

    // ── BootAfter ────────────────────────────────────────────────

    public function testBootAfterStoresDependency(): void
    {
        $attr = new BootAfter(dependency: 'SomeProvider');

        $this->assertSame('SomeProvider', $attr->dependency);
    }

    public function testBootAfterWithFQCN(): void
    {
        $attr = new BootAfter(dependency: 'MonkeysLegion\\Config\\Providers\\DatabaseProvider');

        $this->assertSame('MonkeysLegion\\Config\\Providers\\DatabaseProvider', $attr->dependency);
    }

    public function testBootAfterIsRepeatable(): void
    {
        $ref = new \ReflectionClass(BootAfter::class);
        $attrs = $ref->getAttributes(\Attribute::class);

        $this->assertNotEmpty($attrs);

        /** @var \Attribute $instance */
        $instance = $attrs[0]->newInstance();

        $this->assertTrue(($instance->flags & \Attribute::IS_REPEATABLE) !== 0);
    }
}
