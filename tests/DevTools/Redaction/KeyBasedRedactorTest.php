<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Redaction;

use MonkeysLegion\DevTools\Redaction\KeyBasedRedactor;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Redaction\KeyBasedRedactor
 */
final class KeyBasedRedactorTest extends TestCase
{
    public function testRedactsDefaultSensitiveKeys(): void
    {
        $redactor = new KeyBasedRedactor();

        $data = $redactor->redact([
            'username' => 'jorge',
            'password' => 'secret123',
            'authorization' => 'Bearer xyz',
        ]);

        $this->assertSame('jorge', $data['username']);
        $this->assertSame('████████', $data['password']);
        $this->assertSame('████████', $data['authorization']);
    }

    public function testRedactsNestedKeys(): void
    {
        $redactor = new KeyBasedRedactor();

        $data = $redactor->redact([
            'config' => [
                'api_key' => 'sk-12345',
                'host' => 'localhost',
            ],
        ]);

        $this->assertSame('████████', $data['config']['api_key']);
        $this->assertSame('localhost', $data['config']['host']);
    }

    public function testPartialKeyMatch(): void
    {
        $redactor = new KeyBasedRedactor();

        // "access_token" contains "token" which is in defaults
        $data = $redactor->redact(['my_access_token' => 'abc']);
        $this->assertSame('████████', $data['my_access_token']);
    }

    public function testCustomSensitiveKeys(): void
    {
        $redactor = new KeyBasedRedactor(sensitiveKeys: ['ssn', 'credit_card']);

        $data = $redactor->redact([
            'ssn' => '123-45-6789',
            'name' => 'Jorge',
            'credit_card' => '4111111111111111',
        ]);

        $this->assertSame('████████', $data['ssn']);
        $this->assertSame('Jorge', $data['name']);
        $this->assertSame('████████', $data['credit_card']);
    }

    public function testEmptySensitiveKeysRedactsNothing(): void
    {
        $redactor = new KeyBasedRedactor(sensitiveKeys: []);

        $data = $redactor->redact(['password' => 'test', 'token' => 'abc']);

        $this->assertSame('test', $data['password']);
        $this->assertSame('abc', $data['token']);
    }

    public function testIsRedactable(): void
    {
        $redactor = new KeyBasedRedactor();

        $this->assertTrue($redactor->isRedactable('password'));
        $this->assertTrue($redactor->isRedactable('Authorization'));
        $this->assertFalse($redactor->isRedactable('username'));
    }

    public function testRedactValue(): void
    {
        $redactor = new KeyBasedRedactor();

        $this->assertSame('████████', $redactor->redactValue('token', 'abc123'));
        $this->assertSame('visible', $redactor->redactValue('name', 'visible'));
    }

    public function testRedactionCount(): void
    {
        $redactor = new KeyBasedRedactor();

        $redactor->redact([
            'password' => 'a',
            'token' => 'b',
            'name' => 'jorge',
        ]);

        $this->assertSame(2, $redactor->lastRedactionCount);
    }

    public function testPreserveChars(): void
    {
        $redactor = new KeyBasedRedactor(
            sensitiveKeys: ['secret'],
            preserveChars: 2,
        );

        // Long enough to preserve
        $data = $redactor->redact(['secret' => 'abcdefghijklmnop']);
        $this->assertStringStartsWith('ab', $data['secret']);
        $this->assertStringEndsWith('op', $data['secret']);
    }

    public function testNonStringValueRedactedAsPlaceholder(): void
    {
        $redactor = new KeyBasedRedactor();
        $data = $redactor->redact(['token' => 12345]);

        $this->assertSame('████████', $data['token']);
    }

    public function testMaxDepthLimit(): void
    {
        $redactor = new KeyBasedRedactor();

        // Build 12-level deep nested array
        $data = ['password' => 'deep'];
        for ($i = 0; $i < 12; $i++) {
            $data = ['level' => $data];
        }

        $result = $redactor->redact($data);

        // Beyond max depth (10), redaction stops — password may pass through
        $this->assertIsArray($result);
    }
}
