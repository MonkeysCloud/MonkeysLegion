<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Framework\Application;
use MonkeysLegion\Framework\ExceptionHandler;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * @covers \MonkeysLegion\Framework\ExceptionHandler
 */
final class ExceptionHandlerTest extends TestCase
{
    public function testHandleLogsExceptionViaErrorLogWhenNoLogger(): void
    {
        $container = $this->createMock(Container::class);
        $container->method('has')->willReturn(false);

        $_ENV['APP_DEBUG'] = 'false';
        $app = Application::create(basePath: sys_get_temp_dir());

        $handler = new ExceptionHandler($container, $app);

        // handle() uses echo fallback since headers_sent()=true in CLI
        ob_start();
        $handler->handle(new \RuntimeException('Test error'));
        $output = ob_get_clean();

        $this->assertStringContainsString('500', $output);
    }

    public function testHandleLogsExceptionViaLoggerWhenAvailable(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error')->with('Logger test');

        $container = $this->createMock(Container::class);
        $container->method('has')->willReturnMap([
            [LoggerInterface::class, true],
            [\Psr\Http\Message\ResponseFactoryInterface::class, false],
            [\MonkeysLegion\Http\Emitter\SapiEmitter::class, false],
        ]);
        $container->method('get')->willReturnMap([
            [LoggerInterface::class, $logger],
        ]);

        $_ENV['APP_DEBUG'] = 'false';
        $app = Application::create(basePath: sys_get_temp_dir());

        $handler = new ExceptionHandler($container, $app);

        ob_start();
        $handler->handle(new \RuntimeException('Logger test'));
        ob_get_clean();
    }

    public function testResolveStatusCodeFromExceptionCode(): void
    {
        $_ENV['APP_DEBUG'] = 'true';
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);

        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'resolveStatusCode');

        $this->assertSame(404, $method->invoke($handler, new \RuntimeException('NF', 404)));
        $this->assertSame(500, $method->invoke($handler, new \RuntimeException('ISE', 500)));
        $this->assertSame(500, $method->invoke($handler, new \RuntimeException('Bad', 42)));
        $this->assertSame(500, $method->invoke($handler, new \RuntimeException('Zero')));
    }

    public function testBuildJsonBodyInDebugMode(): void
    {
        $_ENV['APP_DEBUG'] = 'true';
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);

        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'buildJsonBody');

        $body = $method->invoke($handler, new \RuntimeException('JSON test'), 500);
        $decoded = json_decode($body, true);

        $this->assertIsArray($decoded);
        $this->assertSame(500, $decoded['error']['status']);
        $this->assertSame('JSON test', $decoded['error']['message']);
        $this->assertArrayHasKey('exception', $decoded['error']);
        $this->assertArrayHasKey('trace', $decoded['error']);
    }

    public function testBuildJsonBodyInProductionMode(): void
    {
        $_ENV['APP_DEBUG'] = 'false';
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);

        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'buildJsonBody');

        $body = $method->invoke($handler, new \RuntimeException('Secret'), 500);
        $decoded = json_decode($body, true);

        $this->assertSame('Internal Server Error', $decoded['error']['message']);
        $this->assertArrayNotHasKey('exception', $decoded['error']);
        $this->assertArrayNotHasKey('trace', $decoded['error']);
    }

    public function testBuildHtmlBodyInDebugMode(): void
    {
        $_ENV['APP_DEBUG'] = 'true';
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);

        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'buildHtmlBody');

        $html = $method->invoke($handler, new \RuntimeException('HTML test'), 503);

        $this->assertStringContainsString('503', $html);
        $this->assertStringContainsString('HTML test', $html);
        $this->assertStringContainsString('<!DOCTYPE html>', $html);
    }

    public function testBuildHtmlBodyInProductionMode(): void
    {
        $_ENV['APP_DEBUG'] = 'false';
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);

        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'buildHtmlBody');

        $html = $method->invoke($handler, new \RuntimeException('Secret detail'), 500);

        $this->assertStringNotContainsString('Secret detail', $html);
        $this->assertStringContainsString('An unexpected error occurred', $html);
    }

    public function testIsJsonRequestDetectsJsonAccept(): void
    {
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);
        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'isJsonRequest');

        $_SERVER['HTTP_ACCEPT'] = 'application/json';
        $_SERVER['CONTENT_TYPE'] = '';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = '';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertTrue($method->invoke($handler));

        $_SERVER['HTTP_ACCEPT'] = 'text/html';
    }

    public function testIsJsonRequestDetectsApiPrefix(): void
    {
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);
        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'isJsonRequest');

        $_SERVER['HTTP_ACCEPT'] = 'text/html';
        $_SERVER['CONTENT_TYPE'] = '';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = '';
        $_SERVER['REQUEST_URI'] = '/api/v1/users';

        $this->assertTrue($method->invoke($handler));
    }

    public function testIsJsonRequestFalseForHtml(): void
    {
        $app = Application::create(basePath: sys_get_temp_dir());
        $container = $this->createMock(Container::class);
        $handler = new ExceptionHandler($container, $app);
        $method = new \ReflectionMethod($handler, 'isJsonRequest');

        $_SERVER['HTTP_ACCEPT'] = 'text/html';
        $_SERVER['CONTENT_TYPE'] = 'text/html';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = '';
        $_SERVER['REQUEST_URI'] = '/home';

        $this->assertFalse($method->invoke($handler));
    }

    protected function tearDown(): void
    {
        $_ENV['APP_DEBUG'] = 'true';
        $_ENV['APP_ENV'] = 'testing';
    }
}
