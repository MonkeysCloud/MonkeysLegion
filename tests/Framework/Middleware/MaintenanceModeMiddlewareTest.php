<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Middleware;

use MonkeysLegion\Framework\Middleware\MaintenanceModeMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @covers \MonkeysLegion\Framework\Middleware\MaintenanceModeMiddleware
 */
final class MaintenanceModeMiddlewareTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/ml_maint_test_' . bin2hex(random_bytes(4));
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $maintenanceFile = $this->tempDir . '/maintenance.php';

        if (is_file($maintenanceFile)) {
            unlink($maintenanceFile);
        }

        if (is_dir($this->tempDir)) {
            rmdir($this->tempDir);
        }
    }

    public function testPassesThroughWhenNotInMaintenance(): void
    {
        $factory = $this->createMock(ResponseFactoryInterface::class);
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($expectedResponse);

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
        );

        $result = $middleware->process($request, $handler);

        $this->assertSame($expectedResponse, $result);
    }

    public function testReturns503WhenMaintenanceFileExists(): void
    {
        file_put_contents(
            $this->tempDir . '/maintenance.php',
            '<?php return ["retry" => 600, "message" => "Upgrading..."];',
        );

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())->method('write')->with($this->stringContains('Upgrading...'));

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $response->method('getBody')->willReturn($stream);

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects($this->once())
            ->method('createResponse')
            ->with(503)
            ->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getAttribute')->willReturn(null);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '10.0.0.1']);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
        );

        $result = $middleware->process($request, $handler);

        $this->assertSame($response, $result);
    }

    public function testAllowsBypassViaSecretToken(): void
    {
        file_put_contents(
            $this->tempDir . '/maintenance.php',
            '<?php return [];',
        );

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $factory = $this->createMock(ResponseFactoryInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['secret' => 'bypass123']);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($expectedResponse);

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
            secret: 'bypass123',
        );

        $result = $middleware->process($request, $handler);

        $this->assertSame($expectedResponse, $result);
    }

    public function testAllowsBypassViaAllowedIp(): void
    {
        file_put_contents(
            $this->tempDir . '/maintenance.php',
            '<?php return [];',
        );

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $factory = $this->createMock(ResponseFactoryInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getAttribute')->with('client_ip')->willReturn('192.168.1.50');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($expectedResponse);

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
            allowedIps: ['192.168.1.50', '10.0.0.1'],
        );

        $result = $middleware->process($request, $handler);

        $this->assertSame($expectedResponse, $result);
    }

    public function testBlocksNonAllowedIpDuringMaintenance(): void
    {
        file_put_contents(
            $this->tempDir . '/maintenance.php',
            '<?php return ["message" => "Down for maintenance."];',
        );

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())->method('write');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $response->method('getBody')->willReturn($stream);

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->method('createResponse')->with(503)->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getAttribute')->willReturn(null);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '99.99.99.99']);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
            allowedIps: ['10.0.0.1'],
        );

        $middleware->process($request, $handler);
    }

    public function testDefaultsWhenMaintenanceFileReturnsEmptyArray(): void
    {
        file_put_contents($this->tempDir . '/maintenance.php', '<?php return [];');

        $stream = $this->createMock(StreamInterface::class);
        // Default message should be used
        $stream->expects($this->once())->method('write')->with($this->stringContains('Please try again later'));

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $response->method('getBody')->willReturn($stream);

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->method('createResponse')->with(503)->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getAttribute')->willReturn(null);
        $request->method('getServerParams')->willReturn([]);

        $handler = $this->createMock(RequestHandlerInterface::class);

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
        );

        $middleware->process($request, $handler);
    }

    public function testWrongSecretDoesNotBypass(): void
    {
        file_put_contents($this->tempDir . '/maintenance.php', '<?php return [];');

        $stream = $this->createMock(StreamInterface::class);
        $stream->method('write');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')->willReturnSelf();
        $response->method('getBody')->willReturn($stream);

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->method('createResponse')->with(503)->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['secret' => 'wrong']);
        $request->method('getAttribute')->willReturn(null);
        $request->method('getServerParams')->willReturn([]);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $middleware = new MaintenanceModeMiddleware(
            responseFactory: $factory,
            storagePath: $this->tempDir,
            secret: 'correct_secret',
        );

        $middleware->process($request, $handler);
    }
}
