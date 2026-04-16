<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Returns a 503 Service Unavailable response when maintenance mode is active.
 *
 * Activate by creating a `var/maintenance.php` file (or via `ml down`).
 * Optional: allow bypass via secret token or specific IPs.
 */
final class MaintenanceModeMiddleware implements MiddlewareInterface
{
    /**
     * @param string        $storagePath  Path to the maintenance flag file
     * @param array<string> $allowedIps   IPs that bypass maintenance mode
     * @param string        $secret       Secret token for bypass (?secret=...)
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $storagePath,
        private readonly array $allowedIps = [],
        private readonly string $secret = '',
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $maintenanceFile = $this->storagePath . '/maintenance.php';

        if (!is_file($maintenanceFile)) {
            return $handler->handle($request);
        }

        // Allow bypass via secret token
        $queryParams = $request->getQueryParams();

        if ($this->secret !== '' && ($queryParams['secret'] ?? '') === $this->secret) {
            return $handler->handle($request);
        }

        // Allow bypass via IP whitelist
        $clientIp = $request->getAttribute('client_ip')
            ?? $request->getServerParams()['REMOTE_ADDR']
            ?? '';

        if ($this->allowedIps !== [] && in_array($clientIp, $this->allowedIps, true)) {
            return $handler->handle($request);
        }

        // Load custom maintenance data
        $raw = require $maintenanceFile;
        $data = is_array($raw) ? $raw : [];
        $retryAfter = max(0, (int) ($data['retry'] ?? 3600));
        $message = is_string($data['message'] ?? null)
            ? $data['message']
            : 'We are currently performing maintenance. Please try again later.';

        $body = $this->buildMaintenancePage($message);

        $response = $this->responseFactory->createResponse(503)
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Retry-After', (string) $retryAfter)
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

        $response->getBody()->write($body);

        return $response;
    }

    /**
     * Build a styled maintenance page.
     */
    private function buildMaintenancePage(string $message): string
    {
        $escapedMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Maintenance</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 2rem; }
                .card { text-align: center; max-width: 520px; }
                .icon { font-size: 4rem; margin-bottom: 1.5rem; }
                h1 { font-size: 2rem; color: #f0a500; margin-bottom: 1rem; }
                p { font-size: 1.1rem; line-height: 1.7; color: #a0a0b0; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">🔧</div>
                <h1>Under Maintenance</h1>
                <p>{$escapedMessage}</p>
            </div>
        </body>
        </html>
        HTML;
    }
}
