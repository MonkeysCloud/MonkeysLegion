<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Http\Emitter\SapiEmitter;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Unified exception handler for MonkeysLegion v2.
 *
 * - Content-negotiates: JSON for API requests, HTML for browser
 * - Structured error logging
 * - Never leaks stack traces in production
 */
final class ExceptionHandler
{
    public function __construct(
        private readonly Container $container,
        private readonly Application $app,
    ) {}

    /**
     * Handle an uncaught exception and emit an error response.
     */
    public function handle(\Throwable $e): void
    {
        $this->log($e);

        $statusCode = $this->resolveStatusCode($e);

        if (!headers_sent()) {
            $this->emitResponse($e, $statusCode);
        }
    }

    /**
     * Log the exception with full context.
     */
    private function log(\Throwable $e): void
    {
        if (!$this->container->has(LoggerInterface::class)) {
            error_log(sprintf(
                '[MonkeysLegion] %s: %s in %s:%d',
                $e::class,
                $e->getMessage(),
                $e->getFile(),
                $e->getLine(),
            ));
            return;
        }

        /** @var LoggerInterface $logger */
        $logger = $this->container->get(LoggerInterface::class);

        $logger->error($e->getMessage(), [
            'exception' => $e::class,
            'file'      => $e->getFile(),
            'line'      => $e->getLine(),
            'trace'     => $this->app->debug ? $e->getTraceAsString() : '[redacted]',
        ]);
    }

    /**
     * Resolve the HTTP status code from the exception.
     */
    private function resolveStatusCode(\Throwable $e): int
    {
        if (method_exists($e, 'getStatusCode')) {
            return (int) $e->getStatusCode();
        }

        $code = $e->getCode();

        if (is_int($code) && $code >= 400 && $code < 600) {
            return $code;
        }

        return 500;
    }

    /**
     * Build and emit the error response.
     */
    private function emitResponse(\Throwable $e, int $statusCode): void
    {
        $isJsonRequest = $this->isJsonRequest();

        if ($this->container->has(ResponseFactoryInterface::class)) {
            /** @var ResponseFactoryInterface $factory */
            $factory = $this->container->get(ResponseFactoryInterface::class);
            $response = $factory->createResponse($statusCode);

            $body = $isJsonRequest
                ? $this->buildJsonBody($e, $statusCode)
                : $this->buildHtmlBody($e, $statusCode);

            $contentType = $isJsonRequest ? 'application/json' : 'text/html';

            $response = $response
                ->withHeader('Content-Type', $contentType . '; charset=utf-8')
                ->withHeader('X-Content-Type-Options', 'nosniff')
                ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

            $response->getBody()->write($body);

            if ($this->container->has(SapiEmitter::class)) {
                /** @var SapiEmitter $emitter */
                $emitter = $this->container->get(SapiEmitter::class);
                $emitter->emit($response);
                return;
            }
        }

        // Fallback: raw output
        http_response_code($statusCode);
        header('Content-Type: ' . ($isJsonRequest ? 'application/json' : 'text/html') . '; charset=utf-8');
        header('X-Content-Type-Options: nosniff');

        echo $isJsonRequest
            ? $this->buildJsonBody($e, $statusCode)
            : $this->buildHtmlBody($e, $statusCode);
    }

    /**
     * Build a JSON error body.
     */
    private function buildJsonBody(\Throwable $e, int $statusCode): string
    {
        $payload = [
            'error' => [
                'status'  => $statusCode,
                'message' => $this->app->debug ? $e->getMessage() : 'Internal Server Error',
            ],
        ];

        if ($this->app->debug) {
            $payload['error']['exception'] = $e::class;
            $payload['error']['file']      = $e->getFile();
            $payload['error']['line']      = $e->getLine();
            $payload['error']['trace']     = explode("\n", $e->getTraceAsString());
        }

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{"error":"Unknown"}';
    }

    /**
     * Build a minimal HTML error body.
     */
    private function buildHtmlBody(\Throwable $e, int $statusCode): string
    {
        $title   = $this->app->debug ? htmlspecialchars($e::class, ENT_QUOTES, 'UTF-8') : 'Error';
        $message = $this->app->debug
            ? htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8')
            : 'An unexpected error occurred.';

        $debug = '';

        if ($this->app->debug) {
            $trace = htmlspecialchars($e->getTraceAsString(), ENT_QUOTES, 'UTF-8');
            $file  = htmlspecialchars($e->getFile(), ENT_QUOTES, 'UTF-8');
            $debug = <<<HTML
                <p><strong>File:</strong> {$file}:{$e->getLine()}</p>
                <pre style="background:#1a1a2e;color:#e94560;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;">{$trace}</pre>
            HTML;
        }

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{$statusCode} — {$title}</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f23; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 2rem; }
                .card { max-width: 720px; width: 100%; background: #16213e; border-radius: 12px; padding: 2.5rem; border: 1px solid #1a1a3e; }
                h1 { font-size: 3rem; color: #e94560; margin-bottom: 0.5rem; }
                h2 { font-size: 1.2rem; color: #a0a0b0; margin-bottom: 1.5rem; font-weight: 400; }
                p { margin-bottom: 1rem; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>{$statusCode}</h1>
                <h2>{$title}</h2>
                <p>{$message}</p>
                {$debug}
            </div>
        </body>
        </html>
        HTML;
    }

    /**
     * Detect if the current request expects JSON.
     */
    private function isJsonRequest(): bool
    {
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $xRequestedWith = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';

        return str_contains($accept, 'application/json')
            || str_contains($contentType, 'application/json')
            || strtolower($xRequestedWith) === 'xmlhttprequest'
            || str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/api/');
    }
}
