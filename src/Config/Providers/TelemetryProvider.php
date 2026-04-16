<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Telemetry\Factory\TelemetryFactory;
use MonkeysLegion\Telemetry\Metrics\InMemoryMetrics;
use MonkeysLegion\Telemetry\Metrics\MetricsInterface;
use MonkeysLegion\Telemetry\Middleware\RequestMetricsMiddleware;
use MonkeysLegion\Telemetry\Middleware\RequestTracingMiddleware;
use MonkeysLegion\Telemetry\Telemetry;
use MonkeysLegion\Telemetry\Tracing\Tracer;
use MonkeysLegion\Telemetry\Tracing\TracerInterface;

/**
 * Telemetry: tracing, metrics, and request-level middleware.
 *
 * Uses the Telemetry package's actual Tracer and MetricsInterface.
 */
final class TelemetryProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            TracerInterface::class => static function ($c): TracerInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new Tracer(
                    serviceName: $mlc->getString('telemetry.service_name', 'monkeyslegion') ?? 'monkeyslegion',
                    sampleRate: $mlc->getFloat('telemetry.sampling_rate', 1.0) ?? 1.0,
                );
            },

            MetricsInterface::class => fn(): MetricsInterface => new InMemoryMetrics(),

            RequestMetricsMiddleware::class => fn($c): RequestMetricsMiddleware => new RequestMetricsMiddleware(
                metrics: $c->get(MetricsInterface::class),
            ),

            RequestTracingMiddleware::class => fn($c): RequestTracingMiddleware => new RequestTracingMiddleware(
                $c->get(TracerInterface::class),
            ),
        ];
    }
}
