<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Telemetry\Factory\TelemetryFactory;
use MonkeysLegion\Telemetry\Logging\TelemetryLogger;
use MonkeysLegion\Telemetry\Logging\TracingContextProvider;
use MonkeysLegion\Telemetry\Metrics\MetricsInterface;
use MonkeysLegion\Telemetry\Tracing\TracerInterface;
use Psr\Log\LoggerInterface;

final class TelemetryProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            MetricsInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return TelemetryFactory::createMetrics($mlc->get('telemetry.metrics', []));
            },

            TracerInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return TelemetryFactory::createTracer($mlc->get('telemetry.tracing', []));
            },

            TelemetryLogger::class => static function ($c) {
                return new TelemetryLogger(
                    logger: $c->get(LoggerInterface::class),
                    contextProvider: new TracingContextProvider($c->get(TracerInterface::class))
                );
            },
        ];
    }
}
