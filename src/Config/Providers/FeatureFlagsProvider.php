<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\FeatureFlags\Drivers\DatabaseDriver;
use MonkeysLegion\FeatureFlags\Drivers\FeatureDriverInterface;
use MonkeysLegion\FeatureFlags\Drivers\InMemoryDriver;
use MonkeysLegion\FeatureFlags\FeatureManager;
use MonkeysLegion\Mlc\Config as MlcConfig;
use PDO;

/**
 * Feature flags service provider.
 *
 * Registers the FeatureManager and driver based on config/feature-flags.mlc:
 *   feature_flags {
 *       driver = ${FEATURE_FLAGS_DRIVER:memory}
 *       table  = "feature_flags"
 *   }
 */
final class FeatureFlagsProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            FeatureDriverInterface::class => static function ($c): FeatureDriverInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $driver = $mlc->getString('feature_flags.driver', 'memory') ?? 'memory';

                return match ($driver) {
                    'database' => new DatabaseDriver(
                        $c->get(PDO::class),
                        $mlc->getString('feature_flags.table', 'feature_flags') ?? 'feature_flags',
                    ),
                    default => new InMemoryDriver(),
                };
            },

            FeatureManager::class => static function ($c): FeatureManager {
                return new FeatureManager(
                    $c->get(FeatureDriverInterface::class),
                );
            },
        ];
    }
}
