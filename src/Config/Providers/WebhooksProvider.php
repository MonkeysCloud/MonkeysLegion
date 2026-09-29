<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Webhooks\Drivers\DatabaseDriver;
use MonkeysLegion\Webhooks\Drivers\InMemoryDriver;
use MonkeysLegion\Webhooks\Drivers\WebhookDriverInterface;
use MonkeysLegion\Webhooks\WebhookManager;
use MonkeysLegion\Webhooks\WebhookSigner;
use PDO;

/**
 * Webhooks service provider.
 *
 * Registers the WebhookManager, driver, and signer based on config/webhooks.mlc:
 *   webhooks {
 *       driver    = ${WEBHOOKS_DRIVER:memory}
 *       secret    = ${WEBHOOK_SECRET:""}
 *       algorithm = "sha256"
 *       timeout   = 30
 *   }
 */
final class WebhooksProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            WebhookSigner::class => static function ($c): WebhookSigner {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new WebhookSigner(
                    $mlc->getString('webhooks.secret', '') ?? '',
                    $mlc->getString('webhooks.algorithm', 'sha256') ?? 'sha256',
                );
            },

            WebhookDriverInterface::class => static function ($c): WebhookDriverInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $driver = $mlc->getString('webhooks.driver', 'memory') ?? 'memory';

                return match ($driver) {
                    'database' => new DatabaseDriver(
                        $c->get(PDO::class),
                    ),
                    default => new InMemoryDriver(),
                };
            },

            WebhookManager::class => static function ($c): WebhookManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new WebhookManager(
                    $c->get(WebhookDriverInterface::class),
                    $c->get(WebhookSigner::class),
                    $mlc->getInt('webhooks.timeout', 30) ?? 30,
                );
            },
        ];
    }
}
