<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface;
use MonkeysLegion\Mail\Enums\MailDefaults;
use MonkeysLegion\Mail\Enums\MailDriverName;
use MonkeysLegion\Mail\Mailer;
use MonkeysLegion\Mail\MailerFactory;
use MonkeysLegion\Mail\RateLimiter\RateLimiter;
use MonkeysLegion\Mail\TransportInterface;
use MonkeysLegion\Mlc\Config;
use MonkeysLegion\Queue\Contracts\QueueDispatcherInterface;

final class MailProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            RateLimiter::class => static function (Container $c) {
                /** @var Config $mlc */
                $mlc     = $c->get(Config::class);
                $config = $mlc->get('mail.rate_limiter', []);

                return new RateLimiter(
                    safeString($config['key'] ?? null, MailDefaults::RATE_LIMITER_KEY),
                    (int)safeString($config['limit'] ?? null, (string)MailDefaults::RATE_LIMITER_LIMIT),
                    (int)safeString($config['seconds'] ?? null, (string)MailDefaults::RATE_LIMITER_SECONDS),
                    safeString($config['storage_path'] ?? null, MailDefaults::RATE_LIMITER_STORAGE_PATH)
                );
            },

            TransportInterface::class => static function (Container $c) {
                $logger = $c->get(MonkeysLoggerInterface::class);

                /** @var Config $mlc */
                $mlc     = $c->get(Config::class);
                $config = $mlc->get('mail', [
                    'default' => MailDriverName::NULL->value,
                    'drivers' => [
                        MailDriverName::NULL->value => [],
                    ]
                ]);
                try {
                    return MailerFactory::make($config, $logger);
                } catch (\Exception $e) {
                    $logger->error("Failed to create mail transport", [
                        'exception' => $e,
                        'error_message' => $e->getMessage(),
                        'trace' => $e->getTraceAsString()
                    ]);
                    throw $e;
                }
            },

            Mailer::class  => static function (Container $c) {
                /** @var Config $mlc */
                $mlc     = $c->get(Config::class);
                $config = $mlc->get('mail', [
                    'default' => MailDriverName::NULL->value,
                    'drivers' => [
                        MailDriverName::NULL->value => [],
                    ]
                ]);

                return new Mailer(
                    driver: $c->get(TransportInterface::class),
                    rateLimiter: $c->get(RateLimiter::class),
                    dispatcher: $c->get(QueueDispatcherInterface::class),
                    logger: $c->get(MonkeysLoggerInterface::class),
                    rawConfig: $config
                );
            },
        ];
    }
}
