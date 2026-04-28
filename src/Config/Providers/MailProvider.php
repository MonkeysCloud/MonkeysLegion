<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Logger\Logger;
use MonkeysLegion\Mail\Mailer;
use MonkeysLegion\Mail\MailerFactory;
use MonkeysLegion\Mail\RateLimiter\RateLimiter;
use MonkeysLegion\Mail\TransportInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Queue\Contracts\QueueDispatcherInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mail service provider for monkeyslegion-mail v2.
 *
 * Registers the transport layer, rate limiter, factory, and Mailer
 * into the DI container using MLC-based configuration.
 *
 * Required MLC block (config/mail.mlc):
 *   mail {
 *       driver = ${MAIL_DRIVER:-null}
 *       drivers { smtp { … } sendmail { … } null {} … }
 *       rate_limiter { key = ml_mail  limit = 100  seconds = 60 }
 *   }
 */
final class MailProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Transport — resolved via MailerFactory::make() */
            TransportInterface::class => static function ($c): TransportInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->getArray('mail', []) ?? [];
                $logger = $c->has(Logger::class)
                    ? $c->get(Logger::class) : null;

                return MailerFactory::make($config, $logger);
            },

            /* Rate limiter (file-based, per-app key) */
            RateLimiter::class => static function ($c): RateLimiter {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new RateLimiter(
                    key: $mlc->getString('mail.rate_limiter.key', 'ml_mail') ?? 'ml_mail',
                    limit: $mlc->getInt('mail.rate_limiter.limit', 100) ?? 100,
                    seconds: $mlc->getInt('mail.rate_limiter.seconds', 60) ?? 60,
                    storagePath: $mlc->getString('mail.rate_limiter.storage_path', '/tmp') ?? '/tmp',
                );
            },

            /* Factory — enables runtime driver switching */
            MailerFactory::class => static function ($c): MailerFactory {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->getArray('mail', []) ?? [];

                return new MailerFactory(
                    logger: $c->get(Logger::class),
                    config: $config,
                    container: Container::instance(),
                );
            },

            /* Mailer — the main entry point for sending / queuing mail */
            Mailer::class => static function ($c): Mailer {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->getArray('mail', []) ?? [];

                return new Mailer(
                    driver: $c->get(TransportInterface::class),
                    rateLimiter: $c->get(RateLimiter::class),
                    dispatcher: $c->get(QueueDispatcherInterface::class),
                    logger: $c->has(Logger::class)
                        ? $c->get(Logger::class) : null,
                    rawConfig: $config,
                    eventDispatcher: $c->has(EventDispatcherInterface::class)
                        ? $c->get(EventDispatcherInterface::class) : null,
                );
            },
        ];
    }
}
