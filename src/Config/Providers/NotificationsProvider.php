<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Notifications\Channels\MailChannel;
use MonkeysLegion\Notifications\Channels\SlackChannel;
use MonkeysLegion\Notifications\Channels\TeamsChannel;
use MonkeysLegion\Notifications\Channels\WebhookChannel;
use MonkeysLegion\Notifications\NotificationDispatcher;
use MonkeysLegion\Mail\Mailer;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Http\Client\HttpClientInterface;

/**
 * Notifications service provider.
 *
 * Registers notification channels and the dispatcher based on config:
 *   notifications {
 *       channels = ["mail", "slack", "teams", "webhook"]
 *       slack { webhook_url = ${SLACK_WEBHOOK_URL:""} }
 *       teams { webhook_url = ${TEAMS_WEBHOOK_URL:""} }
 *   }
 */
final class NotificationsProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            NotificationDispatcher::class => static function ($c): NotificationDispatcher {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $configuredChannels = $mlc->getArray('notifications.channels', ['mail']) ?? ['mail'];

                $channels = [];

                if (in_array('mail', $configuredChannels, true) && $c->has(Mailer::class)) {
                    $channels['mail'] = new MailChannel($c->get(Mailer::class));
                }

                if (in_array('slack', $configuredChannels, true)) {
                    $channels['slack'] = new SlackChannel(
                        $mlc->getString('notifications.slack.webhook_url', '') ?? '',
                        $c->has(HttpClientInterface::class) ? $c->get(HttpClientInterface::class) : null,
                    );
                }

                if (in_array('teams', $configuredChannels, true)) {
                    $channels['teams'] = new TeamsChannel(
                        $mlc->getString('notifications.teams.webhook_url', '') ?? '',
                        $c->has(HttpClientInterface::class) ? $c->get(HttpClientInterface::class) : null,
                    );
                }

                if (in_array('webhook', $configuredChannels, true)) {
                    $channels['webhook'] = new WebhookChannel(
                        $c->has(HttpClientInterface::class) ? $c->get(HttpClientInterface::class) : null,
                    );
                }

                return new NotificationDispatcher($channels);
            },
        ];
    }
}
