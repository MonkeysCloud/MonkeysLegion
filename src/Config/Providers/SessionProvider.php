<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Session\Contracts\SessionDriverInterface;
use MonkeysLegion\Session\Factory\DriverFactory;
use MonkeysLegion\Session\Middleware\SessionMiddleware;
use MonkeysLegion\Session\Middleware\VerifyCsrfToken;
use MonkeysLegion\Session\NativeSerializer;
use MonkeysLegion\Session\SessionManager;

/**
 * Session driver, manager, middleware, and CSRF provider.
 *
 * HTTP-only. Uses DriverFactory::make() with correct config signatures.
 */
final class SessionProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            SessionDriverInterface::class => static function ($c): SessionDriverInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driverName = $mlc->getString('session.driver', 'file') ?? 'file';
                $lifetime = $mlc->getInt('session.lifetime', 7200) ?? 7200;

                $driverConfig = match ($driverName) {
                    'file' => [
                        'path'     => base_path($mlc->getString('session.file.path', 'var/sessions') ?? 'var/sessions'),
                        'lifetime' => $lifetime,
                    ],
                    'database' => [
                        'connection' => $c->get(ConnectionManagerInterface::class),
                        'table'      => $mlc->getString('session.database.table', 'sessions') ?? 'sessions',
                        'lifetime'   => $lifetime,
                    ],
                    'redis' => [
                        'redis'    => $c->get(\Redis::class),
                        'prefix'   => $mlc->getString('session.redis.prefix', 'session:') ?? 'session:',
                        'lifetime' => $lifetime,
                    ],
                    default => throw new \InvalidArgumentException(
                        sprintf('Unsupported session driver "%s". Supported: file, database, redis.', $driverName),
                    ),
                };

                $factory = new DriverFactory();

                return $factory->make($driverName, $driverConfig);
            },

            SessionManager::class => static function ($c): SessionManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new SessionManager(
                    driver: $c->get(SessionDriverInterface::class),
                    dataHandler: new NativeSerializer(),
                    sessionName: $mlc->getString('session.cookie.name', 'ml_session') ?? 'ml_session',
                );
            },

            SessionMiddleware::class => static function ($c): SessionMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new SessionMiddleware(
                    manager: $c->get(SessionManager::class),
                    config: [
                        'cookie_name'     => $mlc->getString('session.cookie.name', 'ml_session') ?? 'ml_session',
                        'cookie_lifetime' => $mlc->getInt('session.lifetime', 7200) ?? 7200,
                        'cookie_path'     => $mlc->getString('session.cookie.path', '/') ?? '/',
                        'cookie_domain'   => $mlc->getString('session.cookie.domain', '') ?? '',
                        'cookie_secure'   => $mlc->getBool('session.cookie.secure', true) ?? true,
                        'cookie_httponly'  => $mlc->getBool('session.cookie.httponly', true) ?? true,
                        'cookie_samesite' => $mlc->getString('session.cookie.same_site', 'Lax') ?? 'Lax',
                    ],
                );
            },

            VerifyCsrfToken::class => fn($c): VerifyCsrfToken => new VerifyCsrfToken(
                $c->get(SessionManager::class),
            ),
        ];
    }
}
