<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Session\Contracts\SessionDriverInterface;
use MonkeysLegion\Session\Factory\DriverFactory;
use MonkeysLegion\Session\Middleware\SessionMiddleware;
use MonkeysLegion\Session\Middleware\VerifyCsrfToken;
use MonkeysLegion\Session\SessionManager;

final class SessionProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            'session_config' => static function () {
                $path = base_path('config/session.php');

                $configArray = file_exists($path)
                    ? require $path
                    : [
                        'default' => 'file',
                        'drivers' => [
                            'file' => [
                                'path' => base_path('var/sessions'),
                                'lifetime' => 7200,
                            ],
                        ],
                    ];

                return (object) [
                    'config' => $configArray
                ];
            },

            SessionDriverInterface::class => static function ($c) {
                $config = $c->get('session_config')->config ?? [];

                if (
                    !isset($config['default']) ||
                    !is_string($config['default']) ||
                    $config['default'] === '' ||
                    !isset($config['drivers'][$config['default']]) ||
                    !is_array($config['drivers'][$config['default']])
                ) {
                    throw new \InvalidArgumentException(
                        'Invalid session configuration: default driver not defined or missing driver config'
                    );
                }

                $driverName   = $config['default'];
                $driverConfig = $config['drivers'][$driverName];

                $factory = new DriverFactory();

                switch ($driverName) {
                    case 'file':
                        $driverConfig['path'] = $driverConfig['path'] ?? base_path('var/sessions');
                        break;
                    case 'database':
                        $conn = $c->get(ConnectionInterface::class);
                        $driverConfig['connection'] = $conn;
                        break;
                    case 'redis':
                        $driverConfig['redis'] = $c->get(\Redis::class);
                        break;
                    default:
                        throw new \InvalidArgumentException(
                            sprintf(
                                'Unsupported session driver "%s". Supported drivers are: file, database, redis.',
                                $driverName
                            )
                        );
                }

                return $factory->make($driverName, $driverConfig);
            },

            SessionManager::class => static function ($c) {
                $config = $c->get('session_config')->config ?? [];

                $serializer = new \MonkeysLegion\Session\NativeSerializer();
                if (isset($config['encrypt'])) {
                    $keys = $config['keys'] ?? [];
                    $serializer = match ($config['encrypt']) {
                        true => new \MonkeysLegion\Session\EncryptedSerializer($serializer, $keys),
                        default => $serializer,
                    };
                }

                return new SessionManager(
                    $c->get(SessionDriverInterface::class),
                    $serializer
                );
            },

            SessionMiddleware::class => static function ($c) {
                $config = $c->get('session_config')->config ?? [];

                return new SessionMiddleware(
                    $c->get(SessionManager::class),
                    $config
                );
            },

            VerifyCsrfToken::class => static function ($c) {
                return new VerifyCsrfToken($c->get(SessionManager::class));
            },
        ];
    }
}
