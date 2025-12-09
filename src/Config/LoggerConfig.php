<?php

namespace MonkeysLegion\Config;

use MonkeysLegion\Config\ConfigLoader;
use MonkeysLegion\Core\Contracts\FrameworkLoggerInterface;
use MonkeysLegion\Core\Logger\MonkeyLogger;
use MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface;
use MonkeysLegion\Logger\Factory\LoggerFactory;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Psr\Log\NullLogger;
use Psr\Log\LoggerInterface;
use MonkeysLegion\Mlc\{
    Config as MlcConfig,
};

class LoggerConfig
{
    /** @return array<string, callable> */
    public function __invoke(): array
    {
        return [
            ...((new ConfigLoader)()),

            /*
            |--------------------------------------------------------------------------
            | PSR-3 Logger (Monolog)
            |--------------------------------------------------------------------------
            */
            LoggerInterface::class => function ($c) {
                /** @var MlcConfig $mlc */
                $mlc     = $c->get(MlcConfig::class);
                $logging = $mlc->get('logging', []);

                // Master switch
                if (empty($logging['enabled'])) {
                    return new NullLogger();
                }

                $logger = new Logger('app');

                // stdout handler
                if (! empty($logging['stdout']['enabled'])) {
                    $level = strtoupper($logging['stdout']['level'] ?? 'info');
                    $logger->pushHandler(
                        new StreamHandler('php://stdout', Logger::toMonologLevel($level))
                    );
                }

                // file handler
                if (! empty($logging['file']['enabled'])) {
                    $path  = base_path($logging['file']['path'] ?? 'var/log/app.log');
                    $level = strtoupper($logging['file']['level'] ?? 'info');
                    $logger->pushHandler(
                        new StreamHandler($path, Logger::toMonologLevel($level))
                    );
                }

                return $logger;
            },

            /* ----------------------------------------------------------------- */
            /* Framework logger (MonkeysLegion\Logger\MonkeyLogger)                */
            /* ----------------------------------------------------------------- */
            FrameworkLoggerInterface::class => fn() => new MonkeyLogger(),

            /**
             * -----------------------------------------------------------------
             * Monkeys Logger (MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface)
             * -----------------------------------------------------------------
             */
            MonkeysLoggerInterface::class => function () {
                $path = base_path('config/logging.php');
                $config = file_exists($path) ? require $path : [];
                if (!is_array($config)) $config = [];

                if (!is_array($config) || empty($config)) {
                    $config = [
                        'default' => 'stack',
                        'channels' => [
                            'stack' => [
                                'driver' => 'stack',
                                'channels' => ['single'],
                            ],
                            'single' => [
                                'driver' => 'single',
                                'path' => 'var/log/monkeyslegion.log',
                                'level' => 'debug',
                            ],
                        ],
                    ];
                }

                // Recursively normalize any "path" keys
                array_walk_recursive($config, function (&$value, $key) {
                    if ($key === 'path' && is_string($value) && $value !== '') {
                        $value = base_path('var/' . ltrim($value, "/\\"));
                    }
                });
                $factory = new LoggerFactory($config, ($_ENV['APP_ENV'] ?? 'dev'));
                return $factory->make($config['default'] ?? 'stack');
            },
        ];
    }
}
