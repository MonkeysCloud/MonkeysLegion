<?php

namespace MonkeysLegion\Config;

use MonkeysLegion\Config\ConfigLoader;
use MonkeysLegion\Core\Contracts\FrameworkLoggerInterface;
use MonkeysLegion\Core\Logger\MonkeyLogger;
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
        ];
    }
}
