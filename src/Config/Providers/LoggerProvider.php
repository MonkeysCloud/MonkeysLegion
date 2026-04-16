<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Logger\Handler\RotatingFileHandler;
use MonkeysLegion\Logger\LogLevel;
use MonkeysLegion\Logger\LogManager;
use MonkeysLegion\Logger\Logger;
use MonkeysLegion\Logger\LoggerInterface as MlLoggerInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Log\LoggerInterface;

/**
 * PSR-3 logger provider.
 *
 * Uses the Logger package's Logger class with handlers, not MonkeysLogger.
 */
final class LoggerProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            LogManager::class => static function ($c): LogManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new LogManager(
                    config: $mlc->getArray('logging', []) ?? [],
                );
            },

            Logger::class => static function ($c): Logger {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $logPath = base_path($mlc->getString('logging.path', 'var/logs') ?? 'var/logs');
                $channel = $mlc->getString('logging.channel', 'app') ?? 'app';
                $maxFiles = $mlc->getInt('logging.max_files', 14) ?? 14;
                $level = $mlc->getString('logging.level', 'debug') ?? 'debug';

                // Create log directory if needed
                if (!is_dir($logPath)) {
                    mkdir($logPath, 0755, true);
                }

                $handler = new RotatingFileHandler(
                    $logPath . '/' . $channel . '.log',
                    LogLevel::fromPsr3($level),
                    maxFiles: $maxFiles,
                );

                return new Logger(
                    handlers: [$handler],
                    channelName: $channel,
                );
            },

            MlLoggerInterface::class => fn($c): Logger => $c->get(Logger::class),

            LoggerInterface::class => fn($c): Logger => $c->get(Logger::class),
        ];
    }
}
