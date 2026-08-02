<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Logger\Formatter\FormatterInterface;
use MonkeysLegion\Logger\Formatter\JsonFormatter;
use MonkeysLegion\Logger\Formatter\LineFormatter;
use MonkeysLegion\Logger\Handler\ConsoleHandler;
use MonkeysLegion\Logger\Handler\ErrorLogHandler;
use MonkeysLegion\Logger\Handler\HandlerInterface;
use MonkeysLegion\Logger\Handler\NullHandler;
use MonkeysLegion\Logger\Handler\RotatingFileHandler;
use MonkeysLegion\Logger\Handler\StreamHandler;
use MonkeysLegion\Logger\Handler\SyslogHandler;
use MonkeysLegion\Logger\LogLevel;
use MonkeysLegion\Logger\LogManager;
use MonkeysLegion\Logger\Logger;
use MonkeysLegion\Logger\LoggerInterface as MlLoggerInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Log\LoggerInterface;

/**
 * PSR-3 logger provider.
 *
 * Builds the Logger package's {@see Logger} from the `logging.*` section of
 * `.mlc` configuration. Supports a configurable `logging.handlers` array so
 * that consumers can wire multiple sinks (e.g. a rotating file **plus**
 * `php://stderr` for container log collectors) through config alone — no
 * app-level workaround required.
 *
 * Each entry in `logging.handlers` may be a string shorthand or a map with a
 * `type` key and per-handler options:
 *
 *   handlers = [
 *     "rotating_file",                       # shorthand
 *     { type = "stream", path = "php://stderr" },
 *     { type = "error_log", message_type = 0 },
 *   ]
 *
 * Recognised shorthand / type values:
 *   rotating_file | stream | stderr | stdout | error_log | console | syslog | null
 *
 * When `logging.handlers` is absent the provider falls back to a single
 * `rotating_file` handler — preserving backward compatibility.
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

                $channel  = $mlc->getString('logging.channel', 'app') ?? 'app';
                $level    = $mlc->getString('logging.level', 'debug') ?? 'debug';
                $logLevel = LogLevel::fromPsr3($level);
                $json     = $mlc->getBool('logging.json', false) ?? false;
                $handlers = self::buildHandlers($mlc, $logLevel, self::makeFormatter($json));

                return new Logger(
                    handlers: $handlers,
                    channelName: $channel,
                );
            },

            MlLoggerInterface::class => fn($c): Logger => $c->get(Logger::class),

            LoggerInterface::class => fn($c): Logger => $c->get(Logger::class),
        ];
    }

    // ── Handler construction ───────────────────────────────────

    /**
     * Resolve the `logging.handlers` config into a list of handler instances.
     *
     * @param MlcConfig        $mlc
     * @param LogLevel         $defaultLevel  Shared minimum level from `logging.level`.
     * @param FormatterInterface $formatter   Shared formatter (line or json).
     * @return list<HandlerInterface>
     */
    private static function buildHandlers(MlcConfig $mlc, LogLevel $defaultLevel, FormatterInterface $formatter): array
    {
        /** @var list<mixed> $config */
        $config = $mlc->getArray('logging.handlers', null) ?? [];

        // Backward compatibility: no handlers key → single rotating file.
        if ($config === []) {
            $config = ['rotating_file'];
        }

        $handlers = [];
        foreach ($config as $entry) {
            $handler = self::buildHandler($entry, $mlc, $defaultLevel, $formatter);
            if ($handler !== null) {
                $handlers[] = $handler;
            }
        }

        // Guarantee at least one handler so logs are never silently dropped.
        if ($handlers === []) {
            $handlers[] = self::makeRotatingFileHandler($mlc, $defaultLevel, $formatter);
        }

        return $handlers;
    }

    /**
     * Build a single handler from one `logging.handlers` entry.
     *
     * An entry is either a string shorthand or a map with a `type` key.
     *
     * @param mixed $entry
     * @param MlcConfig $mlc
     * @param LogLevel $defaultLevel
     * @param FormatterInterface $formatter
     * @return HandlerInterface|null  Null when the entry is unrecognised (skipped).
     */
    private static function buildHandler(
        mixed $entry,
        MlcConfig $mlc,
        LogLevel $defaultLevel,
        FormatterInterface $formatter,
    ): ?HandlerInterface {
        // Normalise to a [type, options] pair.
        if (is_string($entry)) {
            $type    = $entry;
            $options = [];
        } elseif (is_array($entry) && isset($entry['type']) && is_string($entry['type'])) {
            $type    = $entry['type'];
            $options = $entry;
        } else {
            return null; // unrecognised entry — skip
        }

        // Per-handler level override, falling back to the shared level.
        $level = self::resolveLevel($options['level'] ?? null, $defaultLevel);

        return match ($type) {
            'rotating_file', 'rotating', 'file' => self::makeRotatingFileHandler($mlc, $level, $formatter, $options),
            'stream'                          => self::makeStreamHandler($level, $formatter, $options),
            'stderr'                          => new StreamHandler('php://stderr', $level, $formatter),
            'stdout'                          => new StreamHandler('php://stdout', $level, $formatter),
            'error_log', 'errorlog'           => self::makeErrorLogHandler($level, $formatter, $options),
            'console'                         => self::makeConsoleHandler($level, $formatter, $options),
            'syslog'                          => self::makeSyslogHandler($level, $formatter, $options),
            'null'                            => new NullHandler(),
            default                           => null, // unknown type — skip
        };
    }

    // ── Per-type factories ─────────────────────────────────────

    /**
     * @param array<string, mixed> $options
     */
    private static function makeRotatingFileHandler(
        MlcConfig $mlc,
        LogLevel $level,
        FormatterInterface $formatter,
        array $options = [],
    ): RotatingFileHandler {
        $basePath  = $mlc->getString('logging.path', 'var/logs') ?? 'var/logs';
        $channel   = $mlc->getString('logging.channel', 'app') ?? 'app';
        $maxFiles  = $mlc->getInt('logging.max_files', 14) ?? 14;

        $path      = is_string($options['path'] ?? null)
            ? (string) $options['path']
            : base_path($basePath) . '/' . $channel . '.log';
        $max       = is_int($options['max_files'] ?? null) || is_numeric($options['max_files'] ?? null)
            ? (int) $options['max_files']
            : $maxFiles;

        // Ensure the directory exists.
        $dir = dirname($path);
        if (!str_contains($path, '://') && !is_dir($dir)) {
            mkdir($dir, 0o755, true);
        }

        return new RotatingFileHandler($path, $level, $formatter, maxFiles: $max);
    }

    /**
     * @param array<string, mixed> $options
     */
    private static function makeStreamHandler(
        LogLevel $level,
        FormatterInterface $formatter,
        array $options,
    ): StreamHandler {
        // Resolve a relative file path against base_path; stream URLs pass through.
        $rawPath = is_string($options['path'] ?? null) ? (string) $options['path'] : 'php://stdout';

        if (!str_contains($rawPath, '://')) {
            $rawPath = base_path($rawPath);
            $dir = dirname($rawPath);
            if (!is_dir($dir)) {
                mkdir($dir, 0o755, true);
            }
        }

        return new StreamHandler($rawPath, $level, $formatter);
    }

    /**
     * @param array<string, mixed> $options
     */
    private static function makeErrorLogHandler(
        LogLevel $level,
        FormatterInterface $formatter,
        array $options,
    ): ErrorLogHandler {
        $messageType = is_int($options['message_type'] ?? null) || is_numeric($options['message_type'] ?? null)
            ? (int) $options['message_type']
            : ErrorLogHandler::TYPE_SYSTEM;
        $destination = is_string($options['destination'] ?? null) ? (string) $options['destination'] : null;

        return new ErrorLogHandler($messageType, $destination, $level, $formatter);
    }

    /**
     * @param array<string, mixed> $options
     */
    private static function makeConsoleHandler(
        LogLevel $level,
        FormatterInterface $formatter,
        array $options,
    ): ConsoleHandler {
        $stream   = is_string($options['stream'] ?? null) ? (string) $options['stream'] : 'php://stderr';
        $colorize = is_bool($options['colorize'] ?? null) ? (bool) $options['colorize'] : true;

        return new ConsoleHandler($level, $formatter, $colorize, $stream);
    }

    /**
     * @param array<string, mixed> $options
     */
    private static function makeSyslogHandler(
        LogLevel $level,
        FormatterInterface $formatter,
        array $options,
    ): SyslogHandler {
        $ident    = is_string($options['ident'] ?? null) ? (string) $options['ident'] : 'monkeyslegion';
        $facility = is_int($options['facility'] ?? null) || is_numeric($options['facility'] ?? null)
            ? (int) $options['facility']
            : LOG_USER;

        return new SyslogHandler($ident, $facility, $level, $formatter);
    }

    // ── Helpers ────────────────────────────────────────────────

    private static function makeFormatter(bool $json): FormatterInterface
    {
        return $json ? new JsonFormatter() : new LineFormatter();
    }

    private static function resolveLevel(mixed $value, LogLevel $fallback): LogLevel
    {
        if (!is_string($value) || $value === '') {
            return $fallback;
        }
        try {
            return LogLevel::fromPsr3($value);
        } catch (\InvalidArgumentException) {
            return $fallback;
        }
    }
}
