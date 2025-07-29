<?php

namespace MonkeysLegion\Logger;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Psr\Log\NullLogger;

class MonkeyLogger implements FrameworkLoggerInterface
{
    private LoggerInterface $logger;
    private string $env;
    private array $validLevels = [
        LogLevel::EMERGENCY,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::ERROR,
        LogLevel::WARNING,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::DEBUG
    ];

    public function __construct(?LoggerInterface $logger = null, ?string $env = null)
    {
        $this->logger = $logger ?? new NullLogger();
        $this->env = strtolower($env ?? 'dev');
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    public function setEnvironment(string $env): self
    {
        $this->env = strtolower($env);
        return $this;
    }

    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    public function getEnvironment(): string
    {
        return $this->env;
    }

    public function smartLog(string $message, array $context = []): void
    {
        $context = $this->enrichContext($context);
        switch ($this->env) {
            case 'production':
            case 'prod':
                $this->logger->info($message, $context);
                break;
            case 'test':
            case 'testing':
                $this->logger->notice($message, $context);
                break;
            default:
                $this->logger->debug($message, $context);
                break;
        }
    }

    public function emergency($message, array $context = []): void
    {
        $this->logger->emergency($message, $this->enrichContext($context));
    }

    public function alert($message, array $context = []): void
    {
        $this->logger->alert($message, $this->enrichContext($context));
    }

    public function critical($message, array $context = []): void
    {
        $this->logger->critical($message, $this->enrichContext($context));
    }

    public function error($message, array $context = []): void
    {
        $this->logger->error($message, $this->enrichContext($context));
    }

    public function warning($message, array $context = []): void
    {
        $this->logger->warning($message, $this->enrichContext($context));
    }

    public function notice($message, array $context = []): void
    {
        $this->logger->notice($message, $this->enrichContext($context));
    }

    public function info($message, array $context = []): void
    {
        $this->logger->info($message, $this->enrichContext($context));
    }

    public function debug($message, array $context = []): void
    {
        $this->logger->debug($message, $this->enrichContext($context));
    }

    public function log($level, $message, array $context = []): void
    {
        if (!in_array($level, $this->validLevels, true)) {
            throw new \InvalidArgumentException("Invalid log level: $level");
        }
        $this->logger->log($level, $message, $this->enrichContext($context));
    }

    private function enrichContext(array $context = []): array
    {
        // TODO: Add more useful info like request ID, App name/version, etc.
        return array_merge(['env' => $this->env], $context);
    }
}
