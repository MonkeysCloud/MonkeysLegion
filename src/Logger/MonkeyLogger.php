<?php

namespace MonkeysLegion\Logger;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class MonkeyLogger implements FrameworkLoggerInterface
{
    private LoggerInterface $logger;
    private string $env;

    public function __construct(?LoggerInterface $logger = null, ?string $env = null)
    {
        $this->logger = $logger ?? new NullLogger();
        $this->env = strtolower($env ?? $_ENV['APP_ENV'] ?? 'dev');
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
        switch ($this->env) {
            case 'production':
            case 'prod':
                $this->logger->warning($message, $context);
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
        $this->logger->emergency($message, $context);
    }

    public function alert($message, array $context = []): void
    {
        $this->logger->alert($message, $context);
    }

    public function critical($message, array $context = []): void
    {
        $this->logger->critical($message, $context);
    }

    public function error($message, array $context = []): void
    {
        $this->logger->error($message, $context);
    }

    public function warning($message, array $context = []): void
    {
        $this->logger->warning($message, $context);
    }

    public function notice($message, array $context = []): void
    {
        $this->logger->notice($message, $context);
    }

    public function info($message, array $context = []): void
    {
        $this->logger->info($message, $context);
    }

    public function debug($message, array $context = []): void
    {
        $this->logger->debug($message, $context);
    }

    public function log($level, $message, array $context = []): void
    {
        $this->logger->log($level, $message, $context);
    }
}
