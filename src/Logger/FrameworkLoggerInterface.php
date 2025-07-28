<?php

namespace MonkeysLegion\Logger;

use Psr\Log\LoggerInterface;

interface FrameworkLoggerInterface extends LoggerInterface
{
    public function emergency($message, array $context = []): void;
    public function alert($message, array $context = []): void;
    public function critical($message, array $context = []): void;
    public function error($message, array $context = []): void;
    public function warning($message, array $context = []): void;
    public function notice($message, array $context = []): void;
    public function info($message, array $context = []): void;
    public function debug($message, array $context = []): void;
    public function log($level, $message, array $context = []): void;

    public function smartLog(string $message, array $context = []): void;

    public function setLogger(LoggerInterface $logger): self;
    public function getLogger(): LoggerInterface;
    public function setEnvironment(string $env): self;
    public function getEnvironment(): string;
}
