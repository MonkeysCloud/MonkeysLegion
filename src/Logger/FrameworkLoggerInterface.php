<?php

namespace MonkeysLegion\Logger;

use Psr\Log\LoggerInterface;

interface FrameworkLoggerInterface extends LoggerInterface
{
    public function smartLog(string $message, array $context = []): void;

    public function setLogger(LoggerInterface $logger): self;

    public function getLogger(): LoggerInterface;

    public function setEnvironment(string $env): self;

    public function getEnvironment(): string;
}
