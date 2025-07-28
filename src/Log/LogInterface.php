<?php

declare(strict_types=1);

namespace MonkeysLegion\Log;

interface LogInterface
{
    public function log(string $message): void;
}
