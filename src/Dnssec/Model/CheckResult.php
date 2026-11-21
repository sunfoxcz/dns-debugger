<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec\Model;

readonly class CheckResult
{
    public function __construct(
        public Status $status,
        public string $message,
    ) {}

    public static function ok(string $message): self
    {
        return new self(Status::Ok, $message);
    }

    public static function warning(string $message): self
    {
        return new self(Status::Warning, $message);
    }

    public static function error(string $message): self
    {
        return new self(Status::Error, $message);
    }

    public static function info(string $message): self
    {
        return new self(Status::Info, $message);
    }
}
