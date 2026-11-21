<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec\Model;

readonly class ZoneResult
{
    /** @param array<CheckResult> $checks */
    public function __construct(
        public string $zone,
        public ?string $nameserver,
        public array $checks,
    ) {}

    public function hasErrors(): bool
    {
        return array_any($this->checks, fn(CheckResult $c) => $c->status === Status::Error);
    }
}
