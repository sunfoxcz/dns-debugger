<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec\Model;

readonly class ChainResult
{
    /** @param array<ZoneResult> $zones */
    public function __construct(
        public string $domain,
        public array $zones,
        public \DateTimeImmutable $timestamp = new \DateTimeImmutable(),
    ) {}

    public function hasErrors(): bool
    {
        return array_any($this->zones, fn(ZoneResult $z) => $z->hasErrors());
    }
}
