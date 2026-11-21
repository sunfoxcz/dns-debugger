<?php

declare(strict_types=1);

namespace DnsDebugger\Zone\Model;

readonly class ZoneHierarchy
{
    /** @param array<string> $zones Ordered from root (.) to target zone */
    public function __construct(
        public array $zones,
    ) {}

    public function getParent(string $zone): ?string
    {
        $index = array_search($zone, $this->zones, true);
        if ($index === false || $index === 0) {
            return null;
        }
        return $this->zones[$index - 1];
    }
}
