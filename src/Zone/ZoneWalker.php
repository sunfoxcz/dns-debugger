<?php

declare(strict_types=1);

namespace DnsDebugger\Zone;

use DnsDebugger\Dns\DnsResolver;
use DnsDebugger\Zone\Model\ZoneHierarchy;

class ZoneWalker
{
    public function __construct(
        private DnsResolver $resolver,
    ) {}

    public function discover(string $domain): ZoneHierarchy
    {
        $domain = strtolower(rtrim($domain, '.'));
        $labels = explode('.', $domain);
        $zones = ['.'];

        // Build candidates from TLD down to full domain
        // e.g., for "www.google.com": ["com", "google.com", "www.google.com"]
        $candidates = [];
        for ($i = count($labels) - 1; $i >= 0; $i--) {
            $candidates[] = implode('.', array_slice($labels, $i));
        }

        foreach ($candidates as $candidate) {
            if ($this->isZoneCut($candidate)) {
                $zones[] = $candidate;
            }
        }

        return new ZoneHierarchy($zones);
    }

    private function isZoneCut(string $name): bool
    {
        $records = $this->resolver->query($name, 'SOA');

        foreach ($records as $record) {
            if ($record->type === 'SOA' && $record->name === strtolower($name)) {
                return true;
            }
        }

        return false;
    }
}
