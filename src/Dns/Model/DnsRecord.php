<?php

declare(strict_types=1);

namespace DnsDebugger\Dns\Model;

readonly class DnsRecord
{
    public function __construct(
        public string $name,
        public int $ttl,
        public string $class,
        public string $type,
        public string $rdata,
        public array $parsed = [],
    ) {}

    public static function fromLine(string $line): ?self
    {
        // Match: name ttl class type rdata...
        $line = trim($line);
        if ($line === '' || str_starts_with($line, ';')) {
            return null;
        }

        // Split into at most 5 parts: name, ttl, class, type, rdata
        $parts = preg_split('/\s+/', $line, 5);
        if ($parts === false || count($parts) < 5) {
            return null;
        }

        [$name, $ttl, $class, $type, $rdata] = $parts;

        $name = rtrim($name, '.');
        if ($name === '') {
            $name = '.';
        }

        $record = new self(
            name: strtolower($name),
            ttl: (int) $ttl,
            class: strtoupper($class),
            type: strtoupper($type),
            rdata: $rdata,
        );

        return $record->withParsedData();
    }

    private function withParsedData(): self
    {
        $parsed = match ($this->type) {
            'DS' => $this->parseDS(),
            'DNSKEY' => $this->parseDNSKEY(),
            'RRSIG' => $this->parseRRSIG(),
            'NS' => $this->parseNS(),
            'SOA' => $this->parseSOA(),
            'A' => ['address' => $this->rdata],
            'AAAA' => ['address' => $this->rdata],
            default => [],
        };

        return new self($this->name, $this->ttl, $this->class, $this->type, $this->rdata, $parsed);
    }

    private function parseDS(): array
    {
        $parts = preg_split('/\s+/', $this->rdata, 4);
        if ($parts === false || count($parts) < 4) {
            return [];
        }

        return [
            'keytag' => (int) $parts[0],
            'algorithm' => (int) $parts[1],
            'digestType' => (int) $parts[2],
            'digest' => strtoupper(str_replace(' ', '', $parts[3])),
        ];
    }

    private function parseDNSKEY(): array
    {
        $parts = preg_split('/\s+/', $this->rdata, 4);
        if ($parts === false || count($parts) < 4) {
            return [];
        }

        $flags = (int) $parts[0];

        return [
            'flags' => $flags,
            'protocol' => (int) $parts[1],
            'algorithm' => (int) $parts[2],
            'publicKey' => str_replace(' ', '', $parts[3]),
            'isSep' => ($flags & 1) === 1, // SEP bit (bit 15, lowest bit)
            'isZoneKey' => ($flags & 256) === 256, // Zone Key bit (bit 7)
        ];
    }

    private function parseRRSIG(): array
    {
        $parts = preg_split('/\s+/', $this->rdata, 9);
        if ($parts === false || count($parts) < 9) {
            return [];
        }

        $signer = rtrim($parts[7], '.');
        if ($signer === '') {
            $signer = '.';
        }

        return [
            'typeCovered' => strtoupper($parts[0]),
            'algorithm' => (int) $parts[1],
            'labels' => (int) $parts[2],
            'originalTtl' => (int) $parts[3],
            'sigExpiration' => $parts[4],
            'sigInception' => $parts[5],
            'keyTag' => (int) $parts[6],
            'signer' => strtolower($signer),
            'signature' => str_replace(' ', '', $parts[8]),
        ];
    }

    private function parseNS(): array
    {
        $ns = rtrim($this->rdata, '.');
        return ['nsdname' => strtolower($ns)];
    }

    private function parseSOA(): array
    {
        $parts = preg_split('/\s+/', $this->rdata);
        if ($parts === false || count($parts) < 7) {
            return [];
        }

        return [
            'mname' => strtolower(rtrim($parts[0], '.')),
            'rname' => strtolower(rtrim($parts[1], '.')),
            'serial' => (int) $parts[2],
            'refresh' => (int) $parts[3],
            'retry' => (int) $parts[4],
            'expire' => (int) $parts[5],
            'minimum' => (int) $parts[6],
        ];
    }

    public function algorithmName(): string
    {
        $algo = $this->parsed['algorithm'] ?? null;
        return match ($algo) {
            1 => 'RSAMD5',
            3 => 'DSA',
            5 => 'RSASHA1',
            6 => 'DSA-NSEC3-SHA1',
            7 => 'RSASHA1-NSEC3-SHA1',
            8 => 'RSASHA256',
            10 => 'RSASHA512',
            13 => 'ECDSAP256SHA256',
            14 => 'ECDSAP384SHA384',
            15 => 'ED25519',
            16 => 'ED448',
            default => "algorithm-{$algo}",
        };
    }

    public function digestTypeName(): string
    {
        $dt = $this->parsed['digestType'] ?? null;
        return match ($dt) {
            1 => 'SHA1',
            2 => 'SHA256',
            4 => 'SHA384',
            default => "digest-type-{$dt}",
        };
    }
}
