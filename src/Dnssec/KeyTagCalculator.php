<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec;

class KeyTagCalculator
{
    /**
     * Compute DNSKEY key tag per RFC 4034 Appendix B.
     */
    public function computeKeyTag(int $flags, int $protocol, int $algorithm, string $publicKeyBase64): int
    {
        $rdata = pack('n', $flags) . pack('C', $protocol) . pack('C', $algorithm) . base64_decode($publicKeyBase64);

        $ac = 0;
        $len = strlen($rdata);
        for ($i = 0; $i < $len; $i++) {
            if ($i & 1) {
                $ac += ord($rdata[$i]);
            } else {
                $ac += ord($rdata[$i]) << 8;
            }
        }
        $ac += ($ac >> 16) & 0xFFFF;

        return $ac & 0xFFFF;
    }

    /**
     * Compute DS digest over owner name + DNSKEY RDATA.
     */
    public function computeDSDigest(
        string $domain,
        int $flags,
        int $protocol,
        int $algorithm,
        string $publicKeyBase64,
        int $digestType,
    ): string {
        $wire = $this->domainToWire($domain);
        $rdata = pack('n', $flags) . pack('C', $protocol) . pack('C', $algorithm) . base64_decode($publicKeyBase64);
        $data = $wire . $rdata;

        $algo = match ($digestType) {
            1 => 'sha1',
            2 => 'sha256',
            4 => 'sha384',
            default => throw new \InvalidArgumentException("Unsupported digest type: {$digestType}"),
        };

        return strtoupper(hash($algo, $data));
    }

    /**
     * Convert domain name to DNS wire format (sequence of length-prefixed labels).
     */
    public function domainToWire(string $domain): string
    {
        $domain = strtolower(rtrim($domain, '.'));
        if ($domain === '' || $domain === '.') {
            return "\0";
        }

        $wire = '';
        foreach (explode('.', $domain) as $label) {
            $wire .= chr(strlen($label)) . $label;
        }
        $wire .= "\0";

        return $wire;
    }
}
