<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec;

readonly class TrustAnchor
{
    /**
     * Root zone trust anchors (DS records).
     * Current root KSK: keytag 20326, algorithm 8 (RSASHA256), digest type 2 (SHA-256).
     *
     * @return array<array{keytag: int, algorithm: int, digestType: int, digest: string}>
     */
    public function getDS(): array
    {
        return [
            [
                'keytag' => 20326,
                'algorithm' => 8,
                'digestType' => 2,
                'digest' => 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
            ],
            [
                'keytag' => 38696,
                'algorithm' => 8,
                'digestType' => 2,
                'digest' => '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
            ],
        ];
    }
}
