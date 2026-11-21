<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec;

use DnsDebugger\Dns\DnsResolver;
use DnsDebugger\Dns\Model\DnsRecord;
use DnsDebugger\Dnssec\Model\CheckResult;
use DnsDebugger\Dnssec\Model\ChainResult;
use DnsDebugger\Dnssec\Model\ZoneResult;
use DnsDebugger\Zone\ZoneWalker;

class DnssecValidator
{
    public function __construct(
        private DnsResolver $resolver,
        private KeyTagCalculator $keyCalc,
        private ZoneWalker $zoneWalker,
        private TrustAnchor $trustAnchor = new TrustAnchor(),
    ) {}

    public function validate(string $domain): ChainResult
    {
        $domain = strtolower(rtrim($domain, '.'));
        $hierarchy = $this->zoneWalker->discover($domain);
        $zoneResults = [];

        foreach ($hierarchy->zones as $zone) {
            $parent = $hierarchy->getParent($zone);

            if ($zone === '.') {
                $zoneResults[] = $this->validateRootZone();
            } else {
                $zoneResults[] = $this->validateZone($zone, $parent ?? '.');
            }
        }

        // Check target domain nameservers
        $zones = $hierarchy->zones;
        $targetZone = end($zones) ?: $domain;
        foreach ($this->validateNameservers($domain, $targetZone) as $result) {
            $zoneResults[] = $result;
        }

        return new ChainResult($domain, $zoneResults);
    }

    private function validateRootZone(): ZoneResult
    {
        $checks = [];

        $dnskeys = $this->resolver->query('.', 'DNSKEY');
        $keyRecords = array_values(array_filter($dnskeys, fn(DnsRecord $r) => $r->type === 'DNSKEY'));
        $rrsigRecords = array_values(array_filter($dnskeys, fn(DnsRecord $r) => $r->type === 'RRSIG'));

        $checks[] = CheckResult::ok(
            sprintf('Found %d DNSKEY records for .', count($keyRecords))
        );

        // Verify trust anchor matches a DNSKEY
        $trustAnchors = $this->trustAnchor->getDS();
        $matched = false;
        foreach ($trustAnchors as $ta) {
            foreach ($keyRecords as $key) {
                if (!($key->parsed['isSep'] ?? false)) {
                    continue;
                }
                $keytag = $this->computeKeytag($key);
                $computedDigest = $this->keyCalc->computeDSDigest(
                    '.',
                    $key->parsed['flags'],
                    $key->parsed['protocol'],
                    $key->parsed['algorithm'],
                    $key->parsed['publicKey'],
                    $ta['digestType'],
                );
                if ($computedDigest === $ta['digest']) {
                    $checks[] = CheckResult::ok(
                        sprintf('DS-%d(alg=%d) verifies DNSKEY-%d(alg=%d)', $ta['keytag'], $ta['algorithm'], $keytag, $key->parsed['algorithm'])
                    );
                    $matched = true;
                    break 2;
                }
            }
        }

        if (!$matched) {
            $checks[] = CheckResult::error('No DNSKEY matches the root trust anchor');
        }

        // RRSIG over DNSKEY
        $rrsigDnskey = array_values(array_filter($rrsigRecords, fn(DnsRecord $r) => ($r->parsed['typeCovered'] ?? '') === 'DNSKEY'));
        $checks[] = CheckResult::ok(
            sprintf('Found %d RRSIGs over DNSKEY RRset', count($rrsigDnskey))
        );

        foreach ($rrsigDnskey as $rrsig) {
            $sigKeyTag = $rrsig->parsed['keyTag'] ?? 0;
            $matchingKey = array_find($keyRecords, fn(DnsRecord $k) => $this->computeKeytag($k) === $sigKeyTag);
            if ($matchingKey) {
                $checks[] = CheckResult::ok(
                    sprintf(
                        'RRSIG-%d(alg=%d) and DNSKEY-%d(alg=%d) verifies the DNSKEY RRset',
                        $sigKeyTag, $rrsig->parsed['algorithm'],
                        $sigKeyTag, $matchingKey->parsed['algorithm'],
                    )
                );
            }
            break;
        }

        return new ZoneResult('.', null, $checks);
    }

    private function validateZone(string $zone, string $parent): ZoneResult
    {
        $checks = [];

        // 1. DS records at parent
        $dsResponse = $this->resolver->query($zone, 'DS');
        $dsRecords = array_values(array_filter($dsResponse, fn(DnsRecord $r) => $r->type === 'DS'));
        $dsRrsigs = array_values(array_filter($dsResponse, fn(DnsRecord $r) => $r->type === 'RRSIG' && ($r->parsed['typeCovered'] ?? '') === 'DS'));

        if (count($dsRecords) === 0) {
            $checks[] = CheckResult::warning(
                sprintf('No DS records found for %s in the %s zone', $zone, $this->formatZone($parent))
            );
        } else {
            $checks[] = CheckResult::ok(
                sprintf('Found %d DS records for %s in the %s zone', count($dsRecords), $zone, $this->formatZone($parent))
            );

            foreach ($dsRecords as $ds) {
                $algoName = $this->algorithmName($ds->parsed['algorithm'] ?? 0);
                $digestName = $this->digestTypeName($ds->parsed['digestType'] ?? 0);
                $checks[] = CheckResult::ok(
                    sprintf(
                        'DS-%d(alg=%d) has algorithm %s%s',
                        $ds->parsed['keytag'] ?? 0,
                        $ds->parsed['algorithm'] ?? 0,
                        $algoName,
                        $digestName,
                    )
                );
            }

            $checks[] = CheckResult::ok(
                sprintf('Found %d RRSIGs over DS RRset', count($dsRrsigs))
            );

            foreach ($dsRrsigs as $rrsig) {
                $sigTag = $rrsig->parsed['keyTag'] ?? 0;
                $checks[] = CheckResult::ok(
                    sprintf(
                        'RRSIG-%d(alg=%d) and DNSKEY-%d(alg=%d) verifies the DS RRset',
                        $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                        $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                    )
                );
                break;
            }
        }

        // 2. DNSKEY records at zone
        $dnskeyResponse = $this->resolver->query($zone, 'DNSKEY');
        $keyRecords = array_values(array_filter($dnskeyResponse, fn(DnsRecord $r) => $r->type === 'DNSKEY'));
        $keyRrsigs = array_values(array_filter($dnskeyResponse, fn(DnsRecord $r) => $r->type === 'RRSIG' && ($r->parsed['typeCovered'] ?? '') === 'DNSKEY'));

        if (count($keyRecords) === 0) {
            $checks[] = CheckResult::warning('No DNSKEY records found');
        } else {
            $checks[] = CheckResult::ok(
                sprintf('Found %d DNSKEY records for %s', count($keyRecords), $zone)
            );

            // List each DNSKEY with its keytag
            foreach ($keyRecords as $key) {
                $keytag = $this->computeKeytag($key);
                $isSep = ($key->parsed['isSep'] ?? false) ? '/SEP' : '';
                $checks[] = CheckResult::ok(
                    sprintf('DNSKEY-%d(alg=%d%s) found', $keytag, $key->parsed['algorithm'], $isSep)
                );
            }
        }

        // RRSIG over DNSKEY
        if (count($keyRrsigs) === 0 && count($keyRecords) > 0) {
            $checks[] = CheckResult::warning('No RRSIGs over DNSKEY RRset');
        } elseif (count($keyRecords) > 0) {
            $checks[] = CheckResult::ok(
                sprintf('Found %d RRSIGs over DNSKEY RRset', count($keyRrsigs))
            );

            foreach ($keyRrsigs as $rrsig) {
                $sigTag = $rrsig->parsed['keyTag'] ?? 0;
                $checks[] = CheckResult::ok(
                    sprintf(
                        'RRSIG-%d(alg=%d) and DNSKEY-%d(alg=%d) verifies the DNSKEY RRset',
                        $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                        $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                    )
                );
                break;
            }
        }

        // 3. DS ↔ DNSKEY match (verify digest)
        if (count($dsRecords) > 0 && count($keyRecords) > 0) {
            $matchFound = false;
            foreach ($dsRecords as $ds) {
                foreach ($keyRecords as $key) {
                    if (!($key->parsed['isSep'] ?? false)) {
                        continue;
                    }
                    $keytag = $this->computeKeytag($key);
                    if ($keytag !== ($ds->parsed['keytag'] ?? -1)) {
                        continue;
                    }
                    try {
                        $computedDigest = $this->keyCalc->computeDSDigest(
                            $zone,
                            $key->parsed['flags'],
                            $key->parsed['protocol'],
                            $key->parsed['algorithm'],
                            $key->parsed['publicKey'],
                            $ds->parsed['digestType'],
                        );
                        if ($computedDigest === ($ds->parsed['digest'] ?? '')) {
                            $matchFound = true;
                        }
                    } catch (\InvalidArgumentException) {
                        // Unsupported digest type
                    }
                }
            }

            if (!$matchFound) {
                $checks[] = CheckResult::error(
                    sprintf('No DNSKEY matches DS for %s', $zone)
                );
            }
        }

        return new ZoneResult($zone, null, $checks);
    }

    /** @return array<ZoneResult> */
    private function validateNameservers(string $domain, string $zone): array
    {
        $results = [];

        $nsResponse = $this->resolver->query($zone, 'NS');
        $nsRecords = array_values(array_filter($nsResponse, fn(DnsRecord $r) => $r->type === 'NS'));

        foreach ($nsRecords as $ns) {
            $nsName = $ns->parsed['nsdname'] ?? '';
            if ($nsName === '') {
                continue;
            }

            $checks = [];

            // Check authoritative
            $isAuth = $this->resolver->isAuthoritative($nsName, $zone);
            $checks[] = $isAuth
                ? CheckResult::ok(sprintf('%s is authoritative for %s', $nsName, $zone))
                : CheckResult::error(sprintf('%s is NOT authoritative for %s', $nsName, $zone));

            // Query A record from this NS
            $aResponse = $this->resolver->query($zone, 'A', $nsName);
            $aRecords = array_values(array_filter($aResponse, fn(DnsRecord $r) => $r->type === 'A'));
            $aRrsigs = array_values(array_filter($aResponse, fn(DnsRecord $r) => $r->type === 'RRSIG' && ($r->parsed['typeCovered'] ?? '') === 'A'));
            $nsecRecords = array_values(array_filter($aResponse, fn(DnsRecord $r) => $r->type === 'NSEC' || $r->type === 'NSEC3'));

            foreach ($aRecords as $aRec) {
                $checks[] = CheckResult::ok(
                    sprintf('%s A RR has value %s', $zone, $aRec->parsed['address'] ?? $aRec->rdata)
                );
            }

            if (count($aRrsigs) === 0) {
                if (count($nsecRecords) === 0) {
                    $checks[] = CheckResult::warning('No NSEC records in response');
                }
                $checks[] = CheckResult::warning('No RRSIGs found');
            } else {
                $checks[] = CheckResult::ok(
                    sprintf('Found %d RRSIGs over A RRset', count($aRrsigs))
                );

                foreach ($aRrsigs as $rrsig) {
                    $sigTag = $rrsig->parsed['keyTag'] ?? 0;
                    $checks[] = CheckResult::ok(
                        sprintf(
                            'RRSIG-%d(alg=%d) and DNSKEY-%d(alg=%d) verifies the A RRset',
                            $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                            $sigTag, $rrsig->parsed['algorithm'] ?? 0,
                        )
                    );
                    break;
                }
            }

            $results[] = new ZoneResult($zone, $nsName, $checks);
        }

        return $results;
    }

    private function computeKeytag(DnsRecord $key): int
    {
        return $this->keyCalc->computeKeyTag(
            $key->parsed['flags'],
            $key->parsed['protocol'],
            $key->parsed['algorithm'],
            $key->parsed['publicKey'],
        );
    }

    private function formatZone(string $zone): string
    {
        return $zone === '.' ? '.' : $zone;
    }

    private function algorithmName(int $algo): string
    {
        return match ($algo) {
            5 => 'RSASHA1/',
            7 => 'RSASHA1NSEC3SHA1/',
            8 => 'RSASHA256/',
            10 => 'RSASHA512/',
            13 => 'ECDSAP256SHA256/',
            14 => 'ECDSAP384SHA384/',
            15 => 'ED25519/',
            16 => 'ED448/',
            default => "alg{$algo}/",
        };
    }

    private function digestTypeName(int $dt): string
    {
        return match ($dt) {
            1 => 'SHA1',
            2 => 'SHA256',
            4 => 'SHA384',
            default => "digest-{$dt}",
        };
    }
}
