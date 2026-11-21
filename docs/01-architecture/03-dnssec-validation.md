# DNSSEC Validation

The DNSSEC validation layer implements chain-of-trust verification from the root zone
to the target domain. It uses `DnssecValidator` as the orchestrator, `KeyTagCalculator`
for cryptographic operations, `TrustAnchor` for root trust, and `ZoneWalker` for zone discovery.

## DnssecValidator

`src/Dnssec/DnssecValidator.php` is the main validation orchestrator.

### Constructor Dependencies

```php
public function __construct(
    private DnsResolver $resolver,
    private KeyTagCalculator $keyCalc,
    private ZoneWalker $zoneWalker,
    private TrustAnchor $trustAnchor = new TrustAnchor(),
)
```

### Validation Algorithm

The `validate(string $domain): ChainResult` method performs:

**Root Zone** (`validateRootZone`):

1. Query DNSKEY records for `.`
2. Find SEP (Secure Entry Point) keys (`flags & 1 == 1`)
3. Compute DS digest using `KeyTagCalculator::computeDSDigest()`
4. Match against `TrustAnchor::getDS()`
5. Verify RRSIG exists over the DNSKEY RRset

**Each Intermediate Zone** (`validateZone`):

1. Query DS records at the parent zone
2. Report DS key tags, algorithms, and digest types
3. Check RRSIG over the DS RRset
4. Query DNSKEY records at the child zone
5. List each DNSKEY with its key tag
6. Check RRSIG over the DNSKEY RRset
7. Verify DS digest matches a DNSKEY (SEP keys only, matching key tags)

**Nameserver Checks** (`validateNameservers`):

1. Query NS records for the target zone
2. For each nameserver:
   - Check authoritative (AA) flag
   - Query A record from that nameserver
   - Check for RRSIG over the A RRset
   - Check for NSEC/NSEC3 records if no RRSIGs found

### Status Logic

- **OK** (green): Record found and verified
- **Warning** (orange): Missing DNSKEY, missing RRSIG, missing NSEC, no DS records
- **Error** (red): DS does not match any DNSKEY, nameserver not authoritative

## KeyTagCalculator

`src/Dnssec/KeyTagCalculator.php` performs pure cryptographic calculations with no external dependencies.

### Key Tag (RFC 4034 Appendix B)

```php
$tag = $calc->computeKeyTag(
    int $flags,
    int $protocol,
    int $algorithm,
    string $publicKeyBase64,
): int;
```

Computes a 16-bit key tag from DNSKEY RDATA. Used to match DS records to DNSKEY records.

### DS Digest

```php
$digest = $calc->computeDSDigest(
    string $domain,
    int $flags,
    int $protocol,
    int $algorithm,
    string $publicKeyBase64,
    int $digestType,
): string;
```

Creates a DS digest from `domainWireFormat + DNSKEY_RDATA`. Returns uppercase hex string.

Supported digest types:

| Type | Algorithm |
| ------ | ----------- |
| 1 | SHA-1 |
| 2 | SHA-256 |
| 4 | SHA-384 |

### Wire Format

`domainToWire(string $domain): string` converts a domain name to DNS wire format
(length-prefixed labels terminated by a zero byte).

## TrustAnchor

`src/Dnssec/TrustAnchor.php` provides hardcoded root zone DS records (ICANN root KSKs).

```php
$anchors = (new TrustAnchor())->getDS();
// Returns array of ['keytag' => int, 'algorithm' => int, 'digestType' => int, 'digest' => string]
```

Current trust anchors: key tags 20326 and 38696, both algorithm 8 (RSASHA256), digest type 2 (SHA-256).

## ZoneWalker

`src/Zone/ZoneWalker.php` discovers the actual DNS zone hierarchy for a domain.

### Algorithm

1. Split domain into labels (e.g. `www.google.com` produces `['www', 'google', 'com']`)
2. Build candidate names from the TLD down to the full domain (e.g. `['com', 'google.com', 'www.google.com']`)
3. Query SOA for each candidate
4. A zone cut exists where the SOA name matches the query name
5. Return a `ZoneHierarchy` starting with the root zone (e.g. `['.', 'com', 'google.com']`)

## Result Models

### ChainResult

`src/Dnssec/Model/ChainResult.php` - Complete validation result.

| Property | Type | Description |
| ---------- | ------ | ------------- |
| `$domain` | `string` | Target domain |
| `$zones` | `array<ZoneResult>` | Results per zone |
| `$timestamp` | `DateTimeImmutable` | When validation ran |

`hasErrors(): bool` returns true if any zone has errors.

### ZoneResult

`src/Dnssec/Model/ZoneResult.php` - Per-zone or per-nameserver result.

| Property | Type | Description |
| ---------- | ------ | ------------- |
| `$zone` | `string` | Zone name |
| `$nameserver` | `?string` | Nameserver (null for zone-level checks) |
| `$checks` | `array<CheckResult>` | Individual checks |

### CheckResult

`src/Dnssec/Model/CheckResult.php` - Single check with status and message.

Factory methods: `CheckResult::ok()`, `::warning()`, `::error()`, `::info()`.

### Status

`src/Dnssec/Model/Status.php` - Backed enum: `Ok`, `Warning`, `Error`, `Info`.

## Next Steps

- [Rendering](04-rendering.md) - How results are displayed
- [DNS Layer](02-dns-layer.md) - Wire protocol details
