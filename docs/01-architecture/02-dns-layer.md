# DNS Layer

The DNS layer handles raw DNS queries and response parsing. It consists of three components:
`DigRunner` (wire protocol), `DnsResolver` (query abstraction), and `DnsRecord` (value object).

## DigRunner

`src/Dns/DigRunner.php` implements the DNS wire protocol from scratch without external libraries.

### Capabilities

- Builds binary DNS query packets with proper header, question, and EDNS0 OPT sections
- Sets the CD (Checking Disabled) flag to bypass resolver DNSSEC validation
- Sets the EDNS0 DO (DNSSEC OK) bit to request DNSSEC records
- UDP transport with automatic TCP fallback when responses are truncated
- Parses binary responses including compression pointer support

### Record Types

Supported in response parsing: A, AAAA, NS, SOA, DS, DNSKEY, RRSIG, NSEC, NSEC3.

### Methods

```php
// Standard query - returns dig-style text output
$runner->run(string $name, string $type, ?string $server = null, bool $dnssec = true): string

// Query with AA flag info in output (for authority checks)
$runner->runWithComments(string $name, string $type, string $server): string
```

### Configuration

- Default resolver: `1.1.1.1` (Cloudflare DNS)
- Timeout: 5 seconds
- UDP buffer: 4096 bytes

## DnsResolver

`src/Dns/DnsResolver.php` wraps `DigRunner` with a higher-level interface that returns typed objects.

### Methods

```php
// Execute DNS query, returns array of DnsRecord
$resolver->query(string $name, string $type, ?string $server = null): array

// Check if a nameserver is authoritative for a domain
$resolver->isAuthoritative(string $server, string $domain): bool
```

### Parsing

- Converts dig-style text output into `DnsRecord` objects
- Handles multi-line (parenthesized) records by joining continuation lines
- Strips comments from output

## DnsRecord

`src/Dns/Model/DnsRecord.php` is a readonly value object representing a single DNS record.

### Properties

| Property | Type | Description |
| ---------- | ------ | ------------- |
| `$name` | `string` | Domain name (lowercased, no trailing dot) |
| `$ttl` | `int` | Time to live |
| `$class` | `string` | Record class (usually `IN`) |
| `$type` | `string` | Record type (`A`, `DS`, `DNSKEY`, etc.) |
| `$rdata` | `string` | Raw RDATA string |
| `$parsed` | `array` | Type-specific parsed fields |

### Parsed Fields by Type

**DS**: `keytag`, `algorithm`, `digestType`, `digest`

**DNSKEY**: `flags`, `protocol`, `algorithm`, `publicKey`, `isSep`, `isZoneKey`

**RRSIG**: `typeCovered`, `algorithm`, `labels`, `originalTtl`, `sigExpiration`,
`sigInception`, `keyTag`, `signer`, `signature`

**NS**: `nsdname`

**SOA**: `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum`

**A/AAAA**: `address`

### Factory Method

```php
$record = DnsRecord::fromLine('example.com. 3600 IN A 93.184.216.34');
```

## Next Steps

- [DNSSEC Validation](03-dnssec-validation.md) - How the DNS layer is used for validation
- [Overview](01-overview.md) - Back to architecture overview
