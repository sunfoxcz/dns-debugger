# Overview

The DNSSEC Debugger validates the DNSSEC chain of trust from the DNS root zone down to a target domain.
It implements the DNS wire protocol from scratch, performs cryptographic verification of DS/DNSKEY relationships,
and presents results through both a web UI and a CLI.

## Directory Structure

```text
dns-debugger/
├── composer.json                      # PSR-4 autoload: DnsDebugger\ -> src/
├── bootstrap.php                      # Autoloader for standalone entry points
├── index.php                          # Web entry point
├── cli.php                            # CLI entry point
└── src/
    ├── Dns/
    │   ├── DigRunner.php              # Raw DNS wire protocol client
    │   ├── DnsResolver.php            # High-level query abstraction
    │   └── Model/
    │       └── DnsRecord.php          # DNS record value object
    ├── Dnssec/
    │   ├── DnssecValidator.php        # Chain-of-trust validation
    │   ├── KeyTagCalculator.php       # RFC 4034 key tag + DS digest
    │   ├── TrustAnchor.php            # Root zone trust anchors
    │   └── Model/
    │       ├── ChainResult.php        # Full validation result
    │       ├── CheckResult.php        # Single check (status + message)
    │       ├── Status.php             # Status enum (ok/warning/error/info)
    │       └── ZoneResult.php         # Per-zone result
    ├── Zone/
    │   ├── ZoneWalker.php             # Zone hierarchy discovery
    │   └── Model/
    │       └── ZoneHierarchy.php      # Ordered zone list
    └── Renderer/
        ├── ChainResultRenderer.php    # Renderer interface
        ├── CliRenderer.php            # Terminal ANSI output
        └── HtmlRenderer.php           # Web HTML output
```

## Dependency Graph

```text
index.php / cli.php
    |
DnssecValidator
    ├── DnsResolver -> DigRunner
    ├── KeyTagCalculator
    ├── ZoneWalker -> DnsResolver
    └── TrustAnchor
    |
ChainResult
    |
HtmlRenderer / CliRenderer
```

Both entry points construct the same dependency tree and pass a `ChainResult` to the appropriate renderer.

## Execution Flow

Validating a domain (e.g. `google.com`) proceeds through these stages:

1. **Zone Discovery** - `ZoneWalker` queries SOA records to find zone cuts,
   producing a `ZoneHierarchy` like `['.', 'com', 'google.com']`.

2. **Root Validation** - Query DNSKEY for `.`, find SEP keys, compute DS digest
   with `KeyTagCalculator`, and match against the hardcoded `TrustAnchor`.
   Verify RRSIG over the DNSKEY RRset.

3. **Zone Chain Validation** - For each zone in the hierarchy:
   - Query DS records at the parent zone
   - Query DNSKEY records at the child zone
   - Compute DS digest from DNSKEY and verify it matches the published DS
   - Check RRSIG over both DS and DNSKEY RRsets

4. **Nameserver Validation** - For the target zone:
   - Query NS records
   - For each nameserver: check AA flag, query A records, verify RRSIG over A RRset

5. **Result Assembly** - All checks are collected into `CheckResult` objects,
   grouped into `ZoneResult` objects, and wrapped in a `ChainResult`.

6. **Rendering** - `HtmlRenderer` or `CliRenderer` formats the result for output.

## Design Patterns

- **Value Objects** - All model classes are `readonly` (immutable)
- **Dependency Injection** - Constructor injection throughout
- **Interface Segregation** - `ChainResultRenderer` interface for output
- **Factory Pattern** - `DnsRecord::fromLine()` parses dig-style text
- **DDD-style Layering** - Dns, Dnssec, Zone, and Renderer as bounded contexts

## PHP 8.4 Features

- `readonly` classes and properties
- Enums (`Status`)
- Match expressions
- `new` in initializers (`TrustAnchor` default parameter)
- `array_find()`, `array_any()` (PHP 8.4 array functions)
- `declare(strict_types=1)` in all files

## Next Steps

- [DNS Layer](02-dns-layer.md) - Wire protocol and query details
- [DNSSEC Validation](03-dnssec-validation.md) - Validation logic
- [Rendering](04-rendering.md) - Output formatting
