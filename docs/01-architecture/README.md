# Architecture

System design, component responsibilities, and data flow for the DNSSEC Debugger.

## Table of Contents

### [1. Overview](01-overview.md)

High-level architecture, directory structure, dependency graph, and end-to-end execution flow.

### [2. DNS Layer](02-dns-layer.md)

Wire protocol client (`DigRunner`), query abstraction (`DnsResolver`), and the `DnsRecord` value object.

### [3. DNSSEC Validation](03-dnssec-validation.md)

Chain-of-trust validation logic (`DnssecValidator`), cryptographic calculations (`KeyTagCalculator`),
trust anchors, zone discovery, and result models.

### [4. Rendering](04-rendering.md)

HTML and CLI output renderers, status icons, and the `ChainResultRenderer` interface.

## Related Documentation

- [Getting Started](../02-development/01-getting-started.md)
