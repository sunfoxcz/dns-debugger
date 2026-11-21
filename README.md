# DNSSEC Debugger

A PHP 8.4 DNSSEC chain-of-trust validation tool inspired by the
[Verisign Labs DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/).
Walks the DNS delegation chain from the root zone to a target domain,
verifying DNSSEC records at each level.

## Features

- Validates the full DNSSEC chain of trust (root -> TLD -> domain)
- Implements DNS wire protocol from scratch (no external DNS libraries)
- Supports DS, DNSKEY, RRSIG, NSEC/NSEC3 record types
- RFC 4034 key tag and DS digest computation (SHA-1, SHA-256, SHA-384)
- UDP transport with automatic TCP fallback on truncation
- Web UI with colored status indicators and CLI with ANSI output
- Per-nameserver authority and signature checks

## Requirements

- PHP 8.4+

## Quick Start

Run the CLI and web interface directly from the checkout with PHP. Both entry points load classes through `bootstrap.php`.

### CLI

```bash
php8.4 cli.php google.com
```

### Web

```bash
php8.4 -S localhost:8080
```

Then open `http://localhost:8080/?domain=google.com`.

## Library usage

Applications that install `dns-debugger/dns-debugger` as a Composer dependency load the `DnsDebugger\` classes through their own Composer autoloader.

## Documentation

See [docs/README.md](docs/README.md) for full documentation.

## License

MIT
