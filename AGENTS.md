# Repository guide

## Project overview

DNSSEC Debugger is a PHP 8.4+ tool for checking the DNSSEC chain of trust from the root zone to a target domain. It implements the DNS wire protocol directly and has no external PHP dependencies.

## Development commands

Use the repository root as the working directory for local development.

```bash
# Run a CLI validation
php8.4 cli.php google.com

# Start the web interface
php8.4 -S localhost:8080
```

Open `http://localhost:8080/?domain=google.com` to try the web interface. When `php8.4` is a Docker wrapper, start the container with port 8080 published.

```bash
docker run --rm -i -v "$(pwd):/app" --workdir /app --user "$(id -u):$(id -g)" \
    -p 8080:8080 sunfoxcz/php:8.4-cli php -S 0.0.0.0:8080
```

## Architecture

The `DnsDebugger\` namespace maps to `src/`. Keep each class, interface and enum in its own file at the corresponding PSR-4 path. The CLI and web entry points (`cli.php` and `index.php`) load `bootstrap.php` and wire dependencies directly. Applications that install the library use their own Composer autoloader.

| Directory | Responsibility |
| --- | --- |
| `src/Dns/` | `DigRunner` builds and parses DNS packets over UDP with TCP fallback for truncated responses. It handles EDNS0 and the DO and CD flags. `DnsResolver` returns `DnsRecord` value objects. |
| `src/Dnssec/` | `DnssecValidator` checks the root trust anchor, DS, DNSKEY and RRSIG records along the chain, and A records per nameserver. `KeyTagCalculator` computes RFC 4034 key tags and DS digests using SHA-1, SHA-256 or SHA-384. `TrustAnchor` contains the root KSK DS records. |
| `src/Zone/` | `ZoneWalker` queries SOA records to discover zone cuts and returns a `ZoneHierarchy`, for example `['.', 'com', 'google.com']`. |
| `src/Renderer/` | `HtmlRenderer` and `CliRenderer` implement `ChainResultRenderer` and consume the same `ChainResult`. The web status icons are styled in `index.php`, and the CLI uses ANSI colors. |

## PHP conventions

- Add `declare(strict_types=1);` to each PHP file.
- Keep models immutable with `readonly` classes. Use constructor property promotion and inject dependencies through constructors.
- Follow existing PHP idioms, including enums, `match` expressions, `new` in default arguments, and PHP 8.4's `array_find()` and `array_any()`.
- Build check results with `CheckResult::ok()`, `::warning()`, `::error()` or `::info()`. Use the `Status` enum when inspecting a result.
- Use `DnsRecord::fromLine()` to parse dig-style text and keep record-type-specific fields in `$parsed`.

## Manual verification

The repository has no configured test suite, linter or static analysis. Verify behavior through the CLI and check the web interface when changing HTML output or status styles. The [testing guide](docs/02-development/02-testing.md) describes the expected results and delegation chains.

| Domain | Expected behavior |
| --- | --- |
| `google.com` | Unsigned domain under the signed `.com` zone, with warnings for missing DNSSEC records. |
| `244.98.176.in-addr.arpa` | Signed reverse DNS with a long delegation chain. |
| `239.0.81.in-addr.arpa` | Unsigned reverse DNS with orange warnings for missing DNSSEC records. |

Use the [Verisign Labs DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/) as a reference when comparing validation results.
