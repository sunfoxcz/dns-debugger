# Getting Started

How to install and run the DNSSEC Debugger.

## Prerequisites

- **PHP 8.4+** with sockets extension enabled
- No external PHP dependencies

## Installation

```bash
git clone <repository-url> dns-debugger
cd dns-debugger
```

The CLI and web interface use `bootstrap.php` to load classes directly from `src/`.

## Running

### CLI

```bash
php8.4 cli.php <domain>
```

Example:

```bash
php8.4 cli.php google.com
```

Exit codes: `0` = chain valid, `1` = errors found.

### Web Server

Start the PHP built-in server:

```bash
php8.4 -S localhost:8080
```

Open `http://localhost:8080/?domain=google.com` in a browser.

### Docker

If `php8.4` is a Docker wrapper (e.g. `sunfoxcz/php:8.4-cli`), start the web server with port mapping:

```bash
docker run --rm -i \
    -v $(pwd):/app \
    --workdir /app \
    --user $(id -u):$(id -g) \
    -p 8080:8080 \
    sunfoxcz/php:8.4-cli php -S 0.0.0.0:8080
```

## Project Structure

Both the standalone bootstrap and the library's Composer configuration map the `DnsDebugger\` namespace to `src/`.
See [Architecture Overview](../01-architecture/01-overview.md) for the full directory layout.

## Next Steps

- [Testing](02-testing.md) - Test domains and expected output
- [Architecture Overview](../01-architecture/01-overview.md) - Understand the codebase
