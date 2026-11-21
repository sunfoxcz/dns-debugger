# Rendering

The rendering layer converts `ChainResult` objects into human-readable output.
Both renderers implement the `ChainResultRenderer` interface.

## ChainResultRenderer Interface

`src/Renderer/ChainResultRenderer.php`

```php
interface ChainResultRenderer
{
    public function render(ChainResult $result): string;
}
```

## HtmlRenderer

`src/Renderer/HtmlRenderer.php` generates HTML for the web UI.

### Output Structure

- Two-column table: zone label (left) and checks (right)
- Zone names shown in bold
- Nameserver names shown in italic
- Colored circle icons for status (CSS classes)
- All output HTML-escaped via `htmlspecialchars()`

### Status Icons

| Status | CSS Class | Color |
| -------- | ----------- | ------- |
| OK | `icon-ok` | Green (#4caf50) |
| Warning | `icon-warning` | Orange (#ff9800) |
| Error | `icon-error` | Red (#f44336) |
| Info | `icon-info` | Blue (#2196f3) |

Icons are 10px circles rendered as `<span>` elements with CSS `border-radius: 50%` and `background` color.
CSS is defined in `index.php`, not in the renderer.

## CliRenderer

`src/Renderer/CliRenderer.php` generates ANSI-colored terminal output.

### Output Format

```text
DNSSEC Debugger - google.com
Time: 2026-02-13 12:34:56 UTC
---------------------------------------------

.
  [green checkmark] Found 3 DNSKEY records for .
  [green checkmark] DS-20326(alg=8) verifies DNSKEY-20326(alg=8)

com
  [green checkmark] Found 1 DS records for com in the . zone

google.com
  [yellow warning] No DS records found for google.com in the com zone
  [yellow warning] No DNSKEY records found

  NS: ns1.google.com
    [green checkmark] ns1.google.com is authoritative for google.com

[green checkmark] DNSSEC chain of trust is valid
```

### Status Symbols

| Status | Symbol | ANSI Color |
| -------- | -------- | ------------ |
| OK | Checkmark | Green |
| Warning | Warning sign | Yellow |
| Error | Cross | Red |
| Info | Info circle | Blue |

Zone headings are bold. Nameserver labels are dimmed. A final summary line indicates
whether the chain is valid or has errors.

## Next Steps

- [Overview](01-overview.md) - Back to architecture overview
- [Getting Started](../02-development/01-getting-started.md) - Run the project
