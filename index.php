<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use DnsDebugger\Dns\DigRunner;
use DnsDebugger\Dns\DnsResolver;
use DnsDebugger\Dnssec\DnssecValidator;
use DnsDebugger\Dnssec\KeyTagCalculator;
use DnsDebugger\Renderer\HtmlRenderer;
use DnsDebugger\Zone\ZoneWalker;

$domain = trim($_GET['domain'] ?? '');
$resultHtml = '';

if ($domain !== '') {
    $digRunner = new DigRunner();
    $resolver = new DnsResolver($digRunner);
    $keyCalc = new KeyTagCalculator();
    $zoneWalker = new ZoneWalker($resolver);
    $validator = new DnssecValidator($resolver, $keyCalc, $zoneWalker);

    $result = $validator->validate($domain);

    $renderer = new HtmlRenderer();
    $resultHtml = $renderer->render($result);
    $timestamp = $result->timestamp->format('Y-m-d H:i:s') . ' UTC';
} else {
    $timestamp = '';
}

$domainEsc = htmlspecialchars($domain, ENT_QUOTES | ENT_HTML5);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DNSSEC Debugger<?= $domain !== '' ? " - {$domainEsc}" : '' ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            color: #333;
            background: #fff;
        }
        .header {
            background: #3366a9;
            color: #fff;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 {
            font-size: 18px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .toolbar {
            background: #f5f5f5;
            border-bottom: 1px solid #ddd;
            padding: 10px 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .toolbar label {
            font-weight: 600;
            white-space: nowrap;
        }
        .toolbar input[type="text"] {
            padding: 5px 10px;
            border: 1px solid #ccc;
            border-radius: 3px;
            font-size: 14px;
            width: 300px;
            max-width: 100%;
        }
        .toolbar button {
            padding: 5px 16px;
            background: #3366a9;
            color: #fff;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 14px;
        }
        .toolbar button:hover { background: #254d85; }
        .toolbar .timestamp {
            margin-left: auto;
            color: #666;
            font-size: 12px;
        }
        .content { padding: 20px; }

        /* Chain result table */
        .dnssec-result > p {
            margin-bottom: 15px;
            font-size: 14px;
        }
        .chain-table {
            border-collapse: collapse;
            width: 100%;
        }
        .chain-table tr {
            border-bottom: 1px solid #e0e0e0;
        }
        .chain-table tr:last-child {
            border-bottom: none;
        }
        .chain-table td {
            padding: 10px 12px;
            vertical-align: top;
        }
        .chain-table td.zone-label {
            width: 160px;
            font-size: 13px;
            color: #333;
            white-space: nowrap;
            padding-right: 16px;
        }
        .chain-table td.zone-label strong {
            font-weight: 700;
        }
        .chain-table td.zone-label .ns-label {
            font-weight: normal;
            color: #666;
            font-style: italic;
        }
        .chain-table td.zone-checks {
            padding-left: 8px;
            border-left: 1px solid #e0e0e0;
        }
        .check {
            padding: 1px 0;
            font-size: 13px;
            line-height: 1.7;
            display: flex;
            align-items: baseline;
        }
        .icon {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-right: 6px;
            position: relative;
            top: 0px;
        }
        .icon-ok { background: #4caf50; }
        .icon-warning { background: #ff9800; }
        .icon-error { background: #f44336; }
        .icon-info { background: #2196f3; }
        .check-message {
            flex: 1;
        }

        .footer {
            margin-top: 30px;
            padding: 15px 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #999;
            text-align: right;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>DNSSEC Debugger</h1>
    </div>
    <form method="get" class="toolbar">
        <label for="domain">Domain Name:</label>
        <input type="text" id="domain" name="domain" value="<?= $domainEsc ?>" placeholder="google.com" autofocus>
        <button type="submit">Analyze</button>
        <?php if ($timestamp !== ''): ?>
            <span class="timestamp">Time: <?= htmlspecialchars($timestamp) ?></span>
        <?php endif; ?>
    </form>
    <div class="content">
        <?= $resultHtml ?>
    </div>
    <div class="footer">DNSSEC Debugger</div>
</body>
</html>
