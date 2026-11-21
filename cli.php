<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use DnsDebugger\Dns\DigRunner;
use DnsDebugger\Dns\DnsResolver;
use DnsDebugger\Dnssec\DnssecValidator;
use DnsDebugger\Dnssec\KeyTagCalculator;
use DnsDebugger\Renderer\CliRenderer;
use DnsDebugger\Zone\ZoneWalker;

if ($argc < 2) {
    fprintf(STDERR, "Usage: %s <domain>\n", $argv[0]);
    fprintf(STDERR, "Example: %s google.com\n", $argv[0]);
    exit(1);
}

$domain = $argv[1];

// Wire up dependencies
$digRunner = new DigRunner();
$resolver = new DnsResolver($digRunner);
$keyCalc = new KeyTagCalculator();
$zoneWalker = new ZoneWalker($resolver);
$validator = new DnssecValidator($resolver, $keyCalc, $zoneWalker);

// Validate
$result = $validator->validate($domain);

// Render
$renderer = new CliRenderer();
echo $renderer->render($result);

exit($result->hasErrors() ? 1 : 0);
