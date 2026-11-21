<?php

declare(strict_types=1);

namespace DnsDebugger\Renderer;

use DnsDebugger\Dnssec\Model\ChainResult;
use DnsDebugger\Dnssec\Model\CheckResult;
use DnsDebugger\Dnssec\Model\Status;
use DnsDebugger\Dnssec\Model\ZoneResult;

class CliRenderer implements ChainResultRenderer
{
    public function render(ChainResult $result): string
    {
        $out = '';
        $out .= "\n";
        $out .= $this->bold("DNSSEC Debugger - {$result->domain}") . "\n";
        $out .= sprintf("Time: %s UTC\n", $result->timestamp->format('Y-m-d H:i:s'));
        $out .= str_repeat('─', 60) . "\n\n";

        $currentZone = null;
        foreach ($result->zones as $zoneResult) {
            $label = $this->formatZoneLabel($zoneResult);
            if ($label !== $currentZone) {
                $currentZone = $label;
                $out .= $this->bold($label) . "\n";
            }

            if ($zoneResult->nameserver !== null) {
                $out .= "  " . $this->dim("NS: {$zoneResult->nameserver}") . "\n";
            }

            foreach ($zoneResult->checks as $check) {
                $out .= $this->formatCheck($check) . "\n";
            }
            $out .= "\n";
        }

        if ($result->hasErrors()) {
            $out .= $this->color("✗ DNSSEC validation has errors", '31') . "\n";
        } else {
            $out .= $this->color("✓ DNSSEC chain of trust is valid", '32') . "\n";
        }

        return $out;
    }

    private function formatZoneLabel(ZoneResult $zone): string
    {
        $name = $zone->zone === '.' ? '.' : $zone->zone;
        return $name;
    }

    private function formatCheck(CheckResult $check): string
    {
        [$symbol, $color] = match ($check->status) {
            Status::Ok => ['✓', '32'],      // green
            Status::Warning => ['⚠', '33'],  // yellow
            Status::Error => ['✗', '31'],    // red
            Status::Info => ['ℹ', '34'],     // blue
        };

        return sprintf("  %s %s", $this->color($symbol, $color), $check->message);
    }

    private function color(string $text, string $code): string
    {
        return "\033[{$code}m{$text}\033[0m";
    }

    private function bold(string $text): string
    {
        return "\033[1m{$text}\033[0m";
    }

    private function dim(string $text): string
    {
        return "\033[2m{$text}\033[0m";
    }
}
