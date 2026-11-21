<?php

declare(strict_types=1);

namespace DnsDebugger\Renderer;

use DnsDebugger\Dnssec\Model\ChainResult;
use DnsDebugger\Dnssec\Model\CheckResult;
use DnsDebugger\Dnssec\Model\Status;
use DnsDebugger\Dnssec\Model\ZoneResult;

class HtmlRenderer implements ChainResultRenderer
{
    public function render(ChainResult $result): string
    {
        $html = '<div class="dnssec-result">';
        $html .= sprintf(
            '<p>Analyzing DNSSEC problems for <strong><u>%s</u></strong></p>',
            $this->e($result->domain),
        );

        $html .= '<table class="chain-table">';

        // Group zone results: first by zone name (without NS), then per-NS results
        $lastZoneWithoutNs = null;
        foreach ($result->zones as $zoneResult) {
            $zoneName = $zoneResult->zone === '.' ? '.' : $zoneResult->zone;

            // Show zone label for: new zone, or NS results (like Verisign does)
            $isNsResult = $zoneResult->nameserver !== null;
            $showLabel = ($zoneName !== $lastZoneWithoutNs) || $isNsResult;

            if (!$isNsResult) {
                $lastZoneWithoutNs = $zoneName;
            }

            $html .= '<tr>';
            if ($showLabel && $isNsResult) {
                $html .= sprintf(
                    '<td class="zone-label"><span class="ns-label">%s</span></td>',
                    $this->e($zoneResult->nameserver),
                );
            } elseif ($showLabel) {
                $html .= sprintf(
                    '<td class="zone-label"><strong>%s</strong></td>',
                    $this->e($zoneName),
                );
            } else {
                $html .= '<td class="zone-label"></td>';
            }

            $html .= '<td class="zone-checks">';
            foreach ($zoneResult->checks as $check) {
                $html .= $this->renderCheck($check);
            }
            $html .= '</td>';
            $html .= '</tr>';
        }

        $html .= '</table>';
        $html .= '</div>';

        return $html;
    }

    private function renderCheck(CheckResult $check): string
    {
        $iconClass = match ($check->status) {
            Status::Ok => 'icon-ok',
            Status::Warning => 'icon-warning',
            Status::Error => 'icon-error',
            Status::Info => 'icon-info',
        };

        $title = match ($check->status) {
            Status::Ok => 'OK',
            Status::Warning => 'Warning',
            Status::Error => 'Error',
            Status::Info => 'Info',
        };

        return sprintf(
            '<div class="check"><span class="icon %s" title="%s"></span><span class="check-message">%s</span></div>',
            $iconClass,
            $title,
            $this->e($check->message),
        );
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5);
    }
}
