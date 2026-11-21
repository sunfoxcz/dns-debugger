<?php

declare(strict_types=1);

namespace DnsDebugger\Dns;

use DnsDebugger\Dns\Model\DnsRecord;

class DnsResolver
{
    public function __construct(
        private DigRunner $dig,
    ) {}

    /** @return array<DnsRecord> */
    public function query(string $name, string $type, ?string $server = null): array
    {
        $output = $this->dig->run($name, $type, $server);
        return $this->parseOutput($output);
    }

    public function isAuthoritative(string $server, string $domain): bool
    {
        $output = $this->dig->runWithComments($domain, 'SOA', $server);

        // Look for the "flags:" line and check for "aa" flag
        foreach (explode("\n", $output) as $line) {
            if (preg_match('/flags:.*\baa\b/', $line)) {
                return true;
            }
        }

        return false;
    }

    /** @return array<DnsRecord> */
    private function parseOutput(string $output): array
    {
        $records = [];
        $lines = explode("\n", $output);

        // Join parenthesized multi-line records
        $joined = $this->joinMultilineRecords($lines);

        foreach ($joined as $line) {
            $record = DnsRecord::fromLine($line);
            if ($record !== null) {
                $records[] = $record;
            }
        }

        return $records;
    }

    /** @return array<string> */
    private function joinMultilineRecords(array $lines): array
    {
        $result = [];
        $buffer = '';
        $inParens = false;

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Skip empty lines and comments (but keep processing if inside parens)
            if (!$inParens && ($trimmed === '' || str_starts_with($trimmed, ';'))) {
                continue;
            }

            if (str_starts_with($trimmed, ';')) {
                continue;
            }

            if ($inParens) {
                // Strip comments from continuation lines
                $clean = preg_replace('/\s*;.*$/', '', $trimmed) ?? $trimmed;
                $buffer .= ' ' . $clean;

                if (str_contains($clean, ')')) {
                    $inParens = false;
                    $buffer = str_replace(['(', ')'], '', $buffer);
                    $result[] = preg_replace('/\s+/', ' ', trim($buffer)) ?? trim($buffer);
                    $buffer = '';
                }
            } else {
                if (str_contains($trimmed, '(') && !str_contains($trimmed, ')')) {
                    $inParens = true;
                    $clean = preg_replace('/\s*;.*$/', '', $trimmed) ?? $trimmed;
                    $buffer = $clean;
                } else {
                    // Single line record - strip inline comment
                    $clean = preg_replace('/\s*;.*$/', '', $trimmed) ?? $trimmed;
                    $clean = str_replace(['(', ')'], '', $clean);
                    $result[] = preg_replace('/\s+/', ' ', trim($clean)) ?? trim($clean);
                }
            }
        }

        return $result;
    }
}
