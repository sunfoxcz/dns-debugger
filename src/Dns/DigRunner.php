<?php

declare(strict_types=1);

namespace DnsDebugger\Dns;

/**
 * Raw DNS wire protocol client. Builds DNS query packets with EDNS0/DO bit
 * and parses responses. Uses UDP with TCP fallback for truncated responses.
 */
class DigRunner
{
    private const DEFAULT_RESOLVER = '1.1.1.1';
    private const TIMEOUT = 5;
    private const UDP_MAX = 4096;

    // DNS record type codes
    private const TYPE_A = 1;
    private const TYPE_NS = 2;
    private const TYPE_SOA = 6;
    private const TYPE_AAAA = 28;
    private const TYPE_DS = 43;
    private const TYPE_RRSIG = 46;
    private const TYPE_NSEC = 47;
    private const TYPE_DNSKEY = 48;
    private const TYPE_NSEC3 = 50;
    private const TYPE_OPT = 41;

    private const TYPE_MAP = [
        'A' => self::TYPE_A,
        'NS' => self::TYPE_NS,
        'SOA' => self::TYPE_SOA,
        'AAAA' => self::TYPE_AAAA,
        'DS' => self::TYPE_DS,
        'RRSIG' => self::TYPE_RRSIG,
        'NSEC' => self::TYPE_NSEC,
        'DNSKEY' => self::TYPE_DNSKEY,
        'NSEC3' => self::TYPE_NSEC3,
    ];

    private const TYPE_NAME = [
        self::TYPE_A => 'A',
        self::TYPE_NS => 'NS',
        self::TYPE_SOA => 'SOA',
        self::TYPE_AAAA => 'AAAA',
        self::TYPE_DS => 'DS',
        self::TYPE_RRSIG => 'RRSIG',
        self::TYPE_NSEC => 'NSEC',
        self::TYPE_DNSKEY => 'DNSKEY',
        self::TYPE_NSEC3 => 'NSEC3',
        self::TYPE_OPT => 'OPT',
    ];

    /**
     * Query DNS and return dig-style text output.
     * Sets CD (Checking Disabled) flag so we get DNSSEC records even if validation fails.
     */
    public function run(string $name, string $type, ?string $server = null, bool $dnssec = true): string
    {
        return $this->doQuery($name, $type, $server ?? self::DEFAULT_RESOLVER, $dnssec, false);
    }

    /**
     * Query with comments - returns dig-style output including flags header for AA check.
     */
    public function runWithComments(string $name, string $type, string $server): string
    {
        return $this->doQuery($name, $type, $server, true, true);
    }

    private function doQuery(string $name, string $type, string $server, bool $dnssec, bool $includeComments): string
    {
        $typeCode = self::TYPE_MAP[strtoupper($type)] ?? 0;
        if ($typeCode === 0) {
            return '';
        }

        // Resolve server hostname to IP if needed
        $serverIp = $this->resolveServer($server);
        if ($serverIp === null) {
            return '';
        }

        $packet = $this->buildQuery($name, $typeCode, $dnssec);
        $response = $this->sendUdp($serverIp, $packet);

        if ($response === null) {
            return '';
        }

        // Check for truncation (TC bit)
        if (strlen($response) >= 2) {
            $flags = unpack('n', $response, 2);
            if ($flags && ($flags[1] & 0x0200)) {
                // Retry with TCP
                $response = $this->sendTcp($serverIp, $packet);
                if ($response === null) {
                    return '';
                }
            }
        }

        return $this->parseResponse($response, $includeComments);
    }

    private function buildQuery(string $name, int $type, bool $dnssec): string
    {
        $id = random_int(0, 0xFFFF);

        // Flags: RD=1 (recursion desired), CD=1 (checking disabled)
        // CD is bit 4 from right in second byte of flags = 0x0010
        $flags = 0x0110; // RD + CD

        // Header: ID, FLAGS, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0/1
        $arcount = $dnssec ? 1 : 0;
        $header = pack('nnnnnn', $id, $flags, 1, 0, 0, $arcount);

        // Question section
        $qname = $this->encodeName($name);
        $question = $qname . pack('nn', $type, 1); // QTYPE, QCLASS=IN

        $packet = $header . $question;

        // EDNS0 OPT record for DNSSEC
        if ($dnssec) {
            // Name: 0x00 (root), Type: OPT(41), UDP size: 4096, Extended RCODE: 0, Version: 0, DO bit, RDLENGTH: 0
            $doFlag = 0x8000; // DO bit set
            $opt = "\x00" . pack('nn', self::TYPE_OPT, self::UDP_MAX) . pack('N', $doFlag << 16 >> 16) . pack('n', 0);
            // Actually the OPT wire format: name(1) + type(2) + class/udpsize(2) + ttl(4 bytes: ext-rcode, version, flags with DO) + rdlength(2)
            $opt = "\x00" // root name
                . pack('n', self::TYPE_OPT) // type
                . pack('n', self::UDP_MAX) // UDP payload size
                . pack('C', 0) // extended RCODE
                . pack('C', 0) // version
                . pack('n', 0x8000) // flags: DO bit
                . pack('n', 0); // RDLENGTH
            $packet .= $opt;
        }

        return $packet;
    }

    private function encodeName(string $name): string
    {
        $name = strtolower(rtrim($name, '.'));
        if ($name === '' || $name === '.') {
            return "\x00";
        }

        $result = '';
        foreach (explode('.', $name) as $label) {
            $result .= chr(strlen($label)) . $label;
        }
        $result .= "\x00";

        return $result;
    }

    private function resolveServer(string $server): ?string
    {
        // If already an IP, return as-is
        if (filter_var($server, FILTER_VALIDATE_IP)) {
            return $server;
        }

        // Resolve hostname to IP
        $ip = gethostbyname($server);
        if ($ip === $server) {
            // gethostbyname returns the input on failure
            return null;
        }

        return $ip;
    }

    private function sendUdp(string $server, string $packet): ?string
    {
        $socket = @stream_socket_client(
            "udp://{$server}:53",
            $errno,
            $errstr,
            self::TIMEOUT,
        );

        if ($socket === false) {
            return null;
        }

        stream_set_timeout($socket, self::TIMEOUT);
        fwrite($socket, $packet);
        $response = fread($socket, 65535);
        fclose($socket);

        return $response !== false && $response !== '' ? $response : null;
    }

    private function sendTcp(string $server, string $packet): ?string
    {
        $socket = @stream_socket_client(
            "tcp://{$server}:53",
            $errno,
            $errstr,
            self::TIMEOUT,
        );

        if ($socket === false) {
            return null;
        }

        stream_set_timeout($socket, self::TIMEOUT);

        // TCP DNS: 2-byte length prefix
        fwrite($socket, pack('n', strlen($packet)) . $packet);

        // Read length prefix
        $lenData = fread($socket, 2);
        if ($lenData === false || strlen($lenData) < 2) {
            fclose($socket);
            return null;
        }

        $len = unpack('n', $lenData)[1];
        $response = '';
        while (strlen($response) < $len) {
            $chunk = fread($socket, $len - strlen($response));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $response .= $chunk;
        }

        fclose($socket);

        return $response !== '' ? $response : null;
    }

    /**
     * Parse raw DNS response into dig-style text output.
     */
    private function parseResponse(string $data, bool $includeComments): string
    {
        $offset = 0;
        $len = strlen($data);

        if ($len < 12) {
            return '';
        }

        // Parse header
        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $data);
        $offset = 12;

        $flags = $header['flags'];
        $aa = ($flags & 0x0400) !== 0;
        $rcode = $flags & 0x000F;

        $lines = [];

        if ($includeComments) {
            $flagStrs = [];
            if ($flags & 0x8000) $flagStrs[] = 'qr';
            if ($aa) $flagStrs[] = 'aa';
            if ($flags & 0x0100) $flagStrs[] = 'rd';
            if ($flags & 0x0080) $flagStrs[] = 'ra';
            if ($flags & 0x0010) $flagStrs[] = 'cd';
            $lines[] = ';; flags: ' . implode(' ', $flagStrs) . '; QUERY: ' . $header['qdcount']
                . ', ANSWER: ' . $header['ancount'] . ', AUTHORITY: ' . $header['nscount'];
        }

        // Skip question section
        for ($i = 0; $i < $header['qdcount']; $i++) {
            $this->decodeName($data, $offset); // skip QNAME
            $offset += 4; // skip QTYPE + QCLASS
        }

        // Parse answer + authority sections
        $totalRecords = $header['ancount'] + $header['nscount'];
        for ($i = 0; $i < $totalRecords && $offset < $len; $i++) {
            $line = $this->parseRecord($data, $offset);
            if ($line !== null) {
                $lines[] = $line;
            }
        }

        return implode("\n", $lines) . "\n";
    }

    private function parseRecord(string $data, int &$offset): ?string
    {
        $name = $this->decodeName($data, $offset);
        if ($offset + 10 > strlen($data)) {
            return null;
        }

        $header = unpack('ntype/nclass/Nttl/nrdlength', substr($data, $offset, 10));
        $offset += 10;

        $type = $header['type'];
        $class = $header['class'];
        $ttl = $header['ttl'];
        // Handle unsigned 32-bit TTL
        if ($ttl < 0) {
            $ttl += 4294967296;
        }
        $rdlength = $header['rdlength'];

        if ($type === self::TYPE_OPT) {
            // Skip OPT records
            $offset += $rdlength;
            return null;
        }

        $rdataStart = $offset;
        $rdata = $this->decodeRdata($type, $data, $offset, $rdlength);
        $offset = $rdataStart + $rdlength;

        $typeName = self::TYPE_NAME[$type] ?? "TYPE{$type}";
        $className = $class === 1 ? 'IN' : "CLASS{$class}";

        return "{$name}\t\t{$ttl}\t{$className}\t{$typeName}\t{$rdata}";
    }

    private function decodeRdata(int $type, string $data, int $offset, int $rdlength): string
    {
        return match ($type) {
            self::TYPE_A => $this->decodeA($data, $offset, $rdlength),
            self::TYPE_AAAA => $this->decodeAAAA($data, $offset, $rdlength),
            self::TYPE_NS => $this->decodeNS($data, $offset),
            self::TYPE_SOA => $this->decodeSOA($data, $offset),
            self::TYPE_DS => $this->decodeDS($data, $offset, $rdlength),
            self::TYPE_DNSKEY => $this->decodeDNSKEY($data, $offset, $rdlength),
            self::TYPE_RRSIG => $this->decodeRRSIG($data, $offset, $rdlength),
            self::TYPE_NSEC => $this->decodeNSEC($data, $offset, $rdlength),
            self::TYPE_NSEC3 => $this->decodeNSEC3($data, $offset, $rdlength),
            default => $this->decodeHex($data, $offset, $rdlength),
        };
    }

    private function decodeA(string $data, int $offset, int $rdlength): string
    {
        if ($rdlength !== 4) return '';
        return inet_ntop(substr($data, $offset, 4));
    }

    private function decodeAAAA(string $data, int $offset, int $rdlength): string
    {
        if ($rdlength !== 16) return '';
        return inet_ntop(substr($data, $offset, 16));
    }

    private function decodeNS(string $data, int $offset): string
    {
        return $this->decodeName($data, $offset);
    }

    private function decodeSOA(string $data, int &$offset): string
    {
        $mname = $this->decodeName($data, $offset);
        $rname = $this->decodeName($data, $offset);
        $fields = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminimum', substr($data, $offset, 20));
        $offset += 20;
        return "{$mname} {$rname} {$fields['serial']} {$fields['refresh']} {$fields['retry']} {$fields['expire']} {$fields['minimum']}";
    }

    private function decodeDS(string $data, int $offset, int $rdlength): string
    {
        if ($rdlength < 4) return '';
        $fields = unpack('nkeytag/Calgorithm/CdigestType', substr($data, $offset, 4));
        $digest = strtoupper(bin2hex(substr($data, $offset + 4, $rdlength - 4)));
        return "{$fields['keytag']} {$fields['algorithm']} {$fields['digestType']} {$digest}";
    }

    private function decodeDNSKEY(string $data, int $offset, int $rdlength): string
    {
        if ($rdlength < 4) return '';
        $fields = unpack('nflags/Cprotocol/Calgorithm', substr($data, $offset, 4));
        $publicKey = base64_encode(substr($data, $offset + 4, $rdlength - 4));
        return "{$fields['flags']} {$fields['protocol']} {$fields['algorithm']} {$publicKey}";
    }

    private function decodeRRSIG(string $data, int $offset, int $rdlength): string
    {
        if ($rdlength < 18) return '';
        $end = $offset + $rdlength;
        $fields = unpack('ntypeCovered/Calgorithm/Clabels/NoriginalTtl/NsigExpiration/NsigInception/nkeyTag', substr($data, $offset, 18));
        $off = $offset + 18;
        $signer = $this->decodeName($data, $off);
        $signatureLen = $end - $off;
        $signature = $signatureLen > 0 ? base64_encode(substr($data, $off, $signatureLen)) : '';

        $typeName = self::TYPE_NAME[$fields['typeCovered']] ?? "TYPE{$fields['typeCovered']}";

        // Format timestamps as YYYYMMDDHHmmss
        $expStr = $this->formatTimestamp($fields['sigExpiration']);
        $incStr = $this->formatTimestamp($fields['sigInception']);

        return "{$typeName} {$fields['algorithm']} {$fields['labels']} {$fields['originalTtl']} {$expStr} {$incStr} {$fields['keyTag']} {$signer} {$signature}";
    }

    private function decodeNSEC(string $data, int $offset, int $rdlength): string
    {
        $end = $offset + $rdlength;
        $off = $offset;
        $nextDomain = $this->decodeName($data, $off);
        $types = $this->decodeTypeBitmap($data, $off, $end - $off);
        return "{$nextDomain} " . implode(' ', $types);
    }

    private function decodeNSEC3(string $data, int $offset, int $rdlength): string
    {
        // Simplified NSEC3 decoding
        if ($rdlength < 5) return '';
        return '(NSEC3 data)';
    }

    private function decodeHex(string $data, int $offset, int $rdlength): string
    {
        return '\\# ' . $rdlength . ' ' . bin2hex(substr($data, $offset, $rdlength));
    }

    /** Decode type bitmap (NSEC/NSEC3) */
    private function decodeTypeBitmap(string $data, int $offset, int $length): array
    {
        $types = [];
        $end = $offset + $length;
        while ($offset + 2 <= $end) {
            $window = ord($data[$offset]);
            $bitmapLen = ord($data[$offset + 1]);
            $offset += 2;
            for ($i = 0; $i < $bitmapLen && $offset + $i < $end; $i++) {
                $byte = ord($data[$offset + $i]);
                for ($bit = 0; $bit < 8; $bit++) {
                    if ($byte & (0x80 >> $bit)) {
                        $typeNum = $window * 256 + $i * 8 + $bit;
                        $types[] = self::TYPE_NAME[$typeNum] ?? "TYPE{$typeNum}";
                    }
                }
            }
            $offset += $bitmapLen;
        }
        return $types;
    }

    /**
     * Decode a DNS name with compression support.
     */
    private function decodeName(string $data, int &$offset): string
    {
        $labels = [];
        $jumped = false;
        $savedOffset = 0;
        $maxLen = strlen($data);
        $iterations = 0;

        while ($offset < $maxLen && $iterations++ < 128) {
            $len = ord($data[$offset]);

            if ($len === 0) {
                $offset++;
                break;
            }

            // Compression pointer
            if (($len & 0xC0) === 0xC0) {
                if (!$jumped) {
                    $savedOffset = $offset + 2;
                }
                $pointer = (($len & 0x3F) << 8) | ord($data[$offset + 1]);
                $offset = $pointer;
                $jumped = true;
                continue;
            }

            $offset++;
            $labels[] = substr($data, $offset, $len);
            $offset += $len;
        }

        if ($jumped) {
            $offset = $savedOffset;
        }

        $name = implode('.', $labels);
        return $name === '' ? '.' : $name . '.';
    }

    private function formatTimestamp(int $ts): string
    {
        return gmdate('YmdHis', $ts);
    }
}
