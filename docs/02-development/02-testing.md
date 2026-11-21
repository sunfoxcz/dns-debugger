# Testing

Test domains and expected output for verifying the DNSSEC Debugger works correctly.

## Test Domains

### google.com

Unsigned domain under the signed `.com` zone. Expect passing DNSSEC checks for the root and `.com` zones and warnings about missing DS and DNSKEY records for `google.com`.

Expected chain: `.` -> `com` -> `google.com` -> per-nameserver checks.

### 244.98.176.in-addr.arpa

Reverse DNS zone with DNSSEC. Tests `in-addr.arpa` zone hierarchy.

Expected chain: `.` -> `arpa` -> `in-addr.arpa` -> `176.in-addr.arpa` -> `98.176.in-addr.arpa`
-> `244.98.176.in-addr.arpa` -> per-nameserver checks.

### 239.0.81.in-addr.arpa

Unsigned reverse DNS zone. Tests warning behavior for zones without DNSSEC.

Expected warnings:

- No DS records found for `239.0.81.in-addr.arpa`
- No DNSKEY records found
- No NSEC records in response
- No RRSIGs found

## Comparing with Verisign

The output should closely match the
[Verisign Labs DNSSEC Debugger](https://dnssec-debugger.verisignlabs.com/).
Key behaviors to verify:

- Green circles for verified checks
- Orange circles for missing records (warnings)
- Red circles for verification failures (errors)
- Unsigned zones show warnings, not OK status for missing records

## Next Steps

- [Getting Started](01-getting-started.md) - How to run the project
