# dnsq

Small DNS query client in C. Speaks raw DNS over UDP with automatic TCP fallback when the answer is truncated. Needs only a C compiler and POSIX sockets.

    make
    ./dnsq github.com
    ./dnsq -s 1.1.1.1 github.com MX
    ./dnsq -q -s 9.9.9.9 example.com TXT
    ./dnsq -x 8.8.8.8
    ./dnsq -T -s 1.1.1.1 -p 53 example.com AAAA

Types: A NS CNAME SOA PTR MX TXT AAAA SRV CAA.

## Options

| Flag | Meaning |
|------|---------|
| `-s IP` | Server address, IPv4 or IPv6 (default: first nameserver in `/etc/resolv.conf`) |
| `-p PORT` | Server port, 1-65535 (default 53) |
| `-t MS` | Timeout per attempt, 100-30000 (default 2000) |
| `-r N` | UDP retries, 0-5 (default 2) |
| `-T` | TCP only |
| `-x` | Reverse lookup, the name is an IP address |
| `-q` | Print rdata only |
| `-v` | Also print authority and additional sections |

Exit codes: `0` answers found, `1` no answers or DNS error status, `2` usage error, `3` network or protocol error.

## Hardening

- Query ID comes from `/dev/urandom`. Responses are accepted only if the ID, the QR bit, opcode, question name (case-insensitive), type and class all match, so off-path spoofed packets are ignored and the client keeps waiting for the real answer.
- Name decompression only follows pointers that point backward, with a jump limit and a 255 byte name limit, so pointer loops and forward references are rejected.
- Every read is bounds-checked against the packet and each record's RDLENGTH. Control and non-ASCII bytes in names and TXT data are escaped as `\DDD` before printing.
- Built with `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, PIE and full RELRO.
- The server must be an IP literal, so the tool never needs a resolver to find its resolver.
- Internationalized names are not converted. Pass punycode (`xn--...`).

## License

MIT
