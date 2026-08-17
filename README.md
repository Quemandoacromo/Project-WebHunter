# WebHunter

A Rust-based web vulnerability scanner for OWASP Top 10 issues.

## Scanners

| Scanner | Flag | Notes |
|---------|------|-------|
| XSS | `xss` | Reflected + DOM-based, script-context aware |
| SQL Injection | `sql` | Error, boolean, and time-based (baseline-relative timing) |
| CSRF | `csrf` | Missing anti-CSRF token detection |
| File Inclusion | `file` | LFI/RFI via path traversal and wrappers |
| Auth Bypass | `auth` | SQLi login bypass and default credentials |
| Access Control | `bac` | IDOR, forced browsing, HTTP method override |
| 403/401 Bypass | `bypass` | Header injection, method switching, URL manipulation |
| Directory | `dir` | Brute-force via external `feroxbuster` binary |
| CORS | `cors` | Wildcard/null/arbitrary origin checks |
| SSRF | `ssrf` | Localhost, cloud metadata, internal IPs |
| Exposed Files | `exposed` | Source maps and debug endpoint fuzzing |
| Blind XSS | `blind` | OOB callbacks via local listener |

## Usage

```bash
# Interactive mode (prompts for target, scanner, RPS)
cargo run

# Direct scan, no crawling
cargo run -- --scanner cors --target https://example.com --no-crawl

# Crawl then scan
cargo run -- --scanner sql --target https://example.com
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-t, --target <URL>` | Single target URL |
| `--target-list <FILE>` | File with URLs, one per line |
| `-s, --scanner <NAME>` | Scanner to run (table above) |
| `-w, --wordlist <FILE>` | Custom wordlist |
| `--max-depth <N>` | Max crawl depth (default: 2) |
| `--max-urls <N>` | Max URLs to crawl (default: 50) |
| `--no-crawl` | Scan the target URL directly, skip crawling |
| `--force-install` | Force install `feroxbuster` |

Rate limiting: non-interactive runs use a fixed 5 RPS. Interactive mode
prompts for RPS (capped at 100 with a warning above 5). All requests use a
10-second timeout, so hung responses can't stall a scan.

## Building

```bash
cargo build --release
./target/release/webhunter --scanner xss --target https://example.com --no-crawl
```

The `dir` scanner shells out to `feroxbuster`; it must be installed or fetched
with `--force-install`. All other scanners are self-contained.

## Testing

```bash
cargo test        # 73 tests
cargo clippy -- -D warnings
```

## Wordlists

Payload wordlists live in `wordlists/`:

- `xss/` — payloads, event handlers, polyglots
- `sql_injection/` — boolean pairs, error, time-based
- `file_inclusion/` — path traversal, php wrappers
- `ssrf/` — localhost, cloud metadata, internal IPs
- `exposed_files/` — source maps and debug endpoints

Payloads are loaded per-scanner; adding a `.txt` file to a scanner's wordlist
directory extends that scanner's payload set.

## Reports

Markdown reports are written to `HOST_PORT/` (dots converted to underscores):

```
freebuff_com_443/
├── XSS-output.md
├── SQL-Injection-output.md
└── ...
```

## Warning

Only scan targets you own or have permission to test. Unauthorized scanning
is illegal.

## License

Apache-2.0
