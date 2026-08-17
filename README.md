# WebHunter

A Rust-based web vulnerability scanner for OWASP Top 10 issues.

## Scanners

Twelve scanners are dispatchable via `--scanner`; each writes a markdown
report on findings. `xss` additionally runs a DOM-XSS analysis phase that
reports separately.

| # | Scanner | Flag | Report file |
|---|---------|------|-------------|
| 0 | XSS (reflected) | `xss` | `XSS-output.md` |
| 1 | Open Directory | `dir` | `Open-Directories-output.md` |
| 2 | File Inclusion (LFI/RFI) | `file` | `File-Inclusion-output.md` |
| 3 | SQL Injection | `sql` | `SQL-Injection-output.md` |
| 4 | 403/401 Bypass | `bypass` (or `403`) | `403-Bypass-output.md` |
| 5 | CSRF | `csrf` | `CSRF-output.md` |
| 6 | Auth Bypass | `auth` | `Authentication-Bypass-output.md` |
| 7 | Access Control / IDOR | `bac` | `Access-Control-output.md` |
| 8 | Blind XSS (OOB) | `blind` | `Blind-XSS-output.md` |
| 9 | Exposed Files | `exposed` | `Exposed-Files-output.md` |
| 10 | CORS Misconfiguration | `cors` | `CORS-Misconfiguration-output.md` |
| 11 | SSRF | `ssrf` | `SSRF-output.md` |
| 12 | Open Redirect | `redirect` | `Open-Redirect-output.md` |

DOM XSS (inside the `xss` arm): `DOM-XSS-output.md`.

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
| `--target-list <FILE>` | File with URLs, one per line (prompts for concurrency) |
| `-s, --scanner <NAME>` | Scanner flag from the table above |
| `-w, --wordlist <FILE>` | Custom wordlist |
| `--max-depth <N>` | Max crawl depth (default: 2) |
| `--max-urls <N>` | Max URLs to crawl (default: 50) |
| `--no-crawl` | Scan the target URL directly, skip crawling |
| `--force-install` | Force install the `feroxbuster` binary |

An unknown `--scanner` value silently falls back to XSS.

### Rate limiting

- Non-interactive runs: fixed **5 RPS**.
- Interactive runs: prompted, capped at 100 RPS, warned above 5.
- All requests use a shared client with a **10-second timeout**
  (`http_client()` in `main.rs`), so a hung response can't stall a scan.

## Architecture

Modules under `src/`, as wired in `main.rs`:

| Module | Role |
|--------|------|
| `main.rs` | CLI parsing, scanner dispatch, crawl orchestration |
| `crawler.rs` | BFS crawl, link + form extraction |
| `rate_limiter.rs` | Per-request delay throttle |
| `inject.rs` | Shared payload-injection + finding-reporting helpers |
| `form.rs` | Form/input parsing shared by scanners |
| `reporter.rs` | Markdown report generation, `HOST_PORT/` output dirs |
| `xss.rs` / `dom_xss_scanner.rs` | Reflected + DOM XSS detection |
| `sql_injection_scanner.rs` | Error / boolean / time-based SQLi |
| `file_inclusion_scanner.rs` | LFI/RFI via traversal + wrappers |
| `csrf_scanner.rs` | Missing anti-CSRF token detection |
| `auth_bypass_scanner.rs` | SQLi login bypass, default credentials |
| `access_control_scanner.rs` | IDOR, forced browsing, method override |
| `bypass_403.rs` | 403/401 bypass techniques |
| `cors_scanner.rs` | Wildcard/null/arbitrary origin checks |
| `ssrf_scanner.rs` | Localhost, cloud metadata, internal IPs |
| `exposed_files_scanner.rs` | Source maps, debug endpoints |
| `blind_xss_scanner.rs` / `blind_xss_server.rs` | OOB blind XSS + local callback server |
| `dir_scanner.rs` | Directory brute-force via `feroxbuster` |
| `open_redirect_scanner.rs` | Open redirect detection (3xx + client-side markers) |
| `dependency_manager.rs` | `feroxbuster` detection / install |
| `animation.rs` | Intro banner |

## Building

```bash
cargo build --release
./target/release/webhunter --scanner xss --target https://example.com --no-crawl
```

The `dir` scanner shells out to the external `feroxbuster` binary; it must be
installed separately or fetched with `--force-install`. All other scanners
are self-contained.

## Testing

```bash
cargo test        # 73 tests
cargo clippy -- -D warnings
```

## Wordlists

Payload wordlists live in `wordlists/`:

| Directory / file | Purpose |
|------------------|---------|
| `xss/` | 7 payload files: original, filter/WAF bypass, obfuscation, polyglots, PortSwigger event handlers, alert vectors |
| `sql_injection/` | boolean pairs, error-based, time-based, original |
| `file_inclusion/` | path traversal, php wrappers, original |
| `ssrf/payloads.txt` | localhost, cloud metadata, internal IPs |
| `exposed_files/` | source maps, debug endpoints |
| `bypass_403/` | header payloads, URL payloads, directory list |
| `auth_bypass/` | default credentials, SQLi login bypass |
| `access_control/` | sensitive paths |
| `open_redirect.txt` | redirect payloads (scheme-relative, encoded, JS) |
| `directories.txt`, `files.txt`, `methods.txt`, `http_headers.txt`, `user_agents.txt` | shared lists |

Scanners auto-discover `.txt` files in their wordlist directory.

## Reports

Reports are written to `<HOST>_<PORT>/` (dots converted to underscores),
with one markdown file per vulnerability class (exact filenames in the
scanner table above):

```
freebuff_com_443/
├── XSS-output.md
├── SQL-Injection-output.md
└── ...
```

## Dependencies

Runtime (`Cargo.toml`): `tokio`, `reqwest`, `clap`, `serde`, `serde_json`,
`scraper`, `url`, `chrono`, `dialoguer`, `indicatif`, `colored`,
`crossterm`, `figlet-rs`, `rand`, `html-escape`, `axum`, `tower`, `uuid`.

Dev: `mockito`, `tokio-test`, `tempfile`.

## Warning

Only scan targets you own or have permission to test. Unauthorized scanning
is illegal.

## License

Apache-2.0
