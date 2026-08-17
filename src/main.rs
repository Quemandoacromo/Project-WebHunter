use clap::Parser;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

mod access_control_scanner;
mod animation;
mod auth_bypass_scanner;
mod blind_xss_scanner;
mod blind_xss_server;
mod bypass_403;
mod cors_scanner;
mod crawler;
mod csrf_scanner;
mod dependency_manager;
mod dir_scanner;
mod dom_xss_scanner;
mod exposed_files_scanner;
mod file_inclusion_scanner;
mod form;
mod inject;
mod rate_limiter;
mod reporter;
mod sql_injection_scanner;
mod ssrf_scanner;
mod xss;

struct Config {
    request_delay: Duration,
}

fn configure_rate_limit() -> Config {
    loop {
        let rps_input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter Requests Per Second (RPS)")
            .default("5".into())
            .interact_text()
            .unwrap();

        match rps_input.trim().parse::<u64>() {
            Ok(mut rps) => {
                if rps == 0 {
                    println!("{}", "RPS cannot be 0. Please enter a valid number.".red());
                    continue;
                }
                if rps > 100 {
                    println!(
                        "{}",
                        "RPS is capped at 100 to prevent overwhelming the target server.".yellow()
                    );
                    rps = 100;
                }
                println!("Running at {} RPS.", rps);
                if rps > 5 {
                    println!("{}", "[WARNING] Rates above 5 RPS may get your IP blacklisted. Proceed with caution.".yellow());
                }
                let delay_ms = 1000 / rps;
                return Config {
                    request_delay: Duration::from_millis(delay_ms),
                };
            }
            Err(_) => {
                println!("{}", "Invalid input. Please enter a number.".red());
            }
        }
    }
}

/// Crawl the target, or return the target URL directly in --no-crawl mode.
/// `no_crawl_ok` selects whether the branch honors --no-crawl (the scanners
/// that need a crawl regardless pass `false`).
async fn collect_scan_targets(
    cli: &Cli,
    url: &Url,
    m: &MultiProgress,
    sty: &ProgressStyle,
    rate_limiter: &Arc<rate_limiter::RateLimiter>,
    no_crawl_ok: bool,
) -> Result<(Vec<Url>, Vec<form::Form>), reqwest::Error> {
    if no_crawl_ok && cli.no_crawl {
        println!("[*] No-crawl mode: scanning target URL directly");
        return Ok((vec![url.clone()], Vec::new()));
    }

    let mut crawler =
        crawler::Crawler::with_limits(url.clone(), Arc::clone(rate_limiter), cli.max_depth, cli.max_urls);
    let pb_crawl = m.add(ProgressBar::new(100));
    pb_crawl.set_style(sty.clone());

    match crawler.crawl(&pb_crawl).await {
        Ok((urls, forms)) => {
            pb_crawl.finish_with_message("Crawling complete");
            Ok((urls, forms))
        }
        Err(e) => {
            pb_crawl.finish_with_message(format!("Crawling failed: {}", e));
            eprintln!("Error crawling: {}", e);
            Err(e)
        }
    }
}

fn box_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(e)
}

/// Run a scanner behind a progress bar, with a uniform success/error message.
/// The closure takes the `ProgressBar` by value (it is a cheap Arc clone), so
/// the returned future owns everything it touches.
async fn run_with_progress<F, Fut>(
    name: &str,
    total: u64,
    m: &MultiProgress,
    sty: &ProgressStyle,
    scan: F,
) where
    F: FnOnce(ProgressBar) -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
{
    let pb = m.add(ProgressBar::new(total));
    pb.set_style(sty.clone());
    let pb_scan = pb.clone();
    match scan(pb_scan).await {
        Ok(()) => pb.finish_with_message(format!("{} complete.", name)),
        Err(e) => {
            pb.finish_with_message(format!("{} failed: {}", name, e));
            eprintln!("Error during {} scan: {}", name, e);
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about,
    long_about = "A comprehensive web vulnerability scanner."
)]
struct Cli {
    /// The target website URL to scan
    #[arg(short, long)]
    target: Option<String>,

    /// Path to a file containing a list of target URLs
    #[arg(long)]
    target_list: Option<String>,

    /// The type of scanner to use (xss, dir, file, sql, bypass, cors, ssrf, exposed)
    #[arg(short, long)]
    scanner: Option<String>,

    /// Path to a custom wordlist file
    #[arg(short, long)]
    wordlist: Option<String>,

    /// Force install feroxbuster
    #[arg(long)]
    force_install: bool,

    /// Maximum crawl depth (default: 2)
    #[arg(long, default_value_t = 2)]
    max_depth: u32,

    /// Maximum URLs to crawl (default: 50)
    #[arg(long, default_value_t = 50)]
    max_urls: u32,

    /// Skip crawling and scan only the target URL directly
    #[arg(long)]
    no_crawl: bool,
}

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");
    animation::run_intro_animation();
    let cli = Cli::parse();

    let config = if cli.scanner.is_some() {
        println!("Running at 5 RPS (default for non-interactive mode).");
        Config {
            request_delay: Duration::from_millis(200), // 5 RPS
        }
    } else {
        configure_rate_limit()
    };
    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(config.request_delay));

    let targets = if let Some(ref target_list) = cli.target_list {
        read_lines(target_list).unwrap_or_else(|_| panic!("Failed to read target list file"))
    } else {
        vec![match cli.target.as_ref() {
            Some(target) => target.clone(),
            None => match Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter the target website URL")
                .interact_text()
            {
                Ok(target) => target,
                Err(_) => {
                    eprintln!("Could not read target URL. Are you running in a non-interactive shell? Try specifying a target with the --target argument.");
                    return;
                }
            },
        }]
    };

    let concurrency = if cli.target_list.is_some() {
        let num: usize = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("How many websites would you like to run through at a time?")
            .interact_text()
            .unwrap_or(1);
        println!("{}", "[WARNING] Concurrent scans can multiply your RPS and may get your IP blacklisted. Proceed with caution.".yellow());
        num
    } else {
        1
    };

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = vec![];

    for target_url in targets {
        let mut url_with_scheme = target_url.clone();
        if !url_with_scheme.starts_with("http://") && !url_with_scheme.starts_with("https://") {
            url_with_scheme = format!("http://{}", url_with_scheme);
        }

        let cli = Arc::new(cli.clone());
        let rate_limiter = Arc::clone(&rate_limiter);
        let semaphore = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            run_scan(&cli, &rate_limiter, &url_with_scheme).await;
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

async fn run_scan(cli: &Cli, rate_limiter: &Arc<rate_limiter::RateLimiter>, target_url: &str) {
    let selection = match &cli.scanner {
        Some(scanner) => match scanner.to_lowercase().as_str() {
            "xss" => 0,
            "dir" => 1,
            "file" => 2,
            "sql" => 3,
            "bypass" | "403" => 4,
            "csrf" => 5,
            "auth" => 6,
            "bac" => 7,
            "blind" => 8,
            "exposed" => 9,
            "cors" => 10,
            "ssrf" => 11,
            _ => 0,
        },
        None => match Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .items(&[
                "XSS",
                "Open Directory",
                "File Inclusion",
                "SQL Injection",
                "403/401 Bypass",
                "CSRF",
                "Authentication Bypass",
                "Broken Access Control",
                "Blind XSS (Out-of-Band)",
                "Exposed Files (Source Maps & Debug Endpoints)",
                "CORS Misconfiguration",
                "SSRF (Server-Side Request Forgery)",
            ])
            .interact()
        {
            Ok(selection) => selection,
            Err(_) => {
                eprintln!("Could not read selection. Are you running in a non-interactive shell? Try specifying a scanner with the --scanner argument.");
                return;
            }
        },
    };

    let m = MultiProgress::new();
    let sty = if selection == 0 {
        // XSS Scanner
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("#>-")
    } else {
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
        )
        .unwrap()
        .progress_chars("#>-")
    };

    let url = match Url::parse(target_url) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            eprintln!(
                "Error: Invalid URL. Please provide an absolute URL (e.g., http://example.com)"
            );
            return;
        }
        Err(e) => {
            eprintln!("Error: Invalid URL: {}", e);
            return;
        }
    };

    let reporter = Arc::new(reporter::Reporter::new(url.clone()));

    match selection {
        0 => {
            // XSS Scanner - Ask user which type
            let xss_type = if cli.scanner.is_some() {
                // Non-interactive: default to reflected/stored
                0
            } else {
                Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select XSS scan type")
                    .items(&["Reflected/Stored XSS", "DOM-based XSS"])
                    .default(0)
                    .interact()
                    .unwrap_or(0)
            };

            if xss_type == 0 {
                // Reflected/Stored XSS scanner
                let (found_urls, found_forms) =
                    match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, true).await {
                        Ok(targets) => targets,
                        Err(_) => return,
                    };

                let scanner = xss::XssScanner::new(
                    found_urls.clone(),
                    found_forms.clone(),
                    &reporter,
                    Arc::clone(rate_limiter),
                );
                let num_url_params = found_urls
                    .iter()
                    .filter(|u| u.query_pairs().count() > 0)
                    .count();
                let num_form_inputs = found_forms.iter().map(|f| f.inputs.len()).sum::<usize>();
                let total_checks = (num_url_params + num_form_inputs) * scanner.payloads_count();

                if total_checks == 0 {
                    println!("No parameters or forms to test for XSS.");
                    m.clear().unwrap();
                    return;
                }

                println!("Starting Reflected/Stored XSS scan...");
                if let Err(e) = scanner.scan().await {
                    eprintln!("Error scanning for XSS: {}", e);
                } else {
                    println!("XSS scan complete.");
                }
            } else {
                // DOM-based XSS scanner
                let (found_urls, _) =
                    match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                        Ok(targets) => targets,
                        Err(_) => return,
                    };

                println!(
                    "Starting DOM-based XSS analysis on {} pages...",
                    found_urls.len()
                );

                let dom_scanner =
                    dom_xss_scanner::DomXssScanner::new(&reporter, Arc::clone(rate_limiter));

                // Fetch and analyze each page for DOM XSS
                let client = reqwest::Client::new();
                for page_url in found_urls {
                    rate_limiter.wait().await;

                    match client.get(page_url.as_str()).send().await {
                        Ok(response) => {
                            if let Ok(html) = response.text().await {
                                if let Err(e) = dom_scanner.scan(page_url.clone(), html).await {
                                    eprintln!("Error analyzing {}: {}", page_url, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error fetching {}: {}", page_url, e);
                        }
                    }
                }

                println!("DOM XSS analysis complete.");
            }
        }
        1 => {
            if cli.force_install || !dependency_manager::is_feroxbuster_installed() {
                let confirm = if cli.force_install || cli.scanner.is_some() {
                    0
                } else {
                    Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Feroxbuster is not installed. Would you like to install it now?")
                        .items(&["Yes", "No"])
                        .interact()
                        .unwrap()
                };

                if confirm == 0 {
                    let pb_install = m.add(ProgressBar::new_spinner());
                    pb_install.set_style(sty.clone());
                    pb_install.set_message("Installing feroxbuster...");
                    if let Err(e) = dependency_manager::install_feroxbuster().await {
                        pb_install
                            .finish_with_message(format!("Failed to install feroxbuster: {}", e));
                        return;
                    }
                    pb_install.finish_with_message("Feroxbuster installed successfully");
                } else {
                    println!("Feroxbuster is required for the Open Directory Scanner to work.");
                    return;
                }
            }

            let pb_dir = m.add(ProgressBar::new_spinner());
            pb_dir.set_style(sty.clone());
            let dir_scanner =
                dir_scanner::DirScanner::new(url.clone(), &pb_dir, cli.wordlist.clone(), &reporter);

            if let Err(e) = dir_scanner.scan().await {
                pb_dir.finish_with_message(format!("Directory scan failed: {}", e));
                eprintln!("Error scanning for directories: {}", e);
            } else {
                pb_dir.finish_with_message("Directory scan complete");
            }
        }
        2 => {
            let (found_urls, found_forms) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let scanner = file_inclusion_scanner::FileInclusionScanner::new(
                found_urls.clone(),
                found_forms.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );
            let total = (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64;

            run_with_progress("File Inclusion scan", total, &m, &sty, |pb| async move {
                scanner.scan(&pb).await.map_err(box_err)
            })
            .await;
        }
        3 => {
            let (found_urls, found_forms) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let scanner = sql_injection_scanner::SqlInjectionScanner::new(
                found_urls.clone(),
                found_forms.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );
            let total = (found_urls.len() * scanner.payloads_count()
                + found_forms.len() * scanner.payloads_count()) as u64;

            run_with_progress("SQL Injection scan", total, &m, &sty, |pb| async move {
                scanner.scan(&pb).await.map_err(box_err)
            })
            .await;
        }
        4 => {
            let pb_bypass = m.add(ProgressBar::new(100));
            pb_bypass.set_style(sty.clone());
            let bypass_scanner = bypass_403::BypassScanner::new(
                url.clone(),
                &pb_bypass,
                &reporter,
                Arc::clone(rate_limiter),
            );

            if let Err(e) = bypass_scanner.scan().await {
                pb_bypass.finish_with_message(format!("403 bypass scan failed: {}", e));
                eprintln!("Error scanning for 403 bypasses: {}", e);
            } else {
                pb_bypass.finish_with_message("403 bypass scan complete");
            }
        }
        5 => {
            let (found_urls, found_forms) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let scanner = csrf_scanner::CsrfScanner::new(
                found_forms.clone(),
                found_urls.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            println!("Starting CSRF scan on {} forms...", found_forms.len());

            if let Err(e) = scanner.scan().await {
                eprintln!("Error scanning for CSRF: {}", e);
            } else {
                println!("CSRF scan complete.");
            }
        }
        6 => {
            let (_, found_forms) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let scanner = auth_bypass_scanner::AuthBypassScanner::new(
                found_forms.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            let total_checks = scanner.payloads_count();

            if total_checks == 0 {
                println!("No login forms found to test.");
                m.clear().unwrap();
                return;
            }

            println!("Starting Authentication Bypass scan...");
            run_with_progress("Authentication Bypass", total_checks as u64, &m, &sty, |pb| async move {
                scanner.scan(&pb).await.map_err(box_err)
            })
            .await;
        }
        7 => {
            let (found_urls, _) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let mut scanner = access_control_scanner::AccessControlScanner::new(
                url.clone(),
                found_urls.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            // Load sensitive paths
            if let Ok(paths) = read_lines("wordlists/access_control/sensitive_paths.txt") {
                scanner.load_sensitive_paths(paths);
            } else {
                eprintln!("Warning: Could not load sensitive_paths.txt. Forced browsing check will be limited.");
            }

            println!("Starting Broken Access Control scan...");
            // Estimate progress: sensitive paths + (discovered urls * 2 for IDOR/Method)
            let total_checks = 20 + (found_urls.len() * 2);
            run_with_progress("Access Control scan", total_checks as u64, &m, &sty, |pb| async move {
                scanner.scan(&pb).await.map_err(box_err)
            })
            .await;
        }
        8 => {
            // Blind XSS Scanner
            let (found_urls, found_forms) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, false).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            // Set up callback server
            let callback_port = 8080;
            let callback_url = format!("http://localhost:{}", callback_port);
            let payload_tracker = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

            // Spawn callback server in background
            let tracker_clone = payload_tracker.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    blind_xss_server::start_callback_server(callback_port, tracker_clone).await
                {
                    eprintln!("Callback server error: {}", e);
                }
            });

            // Give server time to start
            tokio::time::sleep(Duration::from_millis(500)).await;

            println!("Starting Blind XSS scan...");
            println!("Callback server listening on: {}", callback_url);

            let scanner = blind_xss_scanner::BlindXssScanner::new(
                found_urls.clone(),
                found_forms.clone(),
                callback_url,
                payload_tracker.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            // Estimate payload count (4 variants per parameter/input)
            let param_count: usize = found_urls.iter().map(|u| u.query_pairs().count()).sum();
            let input_count: usize = found_forms.iter().map(|f| f.inputs.len()).sum();
            let total_payloads = (param_count + input_count) * 4;

            let pb = m.add(ProgressBar::new(total_payloads as u64));
            pb.set_style(sty.clone());
            if let Err(e) = scanner.scan(&pb).await {
                pb.finish_with_message(format!("Payload injection failed: {}", e));
                eprintln!("Error during payload injection: {}", e);
            } else {
                pb.finish_with_message("Payload injection complete.");
            }

            // Wait for delayed callbacks
            println!("\n[*] Waiting 60 seconds for callbacks...");
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Report findings
            scanner.report_findings().await;
            println!("[*] Blind XSS scan complete.");
        }
        9 => {
            // Exposed Files Scanner
            let (found_urls, _) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, true).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let mut scanner = exposed_files_scanner::ExposedFilesScanner::new(
                url.clone(),
                found_urls.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            let total_checks = scanner.targets_count();

            if total_checks == 0 {
                println!("No URLs found to check.");
                m.clear().unwrap();
                return;
            }

            println!("Starting Exposed Files scan...");
            run_with_progress("Exposed Files scan", total_checks as u64, &m, &sty, |pb| async move {
                scanner.scan(&pb).await
            })
            .await;
        }
        10 => {
            // CORS Scanner
            let (found_urls, _) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, true).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let mut scanner = cors_scanner::CorsScanner::new(
                url.clone(),
                found_urls.clone(),
                &reporter,
                Arc::clone(rate_limiter),
            );

            let total_checks = scanner.targets_count();

            if total_checks == 0 {
                println!("No URLs found to check.");
                m.clear().unwrap();
                return;
            }

            println!("Starting CORS Misconfiguration scan...");
            run_with_progress("CORS scan", total_checks as u64, &m, &sty, |pb| async move {
                scanner.scan(&pb).await
            })
            .await;
        }
        11 => {
            // SSRF Scanner
            let (found_urls, _) =
                match collect_scan_targets(cli, &url, &m, &sty, rate_limiter, true).await {
                    Ok(targets) => targets,
                    Err(_) => return,
                };

            let callback_port = 8080;
            let callback_url = format!("http://localhost:{}", callback_port);
            let payload_tracker = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

            let tracker_clone = payload_tracker.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    blind_xss_server::start_callback_server(callback_port, tracker_clone).await
                {
                    eprintln!("Callback server error: {}", e);
                }
            });

            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut scanner = ssrf_scanner::SsrfScanner::new(
                url.clone(),
                found_urls.clone(),
                &reporter,
                Arc::clone(rate_limiter),
                callback_url,
            );

            let total_checks = scanner.targets_count();

            if total_checks == 0 {
                println!("No URLs found to check for SSRF.");
                m.clear().unwrap();
                return;
            }

            println!("Starting SSRF scan...");
            println!(
                "Callback server listening on: {}",
                scanner.get_callback_url()
            );
            run_with_progress("SSRF scan", total_checks as u64, &m, &sty, |pb| async move {
                scanner.scan(&pb).await
            })
            .await;
        }
        _ => {}

    }
}
fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    io::BufReader::new(file).lines().collect()
}
