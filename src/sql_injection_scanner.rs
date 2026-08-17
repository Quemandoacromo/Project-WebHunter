use crate::form::Form;
use crate::inject::{inject_form_field, inject_query_param, report_found};
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone)]
pub struct SqlInjectionVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub vuln_type: String,
}

use std::fs;
use std::io::{self, BufRead};

pub struct SqlInjectionScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    error_based_payloads: Vec<String>,
    boolean_based_payloads: Vec<(String, String)>,
    time_based_payloads: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
}

impl<'a> SqlInjectionScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let mut error_based_payloads =
            Self::load_payloads("wordlists/sql_injection/error_based.txt");
        error_based_payloads.extend(Self::load_payloads(
            "wordlists/sql_injection/original_payloads.txt",
        ));
        let boolean_based_payloads =
            Self::load_boolean_payloads("wordlists/sql_injection/boolean_based.txt");
        let time_based_payloads =
            Self::load_payloads("wordlists/sql_injection/time_based.txt");

        Self {
            target_urls,
            forms,
            error_based_payloads,
            boolean_based_payloads,
            time_based_payloads,
            reporter,
            rate_limiter,
        }
    }

    fn load_payloads(path: &str) -> Vec<String> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                payloads.push(line);
            }
        }
        payloads
    }

    fn load_boolean_payloads(path: &str) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        if let Ok(file) = fs::File::open(path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.split("/").collect();
                if parts.len() == 2 {
                    payloads.push((parts[0].to_string(), parts[1].to_string()));
                }
            }
        }
        payloads
    }

    pub fn payloads_count(&self) -> usize {
        self.error_based_payloads.len()
            + self.boolean_based_payloads.len() * 2
            + self.time_based_payloads.len()
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;
        Ok(())
    }

    async fn scan_urls(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = crate::http_client();

        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            for i in 0..query_pairs.len() {
                let mut vulnerable = false;
                for payload in &self.error_based_payloads {
                    if self.test_error_based(&client, url, payload, i, pb).await? {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable {
                    continue;
                }

                for (true_payload, false_payload) in &self.boolean_based_payloads {
                    if self
                        .test_boolean_based(&client, url, true_payload, false_payload, i, pb)
                        .await?
                    {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable {
                    continue;
                }

                // Baseline control: measure the uninjected request's latency
                // once per param so time-based detection compares a delta
                // instead of an absolute threshold. Freebuff.com's Cloudflare
                // jitter (0.11s-2.04s on identical requests) previously tripped
                // a bare >2s check.
                let baseline = self.measure_url_time(&client, url).await;
                for payload in &self.time_based_payloads {
                    if self
                        .test_time_based(&client, url, payload, i, baseline, pb)
                        .await?
                    {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn test_boolean_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        true_payload: &str,
        false_payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let tested_param = query_pairs[param_index].0.clone();
        let true_url = inject_query_param(url, param_index, |value| format!("{}{}", value, true_payload));
        let false_url = inject_query_param(url, param_index, |value| format!("{}{}", value, false_payload));

        self.rate_limiter.wait().await;
        if let (Some(true_response), Some(false_response)) = (
            self.send_get_request(client, &true_url).await,
            self.send_get_request(client, &false_url).await,
        ) {
            if let (Ok(true_body), Ok(false_body)) =
                (true_response.text().await, false_response.text().await)
            {
                // Diff normalized bodies: raw responses differ on every request
                // (random request IDs, CSRF tokens, timestamps) and on reflected
                // payload echoes, so a naive != comparison false-positives on
                // any dynamic page (verified against freebuff.com).
                let true_norm = normalize_boolean_body(&true_body, true_payload);
                let false_norm = normalize_boolean_body(&false_body, false_payload);
                if true_norm != false_norm {
                    let vuln = SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param.clone(),
                        payload: format!("{} / {}", true_payload, false_payload),
                        vuln_type: "Boolean-Based".to_string(),
                    };
                    println!(
                        "[+] SQL Injection Found: {} in {}",
                        vuln.payload, vuln.parameter
                    );
                    self.reporter.report_sql_injection(&vuln);
                    return Ok(true);
                }
            }
        }
        pb.inc(2);
        Ok(false)
    }

    async fn measure_url_time(
        &self,
        client: &reqwest::Client,
        url: &Url,
    ) -> Option<Duration> {
        self.rate_limiter.wait().await;
        let start = Instant::now();
        let ok = self.send_get_request(client, url).await.is_some();
        let elapsed = start.elapsed();
        ok.then_some(elapsed)
    }

    async fn test_time_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        payload: &str,
        param_index: usize,
        baseline: Option<Duration>,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let tested_param = query_pairs[param_index].0.clone();
        let new_url = inject_query_param(url, param_index, |value| format!("{}{}", value, payload));

        self.rate_limiter.wait().await;
        let start = Instant::now();
        let got_response = self.send_get_request(client, &new_url).await.is_some();
        let duration = start.elapsed();

        if got_response && is_time_based_delta(duration, baseline) {
            let vuln = SqlInjectionVulnerability {
                url: url.clone(),
                parameter: tested_param.clone(),
                payload: payload.to_string(),
                vuln_type: "Time-Based".to_string(),
            };
            return Ok(report_found("SQL Injection", &vuln.payload, &vuln.parameter, || {
                self.reporter.report_sql_injection(&vuln);
            }));
        }
        pb.inc(1);
        Ok(false)
    }

    async fn scan_forms(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        let client = crate::http_client();

        for form in &self.forms {
            for i in 0..form.inputs.len() {
                let mut vulnerable = false;
                for payload in &self.error_based_payloads {
                    if self
                        .test_form_error_based(&client, form, payload, i, pb)
                        .await?
                    {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable {
                    continue;
                }

                for (true_payload, false_payload) in &self.boolean_based_payloads {
                    if self
                        .test_form_boolean_based(&client, form, true_payload, false_payload, i, pb)
                        .await?
                    {
                        vulnerable = true;
                        break;
                    }
                }
                if vulnerable {
                    continue;
                }

                // Baseline control for the form's original values.
                let baseline = self.measure_form_time(&client, form).await;
                for payload in &self.time_based_payloads {
                    if self
                        .test_form_time_based(&client, form, payload, i, baseline, pb)
                        .await?
                    {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn test_form_error_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let tested_param = form.inputs[param_index].name.clone();
        let form_data = inject_form_field(form, param_index, |_| payload.to_string());

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        self.rate_limiter.wait().await;
        let response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&form_data).send().await?
        } else {
            client.get(action_url).query(&form_data).send().await?
        };

        pb.inc(1);
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if let Ok(body) = response.text().await {
            if self.is_error_based_vulnerable(&body) {
                let vuln = SqlInjectionVulnerability {
                    url: form.url.clone(),
                    parameter: tested_param.clone(),
                    payload: payload.to_string(),
                    vuln_type: "Error-Based".to_string(),
                };
                return Ok(report_found("SQL Injection", &vuln.payload, &vuln.parameter, || {
                    self.reporter.report_sql_injection(&vuln);
                }));
            }
        }
        Ok(false)
    }

    async fn test_form_boolean_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        true_payload: &str,
        false_payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let tested_param = form.inputs[param_index].name.clone();
        let true_form_data = inject_form_field(form, param_index, |_| true_payload.to_string());
        let false_form_data = inject_form_field(form, param_index, |_| false_payload.to_string());

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        self.rate_limiter.wait().await;
        let true_response = if form.method.to_lowercase() == "post" {
            client
                .post(action_url.clone())
                .form(&true_form_data)
                .send()
                .await?
        } else {
            client
                .get(action_url.clone())
                .query(&true_form_data)
                .send()
                .await?
        };

        if true_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        self.rate_limiter.wait().await;
        let false_response = if form.method.to_lowercase() == "post" {
            client
                .post(action_url)
                .form(&false_form_data)
                .send()
                .await?
        } else {
            client
                .get(action_url)
                .query(&false_form_data)
                .send()
                .await?
        };

        pb.inc(2);
        if false_response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if let (Ok(true_body), Ok(false_body)) =
            (true_response.text().await, false_response.text().await)
        {
            if true_body != false_body {
                let vuln = SqlInjectionVulnerability {
                    url: form.url.clone(),
                    parameter: tested_param.clone(),
                    payload: format!("{} / {}", true_payload, false_payload),
                    vuln_type: "Boolean-Based".to_string(),
                };
                return Ok(report_found("SQL Injection", &vuln.payload, &vuln.parameter, || {
                    self.reporter.report_sql_injection(&vuln);
                }));
            }
        }
        Ok(false)
    }

    async fn measure_form_time(
        &self,
        client: &reqwest::Client,
        form: &Form,
    ) -> Option<Duration> {
        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return None,
        };
        let mut form_data = std::collections::HashMap::new();
        for input in &form.inputs {
            form_data.insert(input.name.clone(), input.value.clone());
        }
        self.rate_limiter.wait().await;
        let start = Instant::now();
        let response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&form_data).send().await
        } else {
            client.get(action_url).query(&form_data).send().await
        };
        let elapsed = start.elapsed();
        match response {
            Ok(r) if r.status() != reqwest::StatusCode::NOT_FOUND => Some(elapsed),
            _ => None,
        }
    }

    async fn test_form_time_based(
        &self,
        client: &reqwest::Client,
        form: &Form,
        payload: &str,
        param_index: usize,
        baseline: Option<Duration>,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let tested_param = form.inputs[param_index].name.clone();
        let form_data = inject_form_field(form, param_index, |_| payload.to_string());

        let action_url = match form.url.join(&form.action) {
            Ok(url) => url,
            Err(_) => return Ok(false),
        };
        self.rate_limiter.wait().await;
        let start = Instant::now();
        let response = if form.method.to_lowercase() == "post" {
            client.post(action_url).form(&form_data).send().await?
        } else {
            client.get(action_url).query(&form_data).send().await?
        };
        let duration = start.elapsed();

        pb.inc(1);
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if is_time_based_delta(duration, baseline) {
            let vuln = SqlInjectionVulnerability {
                url: form.url.clone(),
                parameter: tested_param.clone(),
                payload: payload.to_string(),
                vuln_type: "Time-Based".to_string(),
            };
            println!(
                "[+] SQL Injection Found: {} in {}",
                vuln.payload, vuln.parameter
            );
            self.reporter.report_sql_injection(&vuln);
            return Ok(true);
        }
        Ok(false)
    }

    async fn test_error_based(
        &self,
        client: &reqwest::Client,
        url: &Url,
        payload: &str,
        param_index: usize,
        pb: &ProgressBar,
    ) -> Result<bool, reqwest::Error> {
        let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let tested_param = query_pairs[param_index].0.clone();
        let new_url = inject_query_param(url, param_index, |value| format!("{}{}", value, payload));

        self.rate_limiter.wait().await;
        if let Some(response) = self.send_get_request(client, &new_url).await {
            if let Ok(body) = response.text().await {
                if self.is_error_based_vulnerable(&body) {
                    let vuln = SqlInjectionVulnerability {
                        url: url.clone(),
                        parameter: tested_param.clone(),
                        payload: payload.to_string(),
                        vuln_type: "Error-Based".to_string(),
                    };
                    println!(
                        "[+] SQL Injection Found: {} in {}",
                        vuln.payload, vuln.parameter
                    );
                    self.reporter.report_sql_injection(&vuln);
                    return Ok(true);
                }
            }
        }
        pb.inc(1);
        Ok(false)
    }

    async fn send_get_request(
        &self,
        client: &reqwest::Client,
        url: &Url,
    ) -> Option<reqwest::Response> {
        match client.get(url.clone()).send().await {
            Ok(response) => {
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return None;
                }
                Some(response)
            }
            Err(e) => {
                eprintln!("[!] Error sending GET request to {}: {}", url, e);
                None
            }
        }
    }

    fn is_error_based_vulnerable(&self, body: &str) -> bool {
        let error_patterns = [
            // MySQL
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            // MSSQL
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",
            // Oracle
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            // PostgreSQL
            "ERROR: unterminated quoted string at or near",
            "ERROR: syntax error at or near",
            // SQLite
            "SQLite/JDBCDriver",
            "SQLITE_ERROR",
        ];
        error_patterns.iter().any(|&p| body.contains(p))
    }
}

/// Normalize a response body before boolean-based comparison so that
/// per-request noise cannot masquerade as a SQL behavior difference:
///
/// - the injected payload itself (raw, URL-encoded, and HTML-escaped forms)
///   is replaced with a placeholder, since any page that reflects the request
///   URL would otherwise differ only because of the payload string;
/// - long hexadecimal runs (request IDs, CSRF tokens, hashes) are collapsed;
/// - ISO-8601 / RFC-3339 timestamps are collapsed.
fn normalize_boolean_body(body: &str, payload: &str) -> String {
    // Canonicalize percent- and plus-encoded sequences FIRST: Next.js echoes
    // the request URL in flight data in mixed encodings (%27, %20, and '+' as
    // space), so the raw payload may appear in several byte forms that must
    // all collapse to the same string before the payload replacement.
    let mut normalized = decode_percent_encoding(body);

    // Neutralize the injected payload in every encoding it may appear in.
    let html_payload = html_escape::encode_text(payload).to_string();
    let trimmed = payload.trim();
    let html_trimmed = html_escape::encode_text(trimmed).to_string();
    for form in [payload, trimmed, html_payload.as_str(), html_trimmed.as_str()] {
        if !form.is_empty() {
            normalized = normalized.replace(form, "<PAYLOAD>");
        }
    }

    // Collapse volatile tokens: long hex runs and timestamps.
    let mut result = String::with_capacity(normalized.len());
    let mut hex_run = String::new();
    let bytes = normalized.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // ISO-8601 / RFC-3339: YYYY-MM-DDTHH:MM:SS(.mmm)?(Z|±HH:MM)
        if bytes[i].is_ascii_digit()
            && i + 9 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
        {
            // Consume YYYY-MM-DD plus optional T time / timezone suffix.
            let mut j = i + 10;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric()
                    || matches!(bytes[j], b':' | b'-' | b'.' | b'+' | b'Z'))
            {
                j += 1;
            }
            result.push_str("<TS>");
            i = j;
            continue;
        }
        if bytes[i].is_ascii_hexdigit() {
            hex_run.push(bytes[i] as char);
            i += 1;
            continue;
        }
        flush_hex(&mut result, &mut hex_run);
        result.push(bytes[i] as char);
        i += 1;
    }
    flush_hex(&mut result, &mut hex_run);
    result
}

fn flush_hex(result: &mut String, hex_run: &mut String) {
    if hex_run.len() >= 12 {
        result.push_str("<HEX>");
    } else {
        result.push_str(hex_run);
    }
    hex_run.clear();
}

/// Time-based detection predicate: the payload response must exceed the
/// baseline (uninjected) response by a real sleep delta. Compares a delta
/// instead of an absolute threshold so site latency jitter (e.g. Cloudflare
/// 0.1s-2s on identical requests) cannot masquerade as a SLEEP() hit.
/// Without a measurable baseline, fall back to a conservative absolute floor
/// so the check stays permissive when the control request itself failed.
fn is_time_based_delta(payload_duration: Duration, baseline: Option<Duration>) -> bool {
    const MIN_SLEEP_DELTA: Duration = Duration::from_secs(3);
    const FALLBACK_FLOOR: Duration = Duration::from_secs(8);
    match baseline {
        Some(base) => payload_duration.saturating_sub(base) > MIN_SLEEP_DELTA,
        None => payload_duration > FALLBACK_FLOOR,
    }
}

fn decode_percent_encoding(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_time_based_delta_ignores_latency_jitter() {
        // freebuff.com shape: baseline request took 2.04s (Cloudflare jitter),
        // the SLEEP(5) payload responded in 0.138s (inert). The old absolute
        // >2s threshold fired; the delta must not.
        assert!(!is_time_based_delta(
            Duration::from_millis(138),
            Some(Duration::from_millis(2040)),
        ));
        // Even a jittery payload (say 2.5s) vs a fast baseline (0.2s) is only
        // a 2.3s delta, not a sleep-class 3s+ gap.
        assert!(!is_time_based_delta(
            Duration::from_millis(2500),
            Some(Duration::from_millis(200)),
        ));
    }

    #[test]
    fn test_time_based_delta_detects_real_sleep() {
        // A genuine SLEEP(5) makes the payload response ~5s slower than the
        // 0.2s baseline.
        assert!(is_time_based_delta(
            Duration::from_secs(5),
            Some(Duration::from_millis(200)),
        ));
    }

    #[test]
    fn test_time_based_delta_fallback_floor() {
        // No baseline (control request failed): only an extreme delay fires.
        assert!(!is_time_based_delta(Duration::from_secs(5), None));
        assert!(is_time_based_delta(Duration::from_secs(10), None));
    }

    #[test]
    fn test_normalize_boolean_body_kills_request_id_fp() {
        // freebuff.com shape: the only diff between the true/false responses
        // is a random per-request RequestID and the reflected payload echo.
        let true_body = "<p>RequestID:<code>a2c926c80dd4e5ed</code></p>\nflight: \"callbackUrl=' AND 1=1\"";
        let false_body = "<p>RequestID:<code>9f1b3d77c0aa44b2</code></p>\nflight: \"callbackUrl=' AND 1=2\"";
        let true_norm = normalize_boolean_body(true_body, "' AND 1=1 ");
        let false_norm = normalize_boolean_body(false_body, "' AND 1=2 ");
        assert_eq!(
            true_norm, false_norm,
            "Bodies differing only in request ID / payload echo must normalize equal"
        );
    }

    #[test]
    fn test_normalize_boolean_body_keeps_genuine_divergence() {
        // A real boolean divergence (page content differs beyond noise) must survive.
        let true_body = "<p>RequestID:<code>a2c926c80dd4e5ed</code></p>Item found: yes";
        let false_body = "<p>RequestID:<code>9f1b3d77c0aa44b2</code></p>Item found: no";
        let true_norm = normalize_boolean_body(true_body, "' AND 1=1 ");
        let false_norm = normalize_boolean_body(false_body, "' AND 1=2 ");
        assert_ne!(
            true_norm, false_norm,
            "Genuine content divergence must survive normalization"
        );
    }

    #[test]
    fn test_normalize_boolean_body_mixed_encoding_echo() {
        // Next.js flight data echoes the payload in mixed encodings: plus-form
        // (%27+AND+...), partial (%20), and raw. All must collapse.
        let true_body = "\"c\":[\"\",\"login?callbackUrl=%27+AND+%27a%27%3D%27a\"],\"q\":\"?callbackUrl='%20AND%20'a'%3D'a\"";
        let false_body = "\"c\":[\"\",\"login?callbackUrl=%27+AND+%27a%27%3D%27b\"],\"q\":\"?callbackUrl='%20AND%20'a'%3D'b\"";
        let true_norm = normalize_boolean_body(true_body, "' AND 'a'='a ");
        let false_norm = normalize_boolean_body(false_body, "' AND 'a'='b ");
        assert_eq!(
            true_norm, false_norm,
            "Mixed-encoding payload echoes must normalize equal"
        );
    }

    #[test]
    fn test_normalize_boolean_body_timestamp() {
        let a = "{\"ts\":\"2026-08-17T13:35:22.123Z\"}";
        let b = "{\"ts\":\"2026-08-17T13:35:23.456Z\"}";
        assert_eq!(
            normalize_boolean_body(a, "x"),
            normalize_boolean_body(b, "x"),
            "Timestamps must collapse"
        );
    }

    #[test]
    fn test_load_payloads() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "' OR '1'='1").unwrap();
        writeln!(temp_file, "1' OR '1' = '1").unwrap();
        writeln!(temp_file, "admin'--").unwrap();

        let path = temp_file.path().to_str().unwrap();
        let payloads = SqlInjectionScanner::load_payloads(path);

        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads[0], "' OR '1'='1");
        assert_eq!(payloads[2], "admin'--");
    }

    #[test]
    fn test_load_boolean_payloads() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "' AND '1'='1/' AND '1'='2").unwrap();
        writeln!(temp_file, "' OR 1=1--/' OR 1=2--").unwrap();
        writeln!(temp_file, "InvalidLine").unwrap(); // Should be ignored

        let path = temp_file.path().to_str().unwrap();
        let payloads = SqlInjectionScanner::load_boolean_payloads(path);

        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].0, "' AND '1'='1");
        assert_eq!(payloads[0].1, "' AND '1'='2");
        assert_eq!(payloads[1].0, "' OR 1=1--");
    }

    #[test]
    fn test_is_error_based_vulnerable_mysql() {
        let reporter = Arc::new(crate::reporter::Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(100)));
        let scanner = SqlInjectionScanner::new(vec![], vec![], &reporter, rate_limiter);

        let body = "You have an error in your SQL syntax; check the manual";
        assert!(
            scanner.is_error_based_vulnerable(body),
            "Should detect MySQL error"
        );
    }

    #[test]
    fn test_is_error_based_vulnerable_postgresql() {
        let reporter = Arc::new(crate::reporter::Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(100)));
        let scanner = SqlInjectionScanner::new(vec![], vec![], &reporter, rate_limiter);

        let body = "ERROR: syntax error at or near 'SELECT'";
        assert!(
            scanner.is_error_based_vulnerable(body),
            "Should detect PostgreSQL error"
        );
    }

    #[test]
    fn test_is_error_based_vulnerable_mssql() {
        let reporter = Arc::new(crate::reporter::Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(100)));
        let scanner = SqlInjectionScanner::new(vec![], vec![], &reporter, rate_limiter);

        let body = "Microsoft OLE DB Provider for SQL Server error '80040e14'";
        assert!(
            scanner.is_error_based_vulnerable(body),
            "Should detect MSSQL error"
        );
    }

    #[test]
    fn test_is_error_based_not_vulnerable() {
        let reporter = Arc::new(crate::reporter::Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(100)));
        let scanner = SqlInjectionScanner::new(vec![], vec![], &reporter, rate_limiter);

        let body = "<html><body>Normal page content</body></html>";
        assert!(
            !scanner.is_error_based_vulnerable(body),
            "Should not detect SQL error in normal response"
        );
    }

    #[test]
    fn test_payloads_count() {
        let reporter = Arc::new(crate::reporter::Reporter::new(
            Url::parse("https://example.com").unwrap(),
        ));
        let rate_limiter = Arc::new(RateLimiter::new(std::time::Duration::from_millis(100)));
        let scanner = SqlInjectionScanner::new(vec![], vec![], &reporter, rate_limiter);

        let count = scanner.payloads_count();
        // count depends on files loaded, verify it calculates correctly
        assert_eq!(
            count,
            scanner.error_based_payloads.len()
                + scanner.boolean_based_payloads.len() * 2
                + scanner.time_based_payloads.len()
        );
    }
}
