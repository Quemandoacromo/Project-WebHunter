use crate::form::Form;
use crate::inject::{inject_form_field, inject_query_param, report_found};
use crate::rate_limiter::RateLimiter;
use crate::reporter::Reporter;
use indicatif::ProgressBar;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct OpenRedirectVulnerability {
    pub url: Url,
    pub parameter: String,
    pub payload: String,
    pub redirect_url: String,
    pub severity: String,
    pub description: String,
}

pub struct OpenRedirectScanner<'a> {
    target_urls: Vec<Url>,
    forms: Vec<Form>,
    payloads: Vec<String>,
    reporter: &'a Arc<Reporter>,
    rate_limiter: Arc<RateLimiter>,
    client: Client,
}

impl<'a> OpenRedirectScanner<'a> {
    pub fn new(
        target_urls: Vec<Url>,
        forms: Vec<Form>,
        reporter: &'a Arc<Reporter>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let payloads = Self::load_payloads("wordlists/open_redirect.txt");
        Self {
            target_urls,
            forms,
            payloads,
            reporter,
            rate_limiter,
            // Redirects must be observable, not followed: a 3xx + Location
            // header is the primary open-redirect signal, and following would
            // hide it (or chase the payload host).
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    fn load_payloads(path: &str) -> Vec<String> {
        let mut payloads = Vec::new();
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    payloads.push(line.to_string());
                }
            }
        }
        if payloads.is_empty() {
            payloads.extend([
                "https://evil.com".to_string(),
                "http://evil.com".to_string(),
                "//evil.com".to_string(),
                "///evil.com".to_string(),
                "//evil.com/".to_string(),
                "/\\evil.com".to_string(),
                "/%2f/evil.com".to_string(),
                "%2f%2fevil.com".to_string(),
                "https:%2f%2fevil.com".to_string(),
                "https://evil.com%2f%2f".to_string(),
                "https:evil.com".to_string(),
                "https://evil.com@example.com".to_string(),
                "https://example.com.evil.com".to_string(),
                "javascript://evil.com%0aalert(1)".to_string(),
            ]);
        }
        payloads
    }

    pub fn payloads_count(&self) -> usize {
        self.payloads.len()
    }

    pub async fn scan(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        self.scan_urls(pb).await?;
        self.scan_forms(pb).await?;
        Ok(())
    }

    async fn scan_urls(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        for url in &self.target_urls {
            let query_pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
            if query_pairs.is_empty() {
                continue;
            }

            'param_loop: for (i, (tested_param, _)) in query_pairs.iter().enumerate() {
                let tested_param = tested_param.clone();
                for payload in &self.payloads {
                    let new_url = inject_query_param(url, i, |_| payload.to_string());

                    self.rate_limiter.wait().await;
                    let response = self.client.get(new_url.clone()).send().await?;
                    pb.inc(1);
                    let status = response.status();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    if let Some(redirect_url) =
                        is_vulnerable(status, &headers, &body, payload)
                    {
                        let vuln = OpenRedirectVulnerability {
                            url: url.clone(),
                            parameter: tested_param.clone(),
                            payload: payload.to_string(),
                            redirect_url,
                            severity: "Medium".to_string(),
                            description: "Server-side redirect to an attacker-controlled host.".to_string(),
                        };
                        report_found("Open Redirect", &vuln.payload, &vuln.parameter, || {
                            self.reporter.report_open_redirect(&vuln);
                        });
                        continue 'param_loop;
                    }
                }
            }
        }
        Ok(())
    }

    async fn scan_forms(&self, pb: &ProgressBar) -> Result<(), reqwest::Error> {
        for form in &self.forms {
            'input_loop: for i in 0..form.inputs.len() {
                let tested_param = form.inputs[i].name.clone();
                for payload in &self.payloads {
                    let form_data = inject_form_field(form, i, |_| payload.to_string());

                    let action_url = form.url.join(&form.action).unwrap();
                    self.rate_limiter.wait().await;
                    let response = if form.method.to_lowercase() == "post" {
                        self.client.post(action_url).form(&form_data).send().await?
                    } else {
                        self.client.get(action_url).query(&form_data).send().await?
                    };

                    pb.inc(1);
                    let status = response.status();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        continue;
                    }
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    if let Some(redirect_url) =
                        is_vulnerable(status, &headers, &body, payload)
                    {
                        let vuln = OpenRedirectVulnerability {
                            url: form.url.clone(),
                            parameter: tested_param.clone(),
                            payload: payload.to_string(),
                            redirect_url,
                            severity: "Medium".to_string(),
                            description: "Server-side redirect to an attacker-controlled host.".to_string(),
                        };
                        report_found("Open Redirect", &vuln.payload, &vuln.parameter, || {
                            self.reporter.report_open_redirect(&vuln);
                        });
                        continue 'input_loop;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Extract the attacker-controlled host from a payload so detection can look
/// for it in Location headers and redirect markers. Handles scheme prefixes,
/// leading slashes (//, /\, %2f, %5c), and encoded control chars.
fn payload_host(payload: &str) -> String {
    let mut p = payload.trim_start_matches('/').trim_start_matches('\\');
    for scheme in ["https:", "http:", "javascript:"] {
        if let Some(rest) = p.strip_prefix(scheme) {
            p = rest.trim_start_matches('/').trim_start_matches('\\');
            break;
        }
    }
    // Strip encoded leading slashes: %2f, %5c, and control chars (%09, %0a, %0d).
    loop {
        let lower = p.to_lowercase();
        if lower.starts_with("%2f")
            || lower.starts_with("%5c")
            || lower.starts_with("%09")
            || lower.starts_with("%0a")
            || lower.starts_with("%0d")
        {
            p = p[3..].trim_start_matches('/').trim_start_matches('\\');
        } else {
            break;
        }
    }
    // Host ends at the first slash, backslash, query/fragment, or encoded
    // control char (e.g. `javascript://evil.com%0aalert(1)`).
    let mut end = p.len();
    for delim in ["/", "\\", "?", "#", "%0a", "%0d", "%09", "%00"] {
        if let Some(idx) = p.find(delim) {
            end = end.min(idx);
        }
    }
    p[..end].to_string()
}

/// Returns the redirect target when the response redirects (3xx Location
/// header) or reflects the payload host in a client-side redirect marker
/// (meta refresh, location assignment).
fn is_vulnerable(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    payload: &str,
) -> Option<String> {
    let host = payload_host(payload);
    if host.is_empty() {
        return None;
    }

    // HTTP-level redirect: Location header carries the attacker host.
    if status.is_redirection() {
        if let Some(location) = headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            if location.contains(&host) {
                return Some(location.to_string());
            }
        }
        return None;
    }

    // Client-side redirect: only fire when the payload host appears near a
    // redirect marker. Requiring proximity keeps reflected-param echoes
    // (e.g. Next.js flight data) from false-positiving.
    if status.is_success() {
        let lower = body.to_lowercase();
        // `url=` alone is too greedy — it matches reflected params like
        // `callbackUrl=` with no redirect at all. Only the meta-refresh form
        // (`;url=`) and explicit JS assignment markers count.
        let markers = [
            "location.replace(",
            "window.location",
            "location.href",
            "http-equiv=\"refresh\"",
            "http-equiv='refresh'",
            ";url=",
        ];
        for marker in markers {
            if let Some(idx) = lower.find(marker) {
                let window = &lower[idx..(idx + marker.len() + 256).min(lower.len())];
                if window.contains(&host.to_lowercase()) {
                    return Some(marker.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_location(location: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LOCATION,
            reqwest::header::HeaderValue::from_str(location).unwrap(),
        );
        headers
    }

    #[test]
    fn test_payload_host_scheme() {
        assert_eq!(payload_host("https://evil.com/path"), "evil.com");
        assert_eq!(payload_host("http://evil.com"), "evil.com");
    }

    #[test]
    fn test_payload_host_protocol_relative() {
        assert_eq!(payload_host("//evil.com"), "evil.com");
        assert_eq!(payload_host("///evil.com/x"), "evil.com");
        assert_eq!(payload_host("/\\evil.com"), "evil.com");
    }

    #[test]
    fn test_payload_host_encoded() {
        assert_eq!(payload_host("/%2f/evil.com"), "evil.com");
        assert_eq!(payload_host("%2f%2fevil.com"), "evil.com");
        assert_eq!(payload_host("https:%2f%2fevil.com"), "evil.com");
    }

    #[test]
    fn test_payload_host_js_scheme() {
        assert_eq!(payload_host("javascript://evil.com%0aalert(1)"), "evil.com");
    }

    #[test]
    fn test_redirect_location_header_fires() {
        let headers = headers_with_location("https://evil.com/steal");
        let result = is_vulnerable(
            reqwest::StatusCode::FOUND,
            &headers,
            "",
            "//evil.com",
        );
        assert_eq!(result, Some("https://evil.com/steal".to_string()));
    }

    #[test]
    fn test_redirect_other_host_silent() {
        let headers = headers_with_location("https://example.com/home");
        let result = is_vulnerable(
            reqwest::StatusCode::FOUND,
            &headers,
            "",
            "//evil.com",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_redirect_3xx_without_location_silent() {
        let result = is_vulnerable(
            reqwest::StatusCode::MOVED_PERMANENTLY,
            &reqwest::header::HeaderMap::new(),
            "",
            "//evil.com",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_meta_refresh_fires() {
        let body = "<html><head><meta http-equiv=\"refresh\" content=\"0;url=https://evil.com/x\"></head></html>";
        let result = is_vulnerable(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            body,
            "//evil.com",
        );
        assert_eq!(result, Some("http-equiv=\"refresh\"".to_string()));
    }

    #[test]
    fn test_js_location_fires() {
        let body = "<script>window.location.href = \"https://evil.com/steal\";</script>";
        let result = is_vulnerable(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            body,
            "https://evil.com",
        );
        assert_eq!(result, Some("window.location".to_string()));
    }

    #[test]
    fn test_reflected_echo_without_marker_silent() {
        // Next.js flight-data style reflection: payload echoed as inert data,
        // no redirect marker anywhere — must not fire.
        let body = r#"self.__next_f.push([1,"pathname":"/login?callbackUrl=//evil.com"})])"#;
        let result = is_vulnerable(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            body,
            "//evil.com",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_marker_far_from_echo_silent() {
        // Redirect marker exists but the payload echo is far away (different
        // script block) — proximity guard must keep it quiet.
        let mut body = String::from("<script>window.location.href = \"/home\";</script>");
        body.push_str(&"x".repeat(500));
        body.push_str("callbackUrl=//evil.com");
        let result = is_vulnerable(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            &body,
            "//evil.com",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_vulnerability_struct_creation() {
        let vuln = OpenRedirectVulnerability {
            url: Url::parse("https://example.com/login?next=/home").unwrap(),
            parameter: "next".to_string(),
            payload: "//evil.com".to_string(),
            redirect_url: "https://evil.com".to_string(),
            severity: "Medium".to_string(),
            description: "test".to_string(),
        };
        assert_eq!(vuln.parameter, "next");
        assert_eq!(vuln.severity, "Medium");
    }
}
