use crate::bypass_403::BypassBypass;
use crate::file_inclusion_scanner::FileInclusionVulnerability;
use crate::sql_injection_scanner::SqlInjectionVulnerability;
use chrono::Local;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use url::Url;

pub struct Reporter {
    target_url: Url,
    report_files: Mutex<HashMap<String, File>>,
    output_dir: Option<std::path::PathBuf>,
}

impl Reporter {
    pub fn new(target_url: Url) -> Self {
        Self {
            target_url,
            report_files: Mutex::new(HashMap::new()),
            output_dir: None,
        }
    }

    #[allow(dead_code)] // Reserved for future custom output directory feature
    pub fn with_output_dir(mut self, path: std::path::PathBuf) -> Self {
        self.output_dir = Some(path);
        self
    }

    fn get_report_file(&self, file_name: &str) -> std::io::Result<File> {
        let mut files = self.report_files.lock().unwrap();
        if let Some(file) = files.get(file_name) {
            return file.try_clone();
        }

        let host = self.target_url.host_str().unwrap_or("unknown_host");
        let port = self.target_url.port_or_known_default().unwrap_or(80);
        let dir_name = format!("{}_{}", host.replace('.', "_"), port);

        let dir_path = if let Some(ref base) = self.output_dir {
            base.join(&dir_name)
        } else {
            std::path::PathBuf::from(&dir_name)
        };

        fs::create_dir_all(&dir_path)?;
        let file_path = dir_path.join(file_name);
        println!("Writing report to: {:?}", file_path);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        writeln!(file, "# WebHunter Scan Report for {}", self.target_url)?;
        writeln!(file, "**Scan started on:** {}", Local::now())?;
        writeln!(file, "---")?;

        files.insert(file_name.to_string(), file.try_clone()?);
        Ok(file)
    }

    // Helper to get severity badge with color
    fn get_severity_badge(&self, severity: &str) -> String {
        match severity.to_lowercase().as_str() {
            "critical" => "🔴 **CRITICAL**".to_string(),
            "high" => "🟠 **HIGH**".to_string(),
            "medium" => "🟡 **MEDIUM**".to_string(),
            "low" => "🟢 **LOW**".to_string(),
            _ => format!("**{}**", severity.to_uppercase()),
        }
    }

    fn link(url: &Url) -> String {
        format!("[{}]({})", url, url)
    }

    fn cors_severity_emoji(severity: &str) -> &'static str {
        if severity.contains("Critical") {
            "🔴"
        } else if severity.contains("High") {
            "🟠"
        } else {
            "🟡"
        }
    }

    /// One generic markdown writer for every vulnerability type.
    fn write_report(
        &self,
        file_name: &str,
        title: &str,
        fields: &[(&str, String)],
        code_block: Option<(&str, &str)>,
        description: Option<&str>,
        remediation: &[&str],
    ) {
        if let Ok(mut file) = self.get_report_file(file_name) {
            let _ = writeln!(file, "## 🎯 {}\n", title);
            let _ = writeln!(file, "| Field | Value |");
            let _ = writeln!(file, "|-------|-------|");
            for (key, value) in fields {
                let _ = writeln!(file, "| **{}** | {} |", key, value);
            }
            if let Some((lang, content)) = code_block {
                let _ = writeln!(file, "\n### 💉 Payload\n```{}\n{}\n```", lang, content);
            }
            if let Some(description) = description {
                let _ = writeln!(file, "\n### 📝 Description\n{}", description);
            }
            if !remediation.is_empty() {
                let _ = writeln!(file, "\n### 🛡️ Remediation");
                for line in remediation {
                    let _ = writeln!(file, "- {}", line);
                }
            }
            let _ = writeln!(file, "\n---\n");
        }
    }

    pub fn report_xss(&self, vuln: &crate::xss::Vulnerability) {
        self.write_report(
            "XSS-output.md",
            "XSS Vulnerability Detected",
            &[
                ("Severity", self.get_severity_badge(&vuln.severity)),
                ("Type", vuln.vuln_type.clone()),
                ("Method", vuln.method.clone()),
                ("URL", Self::link(&vuln.proof_of_concept)),
                ("Parameter", vuln.parameter.clone()),
                ("Technique", vuln.technique.clone()),
            ],
            Some(("javascript", &vuln.payload)),
            None,
            &[
                "Implement proper input validation and output encoding",
                "Use Content Security Policy (CSP) headers",
                "Employ context-aware escaping",
            ],
        );
    }

    pub fn report_sql_injection(&self, vuln: &SqlInjectionVulnerability) {
        self.write_report(
            "SQL-Injection-output.md",
            "SQL Injection Vulnerability Detected",
            &[
                ("Severity", "🔴 **CRITICAL**".to_string()),
                ("Type", vuln.vuln_type.clone()),
                ("URL", Self::link(&vuln.url)),
                ("Parameter", vuln.parameter.clone()),
            ],
            Some(("sql", &vuln.payload)),
            None,
            &[
                "Use parameterized queries (prepared statements)",
                "Implement proper input validation",
                "Apply principle of least privilege to database accounts",
                "Use ORMs with built-in protection",
            ],
        );
    }

    pub fn report_file_inclusion(&self, vuln: &FileInclusionVulnerability) {
        let severity = if vuln.vuln_type == "RFI" { "CRITICAL" } else { "HIGH" };
        self.write_report(
            "File-Inclusion-output.md",
            "File Inclusion Vulnerability Detected",
            &[
                ("Severity", self.get_severity_badge(severity)),
                ("Type", vuln.vuln_type.clone()),
                ("URL", Self::link(&vuln.url)),
                ("Parameter", vuln.parameter.clone()),
            ],
            Some(("", &vuln.payload)),
            None,
            &[
                "Never use user input directly in file paths",
                "Implement a whitelist of allowed files",
                "Use `basename()` to strip directory paths",
                "Disable `allow_url_fopen` and `allow_url_include` in PHP",
            ],
        );
    }

    pub fn report_403_bypass(&self, bypass: &BypassBypass) {
        self.write_report(
            "403-Bypass-output.md",
            "403/401 Bypass Detected",
            &[
                ("Severity", self.get_severity_badge(&bypass.severity)),
                ("Technique", bypass.technique.clone()),
                ("Method", bypass.method.clone()),
                ("Original URL", Self::link(&bypass.url)),
                ("Bypass URL", Self::link(&bypass.bypass_url)),
                ("Headers", bypass.headers.clone()),
            ],
            None,
            None,
            &[
                "Implement consistent access control checks",
                "Validate authorization on both frontend and backend",
                "Use centralized authentication/authorization framework",
                "Test with various HTTP methods and headers",
            ],
        );
    }

    pub fn report_directory(&self, url: &Url, status: u16, content_length: u64) {
        self.write_report(
            "Open-Directories-output.md",
            "Open Directory Detected",
            &[
                ("Severity", "🟡 **MEDIUM**".to_string()),
                ("URL", Self::link(url)),
                ("Status Code", status.to_string()),
                ("Content Length", format!("{} bytes", content_length)),
            ],
            None,
            None,
            &[
                "Disable directory listing in web server configuration",
                "Add index.html/index.php files to all directories",
                "Configure proper access controls",
                "Review exposed files for sensitive data",
            ],
        );
    }

    pub fn report_exposed_files(
        &self,
        vuln: &crate::exposed_files_scanner::ExposedFileVulnerability,
    ) {
        let severity = if vuln.vuln_type.contains("Source Map") {
            "🔴 **HIGH**".to_string()
        } else {
            "🟡 **MEDIUM**".to_string()
        };
        self.write_report(
            "Exposed-Files-output.md",
            "Exposed File Detected",
            &[
                ("Severity", severity),
                ("Type", vuln.vuln_type.clone()),
                ("Path", format!("[{}]({})", vuln.exposed_path, vuln.exposed_path)),
            ],
            None,
            Some(&vuln.description),
            &[
                "Remove source map files from production",
                "Disable debug endpoints in production",
                "Use environment variables for configuration",
                "Implement proper access controls",
            ],
        );
    }

    pub fn report_dom_xss(&self, vuln: &crate::dom_xss_scanner::DomXssVulnerability) {
        self.write_report(
            "DOM-XSS-output.md",
            "DOM-Based XSS Vulnerability Detected",
            &[
                ("Severity", self.get_severity_badge(&vuln.severity)),
                ("URL", Self::link(&vuln.url)),
                ("Source", vuln.source.clone()),
                ("Sink", vuln.sink.clone()),
                ("Line Number", vuln.line_number.to_string()),
            ],
            Some(("javascript", &vuln.code_snippet)),
            None,
            &[
                "Avoid using dangerous sinks (eval, innerHTML, document.write)",
                "Use safe APIs like textContent or setAttribute",
                "Implement Content Security Policy (CSP)",
                "Sanitize data from untrusted sources before DOM manipulation",
            ],
        );
    }

    pub fn report_csrf(&self, vuln: &crate::csrf_scanner::CsrfVulnerability) {
        self.write_report(
            "CSRF-output.md",
            "CSRF Vulnerability Detected",
            &[
                ("Severity", self.get_severity_badge(&vuln.severity)),
                ("URL", Self::link(&vuln.url)),
                ("Form Action", vuln.form_action.clone()),
                ("Method", vuln.method.clone()),
                (
                    "Missing Protections",
                    vuln.missing_protections.join(", "),
                ),
            ],
            Some(("html", &vuln.poc_html)),
            None,
            &[
                "Implement anti-CSRF tokens (synchronizer token pattern)",
                "Use SameSite cookie attribute",
                "Validate Origin/Referer headers",
                "Require re-authentication for sensitive actions",
            ],
        );
    }

    pub fn report_access_control(
        &self,
        vuln: &crate::access_control_scanner::AccessControlVulnerability,
    ) {
        self.write_report(
            "Access-Control-output.md",
            "Access Control Vulnerability Detected",
            &[
                ("Severity", self.get_severity_badge(&vuln.severity)),
                ("Type", vuln.vuln_type.clone()),
                ("URL", Self::link(&vuln.url)),
                ("Description", vuln.description.clone()),
            ],
            Some(("", &vuln.payload)),
            None,
            &[
                "Implement robust authorization checks for all resources",
                "Use indirect object references (map user IDs to internal IDs)",
                "Enforce role-based access control (RBAC)",
                "Deny access by default, explicitly grant only when needed",
            ],
        );
    }

    pub fn report_auth_bypass(&self, vuln: &crate::auth_bypass_scanner::AuthBypassVulnerability) {
        self.write_report(
            "Authentication-Bypass-output.md",
            "Authentication Bypass Detected",
            &[
                ("Severity", "🔴 **CRITICAL**".to_string()),
                ("Type", vuln.vuln_type.clone()),
                ("URL", Self::link(&vuln.url)),
                ("Form Action", vuln.form_action.clone()),
                ("Description", vuln.description.clone()),
            ],
            Some(("", &vuln.payload)),
            None,
            &[
                "Use parameterized queries to prevent SQL injection in auth",
                "Remove or change default credentials immediately",
                "Implement account lockout after failed attempts",
                "Use strong password policies and MFA",
            ],
        );
    }

    pub fn report_blind_xss(&self, vuln: &crate::blind_xss_scanner::BlindXssVulnerability) {
        self.write_report(
            "Blind-XSS-output.md",
            "Blind XSS Vulnerability Detected",
            &[
                ("Severity", "🔴 **CRITICAL**".to_string()),
                ("URL", Self::link(&vuln.url)),
                ("Parameter", vuln.parameter.clone()),
                ("Payload ID", vuln.payload_id.clone()),
                ("Callback Time", vuln.callback_time.to_string()),
            ],
            None,
            Some(
                "Out-of-band callback received, indicating stored XSS executed in a different context (admin panel, support dashboard, etc.)",
            ),
            &[
                "Implement proper output encoding in ALL contexts",
                "Use Content Security Policy (CSP)",
                "Sanitize user input before storage",
                "Validate and encode data when rendering in admin panels",
            ],
        );
    }

    pub fn report_cors(&self, vuln: &crate::cors_scanner::CorsVulnerability) {
        let severity = format!(
            "{} **{}**",
            Self::cors_severity_emoji(&vuln.severity),
            vuln.severity
        );
        self.write_report(
            "CORS-Misconfiguration-output.md",
            "CORS Misconfiguration Detected",
            &[
                ("Severity", severity),
                ("URL", Self::link(&vuln.url)),
                ("Test Origin", vuln.origin.clone()),
                ("Vulnerability Type", vuln.vuln_type.clone()),
            ],
            None,
            Some(&vuln.description),
            &[
                "Use strict origin allowlist instead of wildcards",
                "Avoid `Access-Control-Allow-Credentials: true` with wildcard origins",
                "Validate Origin header against a strict allowlist",
                "Do not reflect user-controlled Origin values",
            ],
        );
    }

    pub fn report_ssrf(&self, vuln: &crate::ssrf_scanner::SsrfVulnerability) {
        let severity = format!(
            "{} **{}**",
            Self::cors_severity_emoji(&vuln.severity),
            vuln.severity
        );
        self.write_report(
            "SSRF-output.md",
            "SSRF Vulnerability Detected",
            &[
                ("Severity", severity),
                ("URL", Self::link(&vuln.url)),
                ("Parameter", vuln.parameter.clone()),
                ("Payload", vuln.payload.clone()),
                ("Vulnerability Type", vuln.vuln_type.clone()),
            ],
            None,
            Some(&vuln.description),
            &[
                "Validate and sanitize user-supplied URLs",
                "Use allowlist for permitted domains/IPs",
                "Disable unnecessary URL schemas (file://, gopher://, etc.)",
                "Implement network segmentation",
                "Use safe URL parsing libraries that prevent bypasses",
            ],
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_reporter() -> (Reporter, TempDir) {
        let temp_dir = TempDir::new().unwrap();

        let url = Url::parse("https://example.com").unwrap();
        let reporter = Reporter::new(url).with_output_dir(temp_dir.path().to_path_buf());

        (reporter, temp_dir)
    }

    #[test]
    fn test_reporter_creation_basic() {
        let url = Url::parse("https://test.example.com").unwrap();
        let reporter = Reporter::new(url.clone());

        // Verify the target URL is stored
        assert_eq!(reporter.target_url, url);
    }

    #[test]
    fn test_report_xss() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::xss::Vulnerability {
            proof_of_concept: Url::parse("https://example.com/page?q=<script>alert(1)</script>")
                .unwrap(),
            parameter: "q".to_string(),
            payload: "<script>alert(1)</script>".to_string(),
            vuln_type: "Reflected XSS".to_string(),
            severity: "Medium".to_string(),
            method: "GET".to_string(),
            technique: "Basic".to_string(),
        };

        reporter.report_xss(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir.path().join("example_com_443/XSS-output.md");
        assert!(
            report_path.exists(),
            "XSS report file should exist at {:?}",
            report_path
        );

        // Verify content
        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 XSS Vulnerability Detected"));
        assert!(content.contains("<script>alert(1)</script>"));
        assert!(content.contains("Reflected"));
    }

    #[test]
    fn test_report_sql_injection() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::sql_injection_scanner::SqlInjectionVulnerability {
            url: Url::parse("https://example.com/page?id=1'").unwrap(),
            parameter: "id".to_string(),
            payload: "1'".to_string(),
            vuln_type: "Error-based".to_string(),
        };

        reporter.report_sql_injection(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/SQL-Injection-output.md");
        assert!(
            report_path.exists(),
            "SQL injection report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 SQL Injection Vulnerability Detected"));
        assert!(content.contains("Error-based"));
        assert!(content.contains("1'"));
    }

    #[test]
    fn test_report_file_inclusion() {
        let (reporter, temp_dir) = create_test_reporter();

        let vuln = crate::file_inclusion_scanner::FileInclusionVulnerability {
            url: Url::parse("https://example.com/page?file=../../../etc/passwd").unwrap(),
            parameter: "file".to_string(),
            payload: "../../../etc/passwd".to_string(),
            vuln_type: "LFI".to_string(),
        };

        reporter.report_file_inclusion(&vuln);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/File-Inclusion-output.md");
        assert!(
            report_path.exists(),
            "File inclusion report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 File Inclusion Vulnerability Detected"));
        assert!(content.contains("LFI"));
        assert!(content.contains("../../../etc/passwd"));
    }

    #[test]
    fn test_report_directory() {
        let (reporter, temp_dir) = create_test_reporter();

        let url = Url::parse("https://example.com/admin/").unwrap();
        reporter.report_directory(&url, 200, 1024);

        // Force flush by dropping reporter
        std::mem::drop(reporter);

        let report_path = temp_dir
            .path()
            .join("example_com_443/Open-Directories-output.md");
        assert!(
            report_path.exists(),
            "Directory report file should exist at {:?}",
            report_path
        );

        let content = fs::read_to_string(report_path).unwrap();
        assert!(content.contains("🎯 Open Directory Detected"));
        assert!(content.contains("200"));
        assert!(content.contains("1024 bytes"));
    }
}
