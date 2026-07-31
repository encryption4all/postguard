use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawCryptifyConfig {
    server_url: String,
    data_dir: String,
    email_from: String,
    smtp_url: String,
    smtp_port: u16,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    smtp_tls: Option<bool>,
    allowed_origins: String,
    pkg_url: String,
    metrics_scan_interval_secs: Option<u64>,
    chunk_size: Option<u64>,
    session_ttl_secs: Option<u64>,
    staging_mode: Option<bool>,
    metrics_token: Option<String>,
    usage_db: Option<String>,
    email_attribute: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawCryptifyConfig")]
pub struct CryptifyConfig {
    server_url: String,
    data_dir: String,
    email_from: lettre::message::Mailbox,
    smtp_url: String,
    smtp_port: u16,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    smtp_tls: bool,
    allowed_origins: String,
    pkg_url: String,
    metrics_scan_interval_secs: u64,
    chunk_size: u64,
    session_ttl_secs: u64,
    staging_mode: bool,
    metrics_token: Option<String>,
    /// Filesystem path to the SQLite database backing the rolling-quota
    /// usage state. When set, per-sender usage survives process restarts
    /// (the in-memory map in `Store` is only a cache). `None` keeps usage
    /// entirely in memory, as it was before persistence was added.
    usage_db: Option<String>,
    /// Attribute type carrying the sender's email in the signing identity
    /// (postguard#236). Finalize requires this attribute to be present.
    /// Test environments override it with a test-scheme type (e.g.
    /// `irma-demo.sidn-pbdf.email.email`); production keeps the default.
    email_attribute: String,
}

impl From<RawCryptifyConfig> for CryptifyConfig {
    fn from(config: RawCryptifyConfig) -> Self {
        CryptifyConfig {
            server_url: config.server_url,
            data_dir: config.data_dir,
            email_from: config.email_from.parse().unwrap_or_else(|e| {
                log::error!("Could not parse Mailbox from email_form: {}", e);
                panic!("Could not parse Mailbox from email_form: {}", e)
            }),
            smtp_url: config.smtp_url,
            smtp_port: config.smtp_port,
            smtp_username: config.smtp_username,
            smtp_password: config.smtp_password,
            smtp_tls: config.smtp_tls.unwrap_or(true),
            allowed_origins: config.allowed_origins,
            pkg_url: config.pkg_url,
            metrics_scan_interval_secs: config.metrics_scan_interval_secs.unwrap_or(60),
            chunk_size: config.chunk_size.unwrap_or(5_000_000),
            session_ttl_secs: config.session_ttl_secs.unwrap_or(3600),
            staging_mode: config.staging_mode.unwrap_or(false),
            metrics_token: config.metrics_token,
            usage_db: config.usage_db,
            email_attribute: config
                .email_attribute
                .unwrap_or_else(|| "pbdf.sidn-pbdf.email.email".to_owned()),
        }
    }
}

impl CryptifyConfig {
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn data_dir(&self) -> &str {
        &self.data_dir
    }

    pub fn email_from(&self) -> lettre::message::Mailbox {
        self.email_from.clone()
    }

    pub fn smtp_url(&self) -> &str {
        &self.smtp_url
    }

    pub fn smtp_port(&self) -> u16 {
        self.smtp_port
    }

    pub fn smtp_username(&self) -> Option<&str> {
        self.smtp_username.as_deref()
    }

    pub fn smtp_password(&self) -> Option<&str> {
        self.smtp_password.as_deref()
    }

    pub fn smtp_tls(&self) -> bool {
        self.smtp_tls
    }

    pub fn allowed_origins(&self) -> &str {
        &self.allowed_origins
    }

    pub fn pkg_url(&self) -> &str {
        &self.pkg_url
    }

    pub fn metrics_scan_interval_secs(&self) -> u64 {
        self.metrics_scan_interval_secs
    }

    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs
    }

    pub fn staging_mode(&self) -> bool {
        self.staging_mode
    }

    /// Bearer token required to scrape `/metrics`. `None` leaves the endpoint
    /// open (with a startup warning); when set, requests must present
    /// `Authorization: Bearer <token>`.
    pub fn metrics_token(&self) -> Option<&str> {
        self.metrics_token.as_deref()
    }

    /// Path to the SQLite database backing rolling-quota usage, if
    /// configured. `None` means usage is kept in memory only.
    pub fn usage_db(&self) -> Option<&str> {
        self.usage_db.as_deref()
    }

    /// The attribute type carrying the sender's email in the signing
    /// identity. Defaults to the production `pbdf.sidn-pbdf.email.email`.
    pub fn email_attribute(&self) -> &str {
        &self.email_attribute
    }

    #[cfg(test)]
    pub(crate) fn for_test(server_url: &str, staging_mode: bool) -> Self {
        CryptifyConfig {
            server_url: server_url.to_owned(),
            data_dir: "/tmp".to_owned(),
            email_from: "noreply@test.invalid".parse().unwrap(),
            smtp_url: "localhost".to_owned(),
            smtp_port: 25,
            smtp_username: None,
            smtp_password: None,
            smtp_tls: false,
            allowed_origins: String::new(),
            pkg_url: String::new(),
            metrics_scan_interval_secs: 60,
            chunk_size: 5_000_000,
            session_ttl_secs: 3600,
            staging_mode,
            metrics_token: None,
            usage_db: None,
            email_attribute: "pbdf.sidn-pbdf.email.email".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::{providers::Serialized, Figment};

    fn base_config() -> serde_json::Value {
        serde_json::json!({
            "server_url": "http://localhost",
            "data_dir": "/tmp/data",
            "email_from": "Test <test@example.com>",
            "smtp_url": "localhost",
            "smtp_port": 1025u16,
            "allowed_origins": ".*",
            "pkg_url": "http://localhost",
        })
    }

    #[test]
    fn usage_db_is_parsed_when_present() {
        let mut raw = base_config();
        raw["usage_db"] = serde_json::json!("/app/data/usage.db");
        let config: CryptifyConfig = Figment::from(Serialized::defaults(raw)).extract().unwrap();
        assert_eq!(config.usage_db(), Some("/app/data/usage.db"));
    }

    #[test]
    fn usage_db_defaults_to_none_when_absent() {
        let config: CryptifyConfig = Figment::from(Serialized::defaults(base_config()))
            .extract()
            .unwrap();
        assert_eq!(config.usage_db(), None);
    }

    #[test]
    fn email_attribute_defaults_to_production_type() {
        let config: CryptifyConfig = Figment::from(Serialized::defaults(base_config()))
            .extract()
            .unwrap();
        assert_eq!(config.email_attribute(), "pbdf.sidn-pbdf.email.email");
    }

    #[test]
    fn email_attribute_is_overridable() {
        let mut raw = base_config();
        raw["email_attribute"] = serde_json::json!("irma-demo.sidn-pbdf.email.email");
        let config: CryptifyConfig = Figment::from(Serialized::defaults(raw)).extract().unwrap();
        assert_eq!(config.email_attribute(), "irma-demo.sidn-pbdf.email.email");
    }
}
