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
    attributed_email: Option<bool>,
    per_upload_limit: Option<u64>,
    rolling_limit: Option<u64>,
    api_key_per_upload_limit: Option<u64>,
    api_key_rolling_limit: Option<u64>,
    rolling_window_days: Option<u64>,
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
    /// Whether a notification email may attribute the upload to the proven
    /// sender at all. See [`CryptifyConfig::attributed_email`].
    attributed_email: bool,
    per_upload_limit: u64,
    rolling_limit: u64,
    api_key_per_upload_limit: u64,
    api_key_rolling_limit: u64,
    /// Length of the rolling-quota window, in days.
    ///
    /// Unlike the four byte limits, changing this retroactively reinterprets
    /// usage that was already recorded: shrinking it forgives usage that was
    /// counted, growing it resurrects usage that had expired, and either
    /// invalidates the `resets_at` timestamps already handed to callers. The
    /// byte limits only ever affect the next comparison. That is accepted —
    /// an operator reasons about the window as a policy period and has to be
    /// able to set it.
    rolling_window_days: u64,
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
            attributed_email: config.attributed_email.unwrap_or(true),
            per_upload_limit: config.per_upload_limit.unwrap_or(5_000_000_000),
            rolling_limit: config.rolling_limit.unwrap_or(5_000_000_000),
            api_key_per_upload_limit: config.api_key_per_upload_limit.unwrap_or(100_000_000_000),
            api_key_rolling_limit: config.api_key_rolling_limit.unwrap_or(100_000_000_000),
            rolling_window_days: config.rolling_window_days.unwrap_or(14),
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

    /// The kill switch for the attributed notification email (postguard#365).
    /// Off sends every notification in the neutral rendering, for a deployment
    /// whose mail filters object to the attribution line. It is applied as a
    /// downgrade *after* the claim resolves, so it can only ever take an
    /// attribution away: no value of it makes an unproven upload render
    /// attributed.
    pub fn attributed_email(&self) -> bool {
        self.attributed_email
    }

    /// Largest single upload accepted from a caller on the default tier.
    pub fn per_upload_limit(&self) -> u64 {
        self.per_upload_limit
    }

    /// Bytes a default-tier sender may upload within the rolling window.
    pub fn rolling_limit(&self) -> u64 {
        self.rolling_limit
    }

    /// Largest single upload accepted from a validated API-key tenant.
    pub fn api_key_per_upload_limit(&self) -> u64 {
        self.api_key_per_upload_limit
    }

    /// Bytes a validated API-key tenant may upload within the rolling window.
    pub fn api_key_rolling_limit(&self) -> u64 {
        self.api_key_rolling_limit
    }

    /// The rolling window as configured. See the field for what changing it
    /// does to usage already recorded.
    pub fn rolling_window_days(&self) -> u64 {
        self.rolling_window_days
    }

    /// The same window in seconds, which is the unit the store compares
    /// timestamps in.
    pub fn rolling_window_secs(&self) -> i64 {
        self.rolling_window_days as i64 * 24 * 60 * 60
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
            attributed_email: true,
            per_upload_limit: 5_000_000_000,
            rolling_limit: 5_000_000_000,
            api_key_per_upload_limit: 100_000_000_000,
            api_key_rolling_limit: 100_000_000_000,
            rolling_window_days: 14,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_attributed_email(mut self, attributed_email: bool) -> Self {
        self.attributed_email = attributed_email;
        self
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
    fn attributed_email_defaults_to_on() {
        let config: CryptifyConfig = Figment::from(Serialized::defaults(base_config()))
            .extract()
            .unwrap();
        assert!(
            config.attributed_email(),
            "a deployment that says nothing gets the attribution it earned"
        );
    }

    #[test]
    fn attributed_email_is_overridable() {
        let mut raw = base_config();
        raw["attributed_email"] = serde_json::json!(false);
        let config: CryptifyConfig = Figment::from(Serialized::defaults(raw)).extract().unwrap();
        assert!(!config.attributed_email());
    }

    #[test]
    fn email_attribute_is_overridable() {
        let mut raw = base_config();
        raw["email_attribute"] = serde_json::json!("irma-demo.sidn-pbdf.email.email");
        let config: CryptifyConfig = Figment::from(Serialized::defaults(raw)).extract().unwrap();
        assert_eq!(config.email_attribute(), "irma-demo.sidn-pbdf.email.email");
    }

    fn config_from(key: &str, value: u64) -> CryptifyConfig {
        let mut raw = base_config();
        raw[key] = serde_json::json!(value);
        Figment::from(Serialized::defaults(raw)).extract().unwrap()
    }

    fn default_config() -> CryptifyConfig {
        Figment::from(Serialized::defaults(base_config()))
            .extract()
            .unwrap()
    }

    // The defaults below are written as literals on purpose: they are the
    // assertion. Every other reader of these numbers goes through the
    // accessor, so a literal here is the only place the value is stated twice
    // -- which is what makes the test able to catch a changed default.

    #[test]
    fn per_upload_limit_defaults_to_five_gb_and_is_overridable() {
        assert_eq!(default_config().per_upload_limit(), 5_000_000_000);
        assert_eq!(
            config_from("per_upload_limit", 1_024).per_upload_limit(),
            1_024
        );
    }

    #[test]
    fn rolling_limit_defaults_to_five_gb_and_is_overridable() {
        assert_eq!(default_config().rolling_limit(), 5_000_000_000);
        assert_eq!(config_from("rolling_limit", 2_048).rolling_limit(), 2_048);
    }

    #[test]
    fn api_key_per_upload_limit_defaults_to_hundred_gb_and_is_overridable() {
        assert_eq!(default_config().api_key_per_upload_limit(), 100_000_000_000);
        assert_eq!(
            config_from("api_key_per_upload_limit", 4_096).api_key_per_upload_limit(),
            4_096
        );
    }

    #[test]
    fn api_key_rolling_limit_defaults_to_hundred_gb_and_is_overridable() {
        assert_eq!(default_config().api_key_rolling_limit(), 100_000_000_000);
        assert_eq!(
            config_from("api_key_rolling_limit", 8_192).api_key_rolling_limit(),
            8_192
        );
    }

    #[test]
    fn rolling_window_defaults_to_fourteen_days_and_is_overridable() {
        let config = default_config();
        assert_eq!(config.rolling_window_days(), 14);
        assert_eq!(config.rolling_window_secs(), 14 * 24 * 60 * 60);

        let config = config_from("rolling_window_days", 3);
        assert_eq!(config.rolling_window_days(), 3);
        assert_eq!(
            config.rolling_window_secs(),
            3 * 24 * 60 * 60,
            "the seconds accessor must follow the configured days, not the default"
        );
    }
}
