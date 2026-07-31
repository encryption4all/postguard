//! Usage metrics for Grafana scraping.
//!
//! Exposes a Prometheus text-format `/metrics` endpoint covering:
//!   - uploads completed, split by traffic source ("channel")
//!   - bytes uploaded, split by channel
//!   - current on-disk storage bytes and active file count (sampled
//!     periodically by a background task)
//!
//! See `docs/grafana/` for the reference dashboard JSON.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rocket::http::HeaderMap;

/// Channel label used when no other source information is present.
pub const CHANNEL_UNKNOWN: &str = "unknown";

/// Channels pre-seeded at value 0 on startup so dashboards see the full
/// label set from the first scrape, rather than each channel popping into
/// existence the first time a request from it lands. Without this, PromQL
/// `increase()` over a window can read `0` for a channel whose first
/// observed sample is already non-zero — see #102 follow-up discussion.
pub const KNOWN_CHANNELS: &[&str] = &[
    "website",
    "staging-website",
    "outlook",
    "thunderbird",
    "api",
    CHANNEL_UNKNOWN,
];

/// Client apps pre-seeded at value 0 on startup so dashboards see the full
/// label set from the first scrape (same rationale as `KNOWN_CHANNELS`).
/// These are the `app` field of the `X-POSTGUARD-CLIENT-VERSION` header.
pub const KNOWN_APPS: &[&str] = &["pg-js", "pg-dotnet", "pg4ol", "pg4tb", CHANNEL_UNKNOWN];

/// Header clients can set to identify themselves (`outlook`, `thunderbird`,
/// `api`, ...). Leading whitespace is trimmed and the value is lowercased
/// and restricted to `[a-z0-9_-]` so it cannot inject Prometheus syntax.
pub const SOURCE_HEADER: &str = "X-Cryptify-Source";

/// Structured client-identity header shared with pg-pkg. Value format is
/// `host,host_version,app,app_version` (e.g. `node,22.1.0,pg-js,1.2.3` or
/// `Outlook,1.0,pg4ol,0.0.1`). Captured for logging (the full raw value) and
/// for the per-app upload metric (the `app` field only).
pub const CLIENT_VERSION_HEADER: &str = "X-POSTGUARD-CLIENT-VERSION";

/// Parsed form of the `X-POSTGUARD-CLIENT-VERSION` header. All four fields
/// are kept for completeness and logging/inspection; only `app` is consumed
/// for the metric label today.
#[allow(dead_code)]
pub struct ClientVersion {
    pub host: String,
    pub host_version: String,
    pub app: String,
    pub app_version: String,
}

/// Parse the 4-field client-version header. Returns `None` unless the value
/// has exactly four comma-separated fields (matching pg-pkg's strict
/// destructuring). Fields are trimmed but otherwise left raw — callers that
/// want a metric label must `sanitize_label` the `app` field themselves.
pub fn parse_client_version(raw: &str) -> Option<ClientVersion> {
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if let [host, host_version, app, app_version] = parts[..] {
        Some(ClientVersion {
            host: host.to_string(),
            host_version: host_version.to_string(),
            app: app.to_string(),
            app_version: app_version.to_string(),
        })
    } else {
        None
    }
}

pub struct Metrics {
    uploads: Mutex<BTreeMap<String, u64>>,
    upload_bytes: Mutex<BTreeMap<String, u64>>,
    uploads_by_app: Mutex<BTreeMap<String, u64>>,
    storage_bytes: AtomicI64,
    active_files: AtomicI64,
    expired_files: AtomicU64,
}

// `Default` is implemented manually (not derived) so it goes through
// `Metrics::new()` and pre-seeds `KNOWN_CHANNELS`. A derived `Default`
// would silently produce an empty-channel object, which diverges from
// `new()` and re-introduces the missing-baseline problem this module
// exists to solve.
impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut uploads = BTreeMap::new();
        let mut bytes = BTreeMap::new();
        for c in KNOWN_CHANNELS {
            uploads.insert((*c).to_string(), 0u64);
            bytes.insert((*c).to_string(), 0u64);
        }
        let mut by_app = BTreeMap::new();
        for a in KNOWN_APPS {
            by_app.insert((*a).to_string(), 0u64);
        }
        Self {
            uploads: Mutex::new(uploads),
            upload_bytes: Mutex::new(bytes),
            uploads_by_app: Mutex::new(by_app),
            storage_bytes: AtomicI64::new(0),
            active_files: AtomicI64::new(0),
            expired_files: AtomicU64::new(0),
        }
    }

    /// Record a successfully finalized upload.
    pub fn record_upload(&self, channel: &str, bytes: u64) {
        let channel = sanitize_label(channel);
        let mut uploads = self.uploads.lock().unwrap();
        *uploads.entry(channel.clone()).or_insert(0) += 1;
        let mut bytes_map = self.upload_bytes.lock().unwrap();
        *bytes_map.entry(channel).or_insert(0) += bytes;
    }

    /// Record a finalized upload against the client `app` that sent it (the
    /// `app` field of `X-POSTGUARD-CLIENT-VERSION`). Cardinality-safe: the
    /// full version is never a label (it lives in logs); only the sanitized
    /// app name is used here.
    pub fn record_upload_app(&self, app: &str) {
        let app = sanitize_label(app);
        let mut by_app = self.uploads_by_app.lock().unwrap();
        *by_app.entry(app).or_insert(0) += 1;
    }

    /// Record an upload that expired / was purged without finalizing.
    pub fn record_expired(&self) {
        self.expired_files.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the current on-disk storage sample.
    pub fn set_storage(&self, bytes: i64, active_files: i64) {
        self.storage_bytes.store(bytes, Ordering::Relaxed);
        self.active_files.store(active_files, Ordering::Relaxed);
    }

    /// Render all metrics in Prometheus text-exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();

        let _ = writeln!(
            out,
            "# HELP cryptify_uploads_total Total finalized uploads per channel."
        );
        let _ = writeln!(out, "# TYPE cryptify_uploads_total counter");
        let uploads = self.uploads.lock().unwrap();
        if uploads.is_empty() {
            let _ = writeln!(
                out,
                "cryptify_uploads_total{{channel=\"{}\"}} 0",
                CHANNEL_UNKNOWN
            );
        } else {
            for (channel, count) in uploads.iter() {
                let _ = writeln!(
                    out,
                    "cryptify_uploads_total{{channel=\"{}\"}} {}",
                    channel, count
                );
            }
        }
        drop(uploads);

        let _ = writeln!(
            out,
            "# HELP cryptify_upload_bytes_total Total bytes uploaded per channel."
        );
        let _ = writeln!(out, "# TYPE cryptify_upload_bytes_total counter");
        let bytes = self.upload_bytes.lock().unwrap();
        if bytes.is_empty() {
            let _ = writeln!(
                out,
                "cryptify_upload_bytes_total{{channel=\"{}\"}} 0",
                CHANNEL_UNKNOWN
            );
        } else {
            for (channel, b) in bytes.iter() {
                let _ = writeln!(
                    out,
                    "cryptify_upload_bytes_total{{channel=\"{}\"}} {}",
                    channel, b
                );
            }
        }
        drop(bytes);

        let _ = writeln!(
            out,
            "# HELP cryptify_uploads_by_app_total Total finalized uploads per client app."
        );
        let _ = writeln!(out, "# TYPE cryptify_uploads_by_app_total counter");
        let by_app = self.uploads_by_app.lock().unwrap();
        if by_app.is_empty() {
            let _ = writeln!(
                out,
                "cryptify_uploads_by_app_total{{app=\"{}\"}} 0",
                CHANNEL_UNKNOWN
            );
        } else {
            for (app, count) in by_app.iter() {
                let _ = writeln!(
                    out,
                    "cryptify_uploads_by_app_total{{app=\"{}\"}} {}",
                    app, count
                );
            }
        }
        drop(by_app);

        let _ = writeln!(
            out,
            "# HELP cryptify_storage_bytes Current bytes of uploads held on disk."
        );
        let _ = writeln!(out, "# TYPE cryptify_storage_bytes gauge");
        let _ = writeln!(
            out,
            "cryptify_storage_bytes {}",
            self.storage_bytes.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP cryptify_active_files Number of upload files currently on disk."
        );
        let _ = writeln!(out, "# TYPE cryptify_active_files gauge");
        let _ = writeln!(
            out,
            "cryptify_active_files {}",
            self.active_files.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP cryptify_expired_files_total Uploads that expired before being finalized."
        );
        let _ = writeln!(out, "# TYPE cryptify_expired_files_total counter");
        let _ = writeln!(
            out,
            "cryptify_expired_files_total {}",
            self.expired_files.load(Ordering::Relaxed)
        );

        out
    }
}

/// Derive the channel label for a request from its headers.
///
/// Priority:
///   1. `X-Cryptify-Source` explicit header.
///   2. API auth (`Authorization: Bearer …` or `X-Api-Key`) → `api`.
///   3. `Origin` → `staging-website` / `website`.
///   4. `User-Agent` substring for Outlook / Thunderbird.
///   5. `unknown`.
pub fn detect_channel(headers: &HeaderMap<'_>) -> String {
    if let Some(raw) = headers.get_one(SOURCE_HEADER) {
        let cleaned = sanitize_label(raw);
        if !cleaned.is_empty() && cleaned != CHANNEL_UNKNOWN {
            return cleaned;
        }
    }
    if headers.get_one("X-Api-Key").is_some()
        || headers
            .get_one("Authorization")
            .map(|v| v.trim_start().to_ascii_lowercase().starts_with("bearer "))
            .unwrap_or(false)
    {
        return "api".to_string();
    }
    if let Some(origin) = headers.get_one("Origin") {
        let o = origin.to_ascii_lowercase();
        if o.contains("staging.postguard") || o.contains("staging-postguard") {
            return "staging-website".to_string();
        }
        if o.contains("postguard.") {
            return "website".to_string();
        }
    }
    if let Some(ua) = headers.get_one("User-Agent") {
        let ua = ua.to_ascii_lowercase();
        if ua.contains("outlook") {
            return "outlook".to_string();
        }
        if ua.contains("thunderbird") {
            return "thunderbird".to_string();
        }
    }
    CHANNEL_UNKNOWN.to_string()
}

/// Reduce an arbitrary string to a safe Prometheus label value:
/// lower-case, `[a-z0-9_-]`, max 32 chars, non-empty (falls back to
/// `unknown`). This prevents clients from injecting label syntax or
/// exploding cardinality with arbitrary inputs.
fn sanitize_label(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '-' | '_' => c,
            _ => '-',
        })
        .take(32)
        .collect();
    let trimmed = cleaned.trim_matches('-').to_string();
    if trimmed.is_empty() {
        CHANNEL_UNKNOWN.to_string()
    } else {
        trimmed
    }
}

/// Walk `data_dir` once and return `(total_bytes, file_count)`. Symlinks
/// and subdirectories are ignored — the upload directory is a flat
/// directory of files named by UUID.
pub fn sample_storage(data_dir: &Path) -> std::io::Result<(i64, i64)> {
    let mut total: i64 = 0;
    let mut count: i64 = 0;
    match std::fs::read_dir(data_dir) {
        Ok(rd) => {
            for entry in rd.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total = total.saturating_add(meta.len() as i64);
                        count += 1;
                    }
                }
            }
            Ok((total, count))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((0, 0)),
        Err(e) => Err(e),
    }
}

/// Periodically sample `data_dir` and push the numbers onto `metrics`.
pub async fn storage_sampler(
    metrics: std::sync::Arc<Metrics>,
    data_dir: std::path::PathBuf,
    interval: Duration,
) {
    loop {
        match sample_storage(&data_dir) {
            Ok((bytes, count)) => metrics.set_storage(bytes, count),
            Err(e) => log::warn!("metrics: storage sampling failed for {:?}: {}", data_dir, e),
        }
        rocket::tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::Header;

    fn headers(pairs: &[(&'static str, &'static str)]) -> rocket::http::HeaderMap<'static> {
        let mut h = rocket::http::HeaderMap::new();
        for (k, v) in pairs {
            h.add(Header::new(*k, *v));
        }
        h
    }

    #[test]
    fn channel_explicit_header_wins() {
        let h = headers(&[
            ("X-Cryptify-Source", "OUTLOOK"),
            ("Origin", "https://postguard.eu"),
        ]);
        assert_eq!(detect_channel(&h), "outlook");
    }

    #[test]
    fn channel_bearer_is_api() {
        let h = headers(&[("Authorization", "Bearer abc123")]);
        assert_eq!(detect_channel(&h), "api");
    }

    #[test]
    fn channel_api_key_is_api() {
        let h = headers(&[("X-Api-Key", "s3cret")]);
        assert_eq!(detect_channel(&h), "api");
    }

    #[test]
    fn channel_origin_staging() {
        let h = headers(&[("Origin", "https://staging.postguard.eu")]);
        assert_eq!(detect_channel(&h), "staging-website");
    }

    #[test]
    fn channel_origin_production() {
        let h = headers(&[("Origin", "https://postguard.eu")]);
        assert_eq!(detect_channel(&h), "website");
    }

    #[test]
    fn channel_user_agent_outlook() {
        let h = headers(&[("User-Agent", "Mozilla Outlook/16.0")]);
        assert_eq!(detect_channel(&h), "outlook");
    }

    #[test]
    fn channel_user_agent_thunderbird() {
        let h = headers(&[("User-Agent", "Thunderbird/115.0")]);
        assert_eq!(detect_channel(&h), "thunderbird");
    }

    #[test]
    fn channel_defaults_to_unknown() {
        let h = headers(&[]);
        assert_eq!(detect_channel(&h), "unknown");
    }

    #[test]
    fn sanitize_strips_unsafe_chars_and_caps_length() {
        assert_eq!(sanitize_label("Outlook\n\"}"), "outlook");
        assert_eq!(sanitize_label(""), "unknown");
        assert_eq!(sanitize_label("   "), "unknown");
        let long = "a".repeat(100);
        assert_eq!(sanitize_label(&long).len(), 32);
    }

    #[test]
    fn parse_client_version_happy_path() {
        let cv = parse_client_version("Outlook,1.0,pg4ol,0.0.1").unwrap();
        assert_eq!(cv.host, "Outlook");
        assert_eq!(cv.host_version, "1.0");
        assert_eq!(cv.app, "pg4ol");
        assert_eq!(cv.app_version, "0.0.1");
    }

    #[test]
    fn parse_client_version_trims_fields() {
        let cv = parse_client_version(" node , 22.1.0 , pg-js , 1.2.3 ").unwrap();
        assert_eq!(cv.host, "node");
        assert_eq!(cv.app, "pg-js");
        assert_eq!(cv.app_version, "1.2.3");
    }

    #[test]
    fn parse_client_version_rejects_wrong_field_count() {
        assert!(parse_client_version("").is_none());
        assert!(parse_client_version("a,b,c").is_none());
        assert!(parse_client_version("a,b,c,d,e").is_none());
    }

    #[test]
    fn record_upload_app_aggregates_and_sanitizes() {
        let m = Metrics::new();
        m.record_upload_app("pg-js");
        m.record_upload_app("pg-js");
        m.record_upload_app("pg-dotnet");
        // Unsafe input is sanitized to the same label as the clean form.
        m.record_upload_app("pg-js\n\"}");
        let text = m.render();
        assert!(text.contains("cryptify_uploads_by_app_total{app=\"pg-js\"} 3"));
        assert!(text.contains("cryptify_uploads_by_app_total{app=\"pg-dotnet\"} 1"));
    }

    #[test]
    fn render_preseeds_known_apps_at_zero() {
        let m = Metrics::new();
        let text = m.render();
        for a in KNOWN_APPS {
            assert!(
                text.contains(&format!("cryptify_uploads_by_app_total{{app=\"{a}\"}} 0")),
                "missing zero-seed for app={a} in:\n{text}"
            );
        }
    }

    #[test]
    fn render_preseeds_known_channels_at_zero() {
        let m = Metrics::new();
        let text = m.render();
        for c in KNOWN_CHANNELS {
            assert!(
                text.contains(&format!("cryptify_uploads_total{{channel=\"{c}\"}} 0")),
                "missing zero-seed for uploads channel={c} in:\n{text}"
            );
            assert!(
                text.contains(&format!("cryptify_upload_bytes_total{{channel=\"{c}\"}} 0")),
                "missing zero-seed for upload_bytes channel={c} in:\n{text}"
            );
        }
        assert!(text.contains("cryptify_storage_bytes 0"));
        assert!(text.contains("cryptify_active_files 0"));
        assert!(text.contains("cryptify_expired_files_total 0"));
    }

    #[test]
    fn render_aggregates_by_channel() {
        let m = Metrics::new();
        m.record_upload("website", 1_000);
        m.record_upload("website", 500);
        m.record_upload("outlook", 250);
        m.record_expired();
        m.set_storage(9_999, 3);
        let text = m.render();
        assert!(text.contains("cryptify_uploads_total{channel=\"website\"} 2"));
        assert!(text.contains("cryptify_uploads_total{channel=\"outlook\"} 1"));
        assert!(text.contains("cryptify_upload_bytes_total{channel=\"website\"} 1500"));
        assert!(text.contains("cryptify_upload_bytes_total{channel=\"outlook\"} 250"));
        assert!(text.contains("cryptify_storage_bytes 9999"));
        assert!(text.contains("cryptify_active_files 3"));
        assert!(text.contains("cryptify_expired_files_total 1"));
    }

    #[test]
    fn sample_storage_missing_dir_is_zero() {
        let tmp = std::env::temp_dir().join("cryptify-metrics-missing-xyz");
        let (bytes, count) = sample_storage(&tmp).unwrap();
        assert_eq!((bytes, count), (0, 0));
    }

    #[test]
    fn sample_storage_counts_files() {
        let tmp = std::env::temp_dir().join(format!("cryptify-metrics-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a"), b"hello").unwrap();
        std::fs::write(tmp.join("b"), b"world!").unwrap();
        let (bytes, count) = sample_storage(&tmp).unwrap();
        assert_eq!(count, 2);
        assert_eq!(bytes, 11);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
