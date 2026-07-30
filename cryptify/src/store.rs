use crate::email;
use crate::metrics::Metrics;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use rocket::tokio::{sync::Notify, time::Instant};

pub const PER_UPLOAD_LIMIT: u64 = 5_000_000_000;
pub const ROLLING_LIMIT: u64 = 5_000_000_000;
pub const API_KEY_PER_UPLOAD_LIMIT: u64 = 100_000_000_000;
pub const API_KEY_ROLLING_LIMIT: u64 = 100_000_000_000;
pub const ROLLING_WINDOW_SECS: i64 = 14 * 24 * 60 * 60;

/// Default idle window for an in-memory upload session when no value is
/// provided in config. Each successful chunk PUT resets it; if no activity
/// is seen for this long the session is evicted (the on-disk file is left
/// alone — `FileState.expires` covers that).
#[cfg(test)]
pub const DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS: u64 = 60 * 60;

pub struct FileState {
    pub uploaded: u64,
    pub cryptify_token: String,
    pub expires: i64,
    pub recipients: lettre::message::Mailboxes,
    pub mail_content: String,
    pub mail_lang: email::Language,
    pub sender: Option<String>,
    pub sender_attributes: Vec<(String, String)>,
    pub confirm: bool,
    /// Traffic source this upload originated from ("website", "outlook",
    /// "thunderbird", "api", ...). Used only for metrics labelling.
    pub source_channel: String,
    /// Raw `X-POSTGUARD-CLIENT-VERSION` header value
    /// (`host,host_version,app,app_version`) sent by the client, captured at
    /// init. Logged verbatim at init and finalize so exact client versions are
    /// greppable. `None` when the header was absent.
    pub client_version: Option<String>,
    /// The `app` field parsed out of `client_version` (e.g. "pg-js",
    /// "pg-dotnet", "pg4ol"). Used as the `cryptify_uploads_by_app_total`
    /// metric label at finalize. `None` when absent or malformed.
    pub client_app: Option<String>,
    /// When false, the recipient notification email is suppressed (the
    /// recipients still appear in the parsed list, but the SMTP delivery
    /// loop in `send_email` is skipped). The sender confirmation, if
    /// `confirm` is true, is sent regardless.
    pub notify_recipients: bool,
    /// Tenant identifier when the request authenticated with a `PG-…` key
    /// validated against pg-pkg. `None` for unauthenticated requests, which
    /// receive the lower default quota tier. Used both for limit selection
    /// and as the rolling-window accounting key (`api-key:<tenant>`).
    pub api_key_tenant: Option<String>,
    /// True when the caller sent an `Authorization: Bearer PG-…` header but
    /// pg-pkg was unreachable during the full retry budget at init time.
    /// Chunk and finalize handlers consult this to differentiate 503
    /// (pkg down — would have allowed the higher tier) from 413 (default
    /// tier — would have rejected anyway) once the default cap is exceeded.
    pub api_key_validation_failed: bool,
    /// Replay record of the most recently committed chunk. Lets the chunk
    /// handler detect a duplicate retry (when the client never saw the
    /// previous response): if the request's `CryptifyToken` matches
    /// `prev_token` and `Content-Range.start` matches `prev_uploaded`, and
    /// recomputing the rolling hash over the incoming body equals
    /// `response_token`, the server replays `response_token` instead of
    /// advancing the rolling-token chain or double-writing the chunk.
    /// `None` until at least one chunk has been successfully committed.
    pub last_chunk: Option<LastChunkRecord>,
    /// Bearer token for the cross-refresh-resume status endpoint
    /// (`GET /fileupload/{uuid}/status`). Issued at `upload_init` and
    /// returned to the client alongside the first `cryptifytoken`. The
    /// path UUID alone isn't authoritative (URLs leak), so any read of
    /// session state requires the client to present this token in an
    /// `X-Recovery-Token` header. Compared in constant time to defeat
    /// timing oracles. Hex-encoded 32-byte random.
    pub recovery_token: String,
}

/// Replay record of the most recently committed chunk. See
/// [`FileState::last_chunk`].
///
/// Body identity is checked by recomputing the rolling hash
/// `sha256(prev_token || body)` and comparing against `response_token` —
/// the same construction the rolling-token chain itself relies on, so no
/// separate digest needs to be cached. Length differences also surface as
/// a hash mismatch.
#[derive(Clone, Debug)]
pub struct LastChunkRecord {
    /// The `CryptifyToken` the client sent in the chunk PUT — i.e., the
    /// rolling token *before* this chunk advanced it. A retry that lost the
    /// response will keep sending this same value.
    pub prev_token: String,
    /// `state.uploaded` *before* this chunk was applied — equals the
    /// chunk's `Content-Range` start.
    pub prev_uploaded: u64,
    /// The token the server returned in response to the original PUT —
    /// i.e., the value of `state.cryptify_token` after this chunk was
    /// applied. Replayed verbatim on a detected retry.
    pub response_token: String,
}

#[derive(Clone, Copy, Debug)]
struct UploadRecord {
    timestamp: i64,
    bytes: u64,
}

/// SQLite-backed persistence for the rolling-quota usage state.
///
/// The in-memory `StoreState.usage` map is only a cache: this database is
/// the source of truth, so per-sender quota survives pod restarts and
/// redeploys. On startup the full table is loaded back into the cache
/// ([`UsageDb::load_all`]); every accounted upload is written through here
/// ([`UsageDb::record`]) before the cache is updated.
///
/// The connection is wrapped in a `Mutex` because `rusqlite::Connection`
/// is `Send` but not `Sync`, and `SharedState` is shared across the purge
/// task via an `Arc`.
struct UsageDb {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl UsageDb {
    /// Open (creating if necessary) the SQLite database at `path` and ensure
    /// the schema exists.
    fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        // WAL keeps writes from blocking the (rare) concurrent reads and
        // survives an unclean pod kill better than the default rollback
        // journal.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS usage (
                 email     TEXT    NOT NULL,
                 timestamp INTEGER NOT NULL,
                 bytes     INTEGER NOT NULL
             )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_usage_email_ts ON usage (email, timestamp)",
            [],
        )?;
        Ok(UsageDb {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Load every persisted record into an in-memory map, grouped by email
    /// and ordered oldest-first so the resulting `VecDeque`s match what the
    /// in-memory path would have built. Stale records are intentionally not
    /// pruned here: pruning is relative to the caller-supplied `now`, which
    /// only the request path knows.
    fn load_all(&self) -> rusqlite::Result<HashMap<String, VecDeque<UploadRecord>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT email, timestamp, bytes FROM usage ORDER BY timestamp ASC")?;
        let rows = stmt.query_map([], |row| {
            let email: String = row.get(0)?;
            let timestamp: i64 = row.get(1)?;
            let bytes: i64 = row.get(2)?;
            Ok((email, timestamp, bytes))
        })?;

        let mut map: HashMap<String, VecDeque<UploadRecord>> = HashMap::new();
        for row in rows {
            let (email, timestamp, bytes) = row?;
            map.entry(email).or_default().push_back(UploadRecord {
                timestamp,
                bytes: bytes as u64,
            });
        }
        Ok(map)
    }

    /// Persist one accounted upload and drop any rows for the same email that
    /// have fallen outside the rolling window, keeping the table bounded for
    /// active senders. Errors are logged rather than propagated: a database
    /// hiccup must not fail an otherwise-successful upload, and the in-memory
    /// cache still reflects the record for the lifetime of the process.
    fn record(&self, email: &str, bytes: u64, now: i64) {
        let conn = self.conn.lock().unwrap();
        if let Err(e) = conn.execute(
            "INSERT INTO usage (email, timestamp, bytes) VALUES (?1, ?2, ?3)",
            rusqlite::params![email, now, bytes as i64],
        ) {
            log::error!("Failed to persist usage record for {}: {}", email, e);
            return;
        }
        let cutoff = now - ROLLING_WINDOW_SECS;
        if let Err(e) = conn.execute(
            "DELETE FROM usage WHERE email = ?1 AND timestamp < ?2",
            rusqlite::params![email, cutoff],
        ) {
            log::error!("Failed to prune usage records for {}: {}", email, e);
        }
    }
}

struct StoreState {
    files: HashMap<String, Arc<rocket::tokio::sync::Mutex<FileState>>>,
    expirations: BTreeMap<(Instant, u64), String>,
    /// Reverse index: file id → its current `(deadline, removal_id)` entry in
    /// `expirations`. Lets `touch` extend the deadline without scanning.
    expiration_keys: HashMap<String, (Instant, u64)>,
    usage: HashMap<String, VecDeque<UploadRecord>>,
    next_id: u64,
    shutdown: bool,
}

struct SharedState {
    state: std::sync::Mutex<StoreState>,
    notify: Notify,
    idle_ttl: Duration,
    metrics: Arc<Metrics>,
    /// SQLite source of truth for rolling-quota usage. `None` keeps usage in
    /// memory only (the pre-persistence behaviour, used by unit tests and
    /// when `usage_db` is unset in config).
    usage_db: Option<UsageDb>,
}

pub struct Store {
    shared: Arc<SharedState>,
}

impl Store {
    #[cfg(test)]
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self::with_idle_ttl(
            Duration::from_secs(DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS),
            metrics,
            None,
        )
    }

    /// Construct a store with the given idle-eviction window. When
    /// `usage_db` is `Some(path)` the rolling-quota state is backed by a
    /// SQLite database at that path: existing usage is loaded from disk on
    /// startup and every accounted upload is written through, so quota
    /// survives process restarts. A configured-but-unopenable database is a
    /// deployment error and panics here, the same way a malformed config
    /// does — better a loud startup failure than silently losing quota
    /// persistence.
    pub fn with_idle_ttl(
        idle_ttl: Duration,
        metrics: Arc<Metrics>,
        usage_db: Option<&str>,
    ) -> Self {
        let (usage_db, usage) = match usage_db {
            Some(path) => {
                let db = UsageDb::open(path)
                    .unwrap_or_else(|e| panic!("Failed to open usage database at {}: {}", path, e));
                let usage = db.load_all().unwrap_or_else(|e| {
                    panic!("Failed to load usage records from {}: {}", path, e)
                });
                let records: usize = usage.values().map(VecDeque::len).sum();
                log::info!(
                    "Loaded {} usage record(s) for {} sender(s) from {}",
                    records,
                    usage.len(),
                    path
                );
                (Some(db), usage)
            }
            None => (None, HashMap::new()),
        };

        let result = Store {
            shared: Arc::new(SharedState {
                state: std::sync::Mutex::new(StoreState {
                    files: HashMap::new(),
                    expirations: BTreeMap::new(),
                    expiration_keys: HashMap::new(),
                    usage,
                    next_id: 0,
                    shutdown: false,
                }),
                notify: Notify::new(),
                idle_ttl,
                metrics,
                usage_db,
            }),
        };

        rocket::tokio::spawn(purge_task(result.shared.clone()));
        result
    }

    pub fn create(&self, id: String, filestate: FileState) {
        let mut state = self.shared.state.lock().unwrap(); // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.
        state.files.insert(
            id.clone(),
            Arc::new(rocket::tokio::sync::Mutex::new(filestate)),
        );
        let removal_id = state.next_id;
        state.next_id += 1;
        let removal_instant = Instant::now() + self.shared.idle_ttl;
        state
            .expirations
            .insert((removal_instant, removal_id), id.clone());
        state
            .expiration_keys
            .insert(id, (removal_instant, removal_id));
        self.shared.notify.notify_one()
    }

    pub fn get(&self, id: &str) -> Option<Arc<rocket::tokio::sync::Mutex<FileState>>> {
        let state = self.shared.state.lock().unwrap(); // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.
        state.files.get(id).cloned()
    }

    /// Reset the idle-eviction deadline for `id` to "now + idle timeout".
    /// Called from `upload_chunk` after a successful chunk PUT so an upload
    /// that takes longer than the idle window is not killed mid-flight.
    pub fn touch(&self, id: &str) {
        let mut state = self.shared.state.lock().unwrap();
        let Some(&(old_when, removal_id)) = state.expiration_keys.get(id) else {
            return;
        };
        state.expirations.remove(&(old_when, removal_id));
        let new_when = Instant::now() + self.shared.idle_ttl;
        state
            .expirations
            .insert((new_when, removal_id), id.to_owned());
        state
            .expiration_keys
            .insert(id.to_owned(), (new_when, removal_id));
        self.shared.notify.notify_one();
    }

    pub fn remove(&self, id: &str) {
        let mut state = self.shared.state.lock().unwrap();
        state.files.remove(id);
        if let Some((when, removal_id)) = state.expiration_keys.remove(id) {
            state.expirations.remove(&(when, removal_id));
        }
    }

    /// Test-only accessor for the current eviction deadline of `id`.
    /// Lets route-level integration tests assert that a successful
    /// `GET /fileupload/{uuid}/status` reset the idle window via
    /// `Store::touch` (the design AC for #146 explicitly calls this
    /// out). Returns `None` if no session exists for `id`.
    #[cfg(test)]
    pub fn deadline_for(&self, id: &str) -> Option<Instant> {
        let state = self.shared.state.lock().unwrap();
        state.expiration_keys.get(id).map(|(when, _)| *when)
    }

    pub fn record_upload(&self, email: String, bytes: u64, now: i64) {
        // Persist to the source of truth first so a crash between the two
        // updates loses nothing: the cache is rebuilt from the database on
        // the next startup anyway.
        if let Some(db) = &self.shared.usage_db {
            db.record(&email, bytes, now);
        }
        let mut state = self.shared.state.lock().unwrap();
        let entry = state.usage.entry(email).or_default();
        prune_records(entry, now);
        entry.push_back(UploadRecord {
            timestamp: now,
            bytes,
        });
    }

    pub fn get_usage(&self, email: &str, now: i64) -> UsageSnapshot {
        let mut state = self.shared.state.lock().unwrap();
        match state.usage.get_mut(email) {
            Some(entry) => {
                prune_records(entry, now);
                let used_bytes = entry.iter().map(|r| r.bytes).sum();
                let oldest_expires_at = entry.front().map(|r| r.timestamp + ROLLING_WINDOW_SECS);
                UsageSnapshot {
                    used_bytes,
                    oldest_expires_at,
                }
            }
            None => UsageSnapshot {
                used_bytes: 0,
                oldest_expires_at: None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UsageSnapshot {
    pub used_bytes: u64,
    pub oldest_expires_at: Option<i64>,
}

fn prune_records(records: &mut VecDeque<UploadRecord>, now: i64) {
    let cutoff = now - ROLLING_WINDOW_SECS;
    while let Some(front) = records.front() {
        if front.timestamp < cutoff {
            records.pop_front();
        } else {
            break;
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if Arc::strong_count(&self.shared) == 2 {
            self.shared.state.lock().unwrap().shutdown = true; // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.
            self.shared.notify.notify_one()
        }
    }
}

impl SharedState {
    fn purge_expired(&self) -> Option<Instant> {
        let mut state = self.state.lock().unwrap(); // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.

        if state.shutdown {
            return None;
        }

        let state = &mut *state; // needed for borrow checker

        let now = Instant::now();
        while let Some((&(when, removal_id), id)) = state.expirations.iter().next() {
            if when > now {
                return Some(when);
            }

            let id = id.clone();
            if let Some(entry) = state.files.remove(&id) {
                // An entry that still had no `sender` set was never finalized.
                // (`sender` is populated by `upload_finalize` once the file has
                // been unsealed.)
                let was_unfinalized = entry
                    .try_lock()
                    .map(|g| g.sender.is_none())
                    .unwrap_or(false);
                if was_unfinalized {
                    self.metrics.record_expired();
                }
            }
            state.expiration_keys.remove(&id);
            state.expirations.remove(&(when, removal_id));
        }

        None
    }

    fn is_shutdown(&self) -> bool {
        self.state.lock().unwrap().shutdown // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.
    }
}

async fn purge_task(shared: Arc<SharedState>) {
    while !shared.is_shutdown() {
        if let Some(when) = shared.purge_expired() {
            rocket::tokio::select! {
                _ = rocket::tokio::time::sleep_until(when) => {}
                _ = shared.notify.notified() => {}
            }
        } else {
            shared.notify.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rocket::async_test]
    async fn usage_is_zero_for_unknown_email() {
        let store = Store::new(Arc::new(Metrics::new()));
        assert_eq!(
            store.get_usage("unknown@example.com", 1_000_000).used_bytes,
            0
        );
    }

    #[rocket::async_test]
    async fn usage_sums_records_in_window() {
        let store = Store::new(Arc::new(Metrics::new()));
        let now: i64 = 2_000_000;
        store.record_upload("a@example.com".into(), 1_000_000_000, now - 3600);
        store.record_upload("a@example.com".into(), 2_000_000_000, now - 60);
        let snap = store.get_usage("a@example.com", now);
        assert_eq!(snap.used_bytes, 3_000_000_000);
        assert_eq!(
            snap.oldest_expires_at,
            Some(now - 3600 + ROLLING_WINDOW_SECS)
        );
    }

    #[rocket::async_test]
    async fn usage_excludes_records_outside_window() {
        let store = Store::new(Arc::new(Metrics::new()));
        let now: i64 = 2_000_000;
        store.record_upload(
            "b@example.com".into(),
            5_000_000_000,
            now - ROLLING_WINDOW_SECS - 1,
        );
        store.record_upload("b@example.com".into(), 1_000_000_000, now - 60);
        assert_eq!(
            store.get_usage("b@example.com", now).used_bytes,
            1_000_000_000
        );
    }

    #[rocket::async_test]
    async fn usage_is_isolated_per_email() {
        let store = Store::new(Arc::new(Metrics::new()));
        let now: i64 = 2_000_000;
        store.record_upload("a@example.com".into(), 1_000, now);
        store.record_upload("b@example.com".into(), 2_000, now);
        assert_eq!(store.get_usage("a@example.com", now).used_bytes, 1_000);
        assert_eq!(store.get_usage("b@example.com", now).used_bytes, 2_000);
    }

    fn dummy_filestate() -> FileState {
        FileState {
            uploaded: 0,
            cryptify_token: String::new(),
            expires: 0,
            recipients: lettre::message::Mailboxes::new(),
            mail_content: String::new(),
            mail_lang: email::Language::En,
            sender: None,
            sender_attributes: Vec::new(),
            confirm: false,
            source_channel: String::new(),
            client_version: None,
            client_app: None,
            notify_recipients: true,
            api_key_tenant: None,
            api_key_validation_failed: false,
            last_chunk: None,
            recovery_token: String::new(),
        }
    }

    #[rocket::async_test]
    async fn touch_extends_eviction_deadline() {
        let store = Store::new(Arc::new(Metrics::new()));
        store.create("u1".into(), dummy_filestate());

        let original = {
            let s = store.shared.state.lock().unwrap();
            s.expiration_keys.get("u1").copied().unwrap()
        };

        // tokio::time::Instant has millisecond resolution on most platforms;
        // sleep enough for the deadline to be strictly later.
        rocket::tokio::time::sleep(Duration::from_millis(10)).await;
        store.touch("u1");

        let updated = {
            let s = store.shared.state.lock().unwrap();
            s.expiration_keys.get("u1").copied().unwrap()
        };

        assert_eq!(original.1, updated.1, "removal_id should be stable");
        assert!(
            updated.0 > original.0,
            "touch should push the deadline forward"
        );

        let s = store.shared.state.lock().unwrap();
        assert!(!s.expirations.contains_key(&original));
        assert_eq!(s.expirations.get(&updated).map(String::as_str), Some("u1"));
    }

    #[rocket::async_test]
    async fn touch_on_unknown_id_is_noop() {
        let store = Store::new(Arc::new(Metrics::new()));
        store.touch("nope");
        let s = store.shared.state.lock().unwrap();
        assert!(s.expirations.is_empty());
        assert!(s.expiration_keys.is_empty());
    }

    #[rocket::async_test]
    async fn remove_cleans_up_expirations() {
        let store = Store::new(Arc::new(Metrics::new()));
        store.create("u2".into(), dummy_filestate());
        store.remove("u2");
        let s = store.shared.state.lock().unwrap();
        assert!(s.files.is_empty());
        assert!(s.expirations.is_empty());
        assert!(s.expiration_keys.is_empty());
    }

    /// Unique temp path for a test database, cleaned up by [`TempDbPath`].
    struct TempDbPath {
        path: std::path::PathBuf,
    }

    impl TempDbPath {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("cryptify-usage-{}.db", uuid::Uuid::new_v4()));
            TempDbPath { path }
        }

        fn as_str(&self) -> &str {
            self.path.to_str().unwrap()
        }
    }

    impl Drop for TempDbPath {
        fn drop(&mut self) {
            // Remove the database file and any WAL/SHM sidecars.
            let _ = std::fs::remove_file(&self.path);
            for ext in ["-wal", "-shm"] {
                let mut p = self.path.clone().into_os_string();
                p.push(ext);
                let _ = std::fs::remove_file(p);
            }
        }
    }

    fn store_with_db(path: &str) -> Store {
        Store::with_idle_ttl(
            Duration::from_secs(DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS),
            Arc::new(Metrics::new()),
            Some(path),
        )
    }

    #[rocket::async_test]
    async fn usage_survives_simulated_restart() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;

        {
            let store = store_with_db(db.as_str());
            store.record_upload("a@example.com".into(), 1_000_000_000, now - 3600);
            store.record_upload("a@example.com".into(), 2_000_000_000, now - 60);
            store.record_upload("b@example.com".into(), 500, now - 10);
            // store dropped here — simulates the pod going away.
        }

        // Fresh Store opening the same database file — simulates restart.
        let store = store_with_db(db.as_str());
        let snap = store.get_usage("a@example.com", now);
        assert_eq!(
            snap.used_bytes, 3_000_000_000,
            "usage for a@ must be reloaded from the database after restart"
        );
        assert_eq!(
            snap.oldest_expires_at,
            Some(now - 3600 + ROLLING_WINDOW_SECS)
        );
        assert_eq!(
            store.get_usage("b@example.com", now).used_bytes,
            500,
            "per-sender usage stays isolated across a restart"
        );
    }

    #[rocket::async_test]
    async fn restart_continues_accumulating() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;

        {
            let store = store_with_db(db.as_str());
            store.record_upload("a@example.com".into(), 1_000, now - 100);
        }

        let store = store_with_db(db.as_str());
        // A record made after the restart must add to the reloaded total.
        store.record_upload("a@example.com".into(), 2_000, now);
        assert_eq!(store.get_usage("a@example.com", now).used_bytes, 3_000);
    }

    #[rocket::async_test]
    async fn rolling_window_eviction_persists_across_restart() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;

        {
            let store = store_with_db(db.as_str());
            // One record well outside the window, one inside.
            store.record_upload(
                "c@example.com".into(),
                9_000,
                now - ROLLING_WINDOW_SECS - 10,
            );
            store.record_upload("c@example.com".into(), 1_000, now - 60);
            // A later record at `now` triggers the database-side prune of the
            // stale row (DELETE WHERE timestamp < now - window).
            store.record_upload("c@example.com".into(), 2_000, now);
        }

        // After restart only the two in-window records should remain — the
        // expired one must have been evicted from the database, not just the
        // in-memory cache.
        let store = store_with_db(db.as_str());
        assert_eq!(
            store.get_usage("c@example.com", now).used_bytes,
            3_000,
            "stale record must not resurrect from the database after restart"
        );
    }

    #[rocket::async_test]
    async fn rolling_window_evicts_in_memory_after_reload() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;

        {
            let store = store_with_db(db.as_str());
            // Record that is in-window now but will fall out by `later`.
            store.record_upload("d@example.com".into(), 4_000, now);
        }

        let store = store_with_db(db.as_str());
        // Immediately after reload the record counts.
        assert_eq!(store.get_usage("d@example.com", now).used_bytes, 4_000);
        // Far in the future it has rolled out of the window.
        let later = now + ROLLING_WINDOW_SECS + 1;
        assert_eq!(store.get_usage("d@example.com", later).used_bytes, 0);
    }

    #[rocket::async_test]
    async fn pruning_removes_only_expired_records() {
        let store = Store::new(Arc::new(Metrics::new()));
        let now: i64 = 2_000_000;
        store.record_upload(
            "c@example.com".into(),
            1_000,
            now - ROLLING_WINDOW_SECS - 10,
        );
        store.record_upload("c@example.com".into(), 2_000, now - 10);
        assert_eq!(store.get_usage("c@example.com", now).used_bytes, 2_000);
        store.record_upload("c@example.com".into(), 3_000, now);
        assert_eq!(store.get_usage("c@example.com", now).used_bytes, 5_000);
    }
}
