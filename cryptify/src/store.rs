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

/// One row of the `upload_sessions` table: the durable projection of a
/// [`FileState`], carrying everything needed to rebuild an in-flight upload
/// after a restart.
///
/// Two fields are deliberately *not* verbatim copies of `FileState`:
///
/// - `recovery_token_hash` is `sha256(recovery_token)`, hex-encoded. The
///   plaintext is a bearer credential for `GET /fileupload/{uuid}/status`,
///   so it is stored the way a password would be — a restore path compares
///   `sha256(presented)` against this column rather than the token itself.
/// - `sender_attributes` is the JSON encoding of `FileState`'s
///   `Vec<(String, String)>`, so a variable-length list fits one column.
///
/// Nothing reads these rows back yet: restore-on-boot is postguard#303.
/// This step only makes the state durable, with no client-visible change.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PersistedSession {
    uuid: String,
    /// Current head of the rolling-token chain (`FileState::cryptify_token`).
    cryptify_token: String,
    /// The three [`LastChunkRecord`] fields, all `None` until the first chunk
    /// is committed. `prev_token` is the previous `cryptifytoken` — the value
    /// the client sent on the last accepted chunk, which the idempotent-replay
    /// path matches against.
    prev_token: Option<String>,
    prev_uploaded: Option<u64>,
    response_token: Option<String>,
    recovery_token_hash: String,
    /// Bytes received so far. There is no "expected size" counterpart:
    /// clients send `Content-Range: bytes <start>-<end>/*` on chunk PUTs, so
    /// the total is unknown to the server until finalize declares it (and
    /// finalize rejects a declaration that disagrees with `uploaded`).
    uploaded: u64,
    /// Absolute unix timestamp of the 14-day on-disk expiry
    /// (`FileState::expires`), not the idle-eviction deadline.
    expires: i64,
    /// Recipient list rendered by `Mailboxes`' `Display`, which its `FromStr`
    /// parses back.
    recipients: String,
    mail_content: String,
    /// `"EN"` / `"NL"` — [`email::Language::code`], pinned to the serde
    /// representation by a test in `email.rs`.
    mail_lang: String,
    confirm: bool,
    notify_recipients: bool,
    source_channel: String,
    client_version: Option<String>,
    client_app: Option<String>,
    api_key_tenant: Option<String>,
    api_key_validation_failed: bool,
    /// Populated at finalize, once the sealed file has been unsealed.
    sender: Option<String>,
    sender_attributes: String,
    /// Set when the row is first inserted and never overwritten afterwards
    /// (the upsert's `DO UPDATE` list omits it on purpose).
    created_at: i64,
    /// Refreshed on every persisted transition.
    last_active_at: i64,
}

impl PersistedSession {
    /// Project a live [`FileState`] onto its durable row. `now` is used for
    /// `last_active_at`, and for `created_at` on the initial insert only —
    /// on an update the upsert keeps the stored value.
    fn from_state(uuid: &str, state: &FileState, now: i64) -> Self {
        let (prev_token, prev_uploaded, response_token) = match state.last_chunk.as_ref() {
            Some(last) => (
                Some(last.prev_token.clone()),
                Some(last.prev_uploaded),
                Some(last.response_token.clone()),
            ),
            None => (None, None, None),
        };

        PersistedSession {
            uuid: uuid.to_owned(),
            cryptify_token: state.cryptify_token.clone(),
            prev_token,
            prev_uploaded,
            response_token,
            recovery_token_hash: hash_recovery_token(&state.recovery_token),
            uploaded: state.uploaded,
            expires: state.expires,
            recipients: state.recipients.to_string(),
            mail_content: state.mail_content.clone(),
            mail_lang: state.mail_lang.code().to_owned(),
            confirm: state.confirm,
            notify_recipients: state.notify_recipients,
            source_channel: state.source_channel.clone(),
            client_version: state.client_version.clone(),
            client_app: state.client_app.clone(),
            api_key_tenant: state.api_key_tenant.clone(),
            api_key_validation_failed: state.api_key_validation_failed,
            sender: state.sender.clone(),
            // Infallible in practice (a Vec of string pairs); fall back to an
            // empty list rather than failing the upload over metadata.
            sender_attributes: serde_json::to_string(&state.sender_attributes)
                .unwrap_or_else(|_| "[]".to_owned()),
            created_at: now,
            last_active_at: now,
        }
    }
}

/// Hex-encoded SHA-256 of an upload session's recovery token. See
/// [`PersistedSession::recovery_token_hash`].
fn hash_recovery_token(token: &str) -> String {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(token.as_bytes());
    crate::bytes_to_hex(&hash.finalize())
}

/// SQLite-backed persistence for cryptify's durable state: the rolling-quota
/// `usage` table and the `upload_sessions` table.
///
/// Both live in the single database file named by the `usage_db` config key
/// (one file to mount and back up), on one connection, so a session write and
/// a usage write can never disagree about which file they landed in.
///
/// For usage, the in-memory `StoreState.usage` map is only a cache: this
/// database is the source of truth, so per-sender quota survives pod restarts
/// and redeploys. On startup the full table is loaded back into the cache
/// ([`StateDb::load_all_usage`]); every accounted upload is written through
/// here ([`StateDb::record_usage`]) before the cache is updated.
///
/// For sessions the direction is currently one-way: every state transition is
/// written through ([`StateDb::upsert_session`]) and eviction deletes the row
/// ([`StateDb::delete_session`]), but nothing loads rows back yet — that is
/// postguard#303.
///
/// The connection is wrapped in a `Mutex` because `rusqlite::Connection`
/// is `Send` but not `Sync`, and `SharedState` is shared across the purge
/// task via an `Arc`.
struct StateDb {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl StateDb {
    /// Open (creating if necessary) the SQLite database at `path` and ensure
    /// the schema exists. Called once at startup, so an existing database
    /// from before upload-session persistence simply gains the new table.
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
        conn.execute(
            "CREATE TABLE IF NOT EXISTS upload_sessions (
                 uuid                      TEXT    PRIMARY KEY,
                 cryptify_token            TEXT    NOT NULL,
                 prev_token                TEXT,
                 prev_uploaded             INTEGER,
                 response_token            TEXT,
                 recovery_token_hash       TEXT    NOT NULL,
                 uploaded                  INTEGER NOT NULL,
                 expires                   INTEGER NOT NULL,
                 recipients                TEXT    NOT NULL,
                 mail_content              TEXT    NOT NULL,
                 mail_lang                 TEXT    NOT NULL,
                 confirm                   INTEGER NOT NULL,
                 notify_recipients         INTEGER NOT NULL,
                 source_channel            TEXT    NOT NULL,
                 client_version            TEXT,
                 client_app                TEXT,
                 api_key_tenant            TEXT,
                 api_key_validation_failed INTEGER NOT NULL,
                 sender                    TEXT,
                 sender_attributes         TEXT    NOT NULL,
                 created_at                INTEGER NOT NULL,
                 last_active_at            INTEGER NOT NULL
             )",
            [],
        )?;
        Ok(StateDb {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Write a session's current state, inserting on the first transition and
    /// updating on every later one. `created_at` is omitted from the update
    /// list so it keeps recording when the session began.
    ///
    /// Errors are logged rather than propagated, for the same reason
    /// [`StateDb::record_usage`] swallows them: this step must not add a way
    /// for an otherwise-successful upload to fail. The in-memory state stays
    /// authoritative for the lifetime of the process either way.
    fn upsert_session(&self, session: &PersistedSession) {
        let conn = self.conn.lock().unwrap();
        if let Err(e) = conn.execute(
            "INSERT INTO upload_sessions (
                 uuid, cryptify_token, prev_token, prev_uploaded, response_token,
                 recovery_token_hash, uploaded, expires, recipients, mail_content,
                 mail_lang, confirm, notify_recipients, source_channel, client_version,
                 client_app, api_key_tenant, api_key_validation_failed, sender,
                 sender_attributes, created_at, last_active_at
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
             )
             ON CONFLICT(uuid) DO UPDATE SET
                 cryptify_token            = excluded.cryptify_token,
                 prev_token                = excluded.prev_token,
                 prev_uploaded             = excluded.prev_uploaded,
                 response_token            = excluded.response_token,
                 recovery_token_hash       = excluded.recovery_token_hash,
                 uploaded                  = excluded.uploaded,
                 expires                   = excluded.expires,
                 recipients                = excluded.recipients,
                 mail_content              = excluded.mail_content,
                 mail_lang                 = excluded.mail_lang,
                 confirm                   = excluded.confirm,
                 notify_recipients         = excluded.notify_recipients,
                 source_channel            = excluded.source_channel,
                 client_version            = excluded.client_version,
                 client_app                = excluded.client_app,
                 api_key_tenant            = excluded.api_key_tenant,
                 api_key_validation_failed = excluded.api_key_validation_failed,
                 sender                    = excluded.sender,
                 sender_attributes         = excluded.sender_attributes,
                 last_active_at            = excluded.last_active_at",
            rusqlite::params![
                session.uuid,
                session.cryptify_token,
                session.prev_token,
                session.prev_uploaded.map(|v| v as i64),
                session.response_token,
                session.recovery_token_hash,
                session.uploaded as i64,
                session.expires,
                session.recipients,
                session.mail_content,
                session.mail_lang,
                session.confirm,
                session.notify_recipients,
                session.source_channel,
                session.client_version,
                session.client_app,
                session.api_key_tenant,
                session.api_key_validation_failed,
                session.sender,
                session.sender_attributes,
                session.created_at,
                session.last_active_at,
            ],
        ) {
            log::error!("Failed to persist upload session {}: {}", session.uuid, e);
        }
    }

    /// Drop a session's row once it can never be resumed — evicted by the
    /// purge task, or explicitly removed (e.g. a finalize rejected for quota,
    /// which also deletes the on-disk file).
    fn delete_session(&self, uuid: &str) {
        let conn = self.conn.lock().unwrap();
        if let Err(e) = conn.execute(
            "DELETE FROM upload_sessions WHERE uuid = ?1",
            rusqlite::params![uuid],
        ) {
            log::error!("Failed to delete persisted upload session {}: {}", uuid, e);
        }
    }

    /// Read one persisted session back. Only tests need this today; the
    /// production reader arrives with restore-on-boot (postguard#303).
    #[cfg(test)]
    fn load_session(&self, uuid: &str) -> Option<PersistedSession> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT uuid, cryptify_token, prev_token, prev_uploaded, response_token,
                    recovery_token_hash, uploaded, expires, recipients, mail_content,
                    mail_lang, confirm, notify_recipients, source_channel, client_version,
                    client_app, api_key_tenant, api_key_validation_failed, sender,
                    sender_attributes, created_at, last_active_at
             FROM upload_sessions WHERE uuid = ?1",
            rusqlite::params![uuid],
            |row| {
                Ok(PersistedSession {
                    uuid: row.get(0)?,
                    cryptify_token: row.get(1)?,
                    prev_token: row.get(2)?,
                    prev_uploaded: row.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    response_token: row.get(4)?,
                    recovery_token_hash: row.get(5)?,
                    uploaded: row.get::<_, i64>(6)? as u64,
                    expires: row.get(7)?,
                    recipients: row.get(8)?,
                    mail_content: row.get(9)?,
                    mail_lang: row.get(10)?,
                    confirm: row.get(11)?,
                    notify_recipients: row.get(12)?,
                    source_channel: row.get(13)?,
                    client_version: row.get(14)?,
                    client_app: row.get(15)?,
                    api_key_tenant: row.get(16)?,
                    api_key_validation_failed: row.get(17)?,
                    sender: row.get(18)?,
                    sender_attributes: row.get(19)?,
                    created_at: row.get(20)?,
                    last_active_at: row.get(21)?,
                })
            },
        )
        .ok()
    }

    /// Number of persisted sessions, for tests asserting eviction.
    #[cfg(test)]
    fn session_count(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM upload_sessions", [], |row| row.get(0))
            .unwrap_or(-1)
    }

    /// Load every persisted record into an in-memory map, grouped by email
    /// and ordered oldest-first so the resulting `VecDeque`s match what the
    /// in-memory path would have built. Stale records are intentionally not
    /// pruned here: pruning is relative to the caller-supplied `now`, which
    /// only the request path knows.
    fn load_all_usage(&self) -> rusqlite::Result<HashMap<String, VecDeque<UploadRecord>>> {
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
    fn record_usage(&self, email: &str, bytes: u64, now: i64) {
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
    /// SQLite handle backing rolling-quota usage and upload-session state.
    /// `None` keeps both in memory only (the pre-persistence behaviour, used
    /// by unit tests and when `usage_db` is unset in config).
    db: Option<StateDb>,
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
    /// `db_path` is `Some(path)` the durable state is backed by a SQLite
    /// database at that path (the `usage_db` config key): existing usage is
    /// loaded from disk on startup and every accounted upload is written
    /// through, so quota survives process restarts, and every upload-session
    /// transition is written through to the `upload_sessions` table. The
    /// schema is created here if absent, so an existing database from before
    /// session persistence just gains the new table. A
    /// configured-but-unopenable database is a deployment error and panics
    /// here, the same way a malformed config does — better a loud startup
    /// failure than silently losing persistence.
    pub fn with_idle_ttl(idle_ttl: Duration, metrics: Arc<Metrics>, db_path: Option<&str>) -> Self {
        let (db, usage) = match db_path {
            Some(path) => {
                let db = StateDb::open(path)
                    .unwrap_or_else(|e| panic!("Failed to open state database at {}: {}", path, e));
                let usage = db.load_all_usage().unwrap_or_else(|e| {
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
                db,
            }),
        };

        rocket::tokio::spawn(purge_task(result.shared.clone()));
        result
    }

    pub fn create(&self, id: String, filestate: FileState) {
        // Write-through before the entry becomes visible in memory (and so
        // before the handler can answer the client), keeping the database at
        // least as far ahead as the response the client acted on. Done
        // outside the `state` mutex so a slow disk never blocks lookups.
        self.persist_session(&id, &filestate);

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

    /// Write the session's current state through to the `upload_sessions`
    /// table. A no-op when no database is configured.
    ///
    /// Called at every transition — session creation, an accepted chunk, and
    /// finalize — *before* the handler builds its response, so the durable
    /// row never lags behind what the client was told. The write is a single
    /// small upsert under a `Mutex`; the same shape as the usage write that
    /// already runs on the finalize path.
    ///
    /// Failures are logged inside [`StateDb::upsert_session`] rather than
    /// returned: persistence is a restart-recovery aid, and this step must
    /// not introduce a new way for a healthy upload to fail.
    pub fn persist_session(&self, id: &str, state: &FileState) {
        let Some(db) = &self.shared.db else {
            return;
        };
        let now = chrono::offset::Utc::now().timestamp();
        db.upsert_session(&PersistedSession::from_state(id, state, now));
    }

    pub fn remove(&self, id: &str) {
        // A removed session can never be resumed, so its row goes too —
        // otherwise it would outlive the on-disk file the caller deletes
        // alongside this call.
        if let Some(db) = &self.shared.db {
            db.delete_session(id);
        }
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
        if let Some(db) = &self.shared.db {
            db.record_usage(&email, bytes, now);
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
        let mut evicted: Vec<String> = Vec::new();

        let next_deadline = {
            let mut state = self.state.lock().unwrap(); // this will only panic if we already panicked elsewhere while holding the mutex, which is fine.

            if state.shutdown {
                return None;
            }

            let state = &mut *state; // needed for borrow checker

            let now = Instant::now();
            loop {
                let Some((&(when, removal_id), id)) = state.expirations.iter().next() else {
                    break None;
                };
                if when > now {
                    break Some(when);
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
                evicted.push(id);
            }
        };

        // Outside the `state` mutex: an evicted session is unresumable, so its
        // row goes with it. Without this the table would grow without bound
        // and a restore would resurrect sessions the purge already killed.
        if let Some(db) = &self.db {
            for id in &evicted {
                db.delete_session(id);
            }
        }

        next_deadline
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
                std::env::temp_dir().join(format!("cryptify-state-{}.db", uuid::Uuid::new_v4()));
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

    // ---------------------------------------------------------------------
    // Upload-session persistence (postguard#302).
    //
    // Rows are read back through a *second* `StateDb` on the same file, so
    // these assert what a restarting process would actually find on disk
    // rather than what the writing connection happens to hold.
    // ---------------------------------------------------------------------

    const RECIPIENTS: &str = "one@example.com, two@example.com";
    const RECOVERY_TOKEN: &str = "3f7a9c1e-recovery-secret";

    /// A `FileState` with every persisted field set to something
    /// distinguishable, so a column swapped for its neighbour fails.
    fn populated_filestate() -> FileState {
        FileState {
            uploaded: 0,
            cryptify_token: "init-token".to_owned(),
            expires: 1_700_000_000,
            recipients: RECIPIENTS.parse().expect("parse recipients"),
            mail_content: "hello <b>world</b>".to_owned(),
            mail_lang: email::Language::Nl,
            sender: None,
            sender_attributes: Vec::new(),
            confirm: true,
            source_channel: "website".to_owned(),
            client_version: Some("web,1.2,pg-js,2.3.3".to_owned()),
            client_app: Some("pg-js".to_owned()),
            notify_recipients: false,
            api_key_tenant: Some("tenant-a".to_owned()),
            api_key_validation_failed: false,
            last_chunk: None,
            recovery_token: RECOVERY_TOKEN.to_owned(),
        }
    }

    /// Open a second connection to the same database file and read one row.
    fn read_back(path: &str, uuid: &str) -> Option<PersistedSession> {
        StateDb::open(path)
            .expect("reopen state database")
            .load_session(uuid)
    }

    #[rocket::async_test]
    async fn create_persists_the_whole_session_row() {
        let db = TempDbPath::new();
        let store = store_with_db(db.as_str());
        store.create("session-1".into(), populated_filestate());

        let row = read_back(db.as_str(), "session-1").expect("row visible after init");
        assert_eq!(row.uuid, "session-1");
        assert_eq!(row.cryptify_token, "init-token");
        assert_eq!(row.uploaded, 0);
        assert_eq!(row.expires, 1_700_000_000);
        assert_eq!(
            row.recipients,
            RECIPIENTS
                .parse::<lettre::message::Mailboxes>()
                .unwrap()
                .to_string(),
            "recipients round-trip through Mailboxes' Display"
        );
        assert_eq!(row.mail_content, "hello <b>world</b>");
        assert_eq!(row.mail_lang, "NL");
        assert!(row.confirm);
        assert!(!row.notify_recipients);
        assert_eq!(row.source_channel, "website");
        assert_eq!(row.client_version.as_deref(), Some("web,1.2,pg-js,2.3.3"));
        assert_eq!(row.client_app.as_deref(), Some("pg-js"));
        assert_eq!(row.api_key_tenant.as_deref(), Some("tenant-a"));
        assert!(!row.api_key_validation_failed);
        assert_eq!(row.sender, None, "sender is unknown until finalize");
        assert_eq!(row.sender_attributes, "[]");
        // No chunk committed yet, so the whole replay record is absent.
        assert_eq!(row.prev_token, None);
        assert_eq!(row.prev_uploaded, None);
        assert_eq!(row.response_token, None);
        assert_eq!(
            row.created_at, row.last_active_at,
            "a session that has only been created has not been active since"
        );
    }

    #[rocket::async_test]
    async fn recovery_token_is_persisted_only_as_a_hash() {
        let db = TempDbPath::new();
        let store = store_with_db(db.as_str());
        store.create("session-hash".into(), populated_filestate());

        let row = read_back(db.as_str(), "session-hash").expect("row visible after init");
        assert_eq!(row.recovery_token_hash, hash_recovery_token(RECOVERY_TOKEN));
        assert_eq!(row.recovery_token_hash.len(), 64, "hex-encoded SHA-256");
        // The bearer credential itself must not be recoverable from the row.
        let serialized = format!("{:?}", row);
        assert!(
            !serialized.contains(RECOVERY_TOKEN),
            "plaintext recovery token must not appear anywhere in the row: {serialized}"
        );
    }

    #[rocket::async_test]
    async fn an_accepted_chunk_persists_progress_and_keeps_created_at() {
        let db = TempDbPath::new();
        let store = store_with_db(db.as_str());
        store.create("session-2".into(), populated_filestate());
        let created_at = read_back(db.as_str(), "session-2")
            .expect("row after init")
            .created_at;

        // Mirror what `upload_chunk` does to the live state before it calls
        // `persist_session`: advance the chain and record the replay entry.
        let handle = store.get("session-2").expect("live session");
        {
            let mut state = handle.lock().await;
            state.cryptify_token = "chunk-1-token".to_owned();
            state.uploaded = 1_048_576;
            state.last_chunk = Some(LastChunkRecord {
                prev_token: "init-token".to_owned(),
                prev_uploaded: 0,
                response_token: "chunk-1-token".to_owned(),
            });
            store.persist_session("session-2", &state);
        }

        let row = read_back(db.as_str(), "session-2").expect("row after chunk");
        assert_eq!(row.cryptify_token, "chunk-1-token");
        assert_eq!(row.uploaded, 1_048_576);
        assert_eq!(row.prev_token.as_deref(), Some("init-token"));
        assert_eq!(row.prev_uploaded, Some(0));
        assert_eq!(row.response_token.as_deref(), Some("chunk-1-token"));
        assert_eq!(
            row.created_at, created_at,
            "created_at records when the session began and must survive updates"
        );
        assert!(
            row.last_active_at >= created_at,
            "last_active_at should track the newest transition"
        );
        // Still exactly one row: the transition is an update, not an insert.
        assert_eq!(
            StateDb::open(db.as_str()).unwrap().session_count(),
            1,
            "a transition must upsert, not append"
        );
    }

    #[rocket::async_test]
    async fn finalize_persists_the_sender_and_its_attributes() {
        let db = TempDbPath::new();
        let store = store_with_db(db.as_str());
        store.create("session-3".into(), populated_filestate());

        let handle = store.get("session-3").expect("live session");
        {
            let mut state = handle.lock().await;
            state.sender = Some("bob@example.com".to_owned());
            state.sender_attributes = vec![(
                "pbdf.gemeente.personalData.fullname".to_owned(),
                "Bob".to_owned(),
            )];
            store.persist_session("session-3", &state);
        }

        let row = read_back(db.as_str(), "session-3").expect("row after finalize");
        assert_eq!(row.sender.as_deref(), Some("bob@example.com"));
        assert_eq!(
            row.sender_attributes,
            r#"[["pbdf.gemeente.personalData.fullname","Bob"]]"#
        );
    }

    #[rocket::async_test]
    async fn remove_deletes_the_persisted_row() {
        let db = TempDbPath::new();
        let store = store_with_db(db.as_str());
        store.create("session-4".into(), populated_filestate());
        assert!(read_back(db.as_str(), "session-4").is_some());

        // What `upload_finalize` does when it rejects an upload for quota and
        // deletes the on-disk file: the row must not outlive the file.
        store.remove("session-4");
        assert!(
            read_back(db.as_str(), "session-4").is_none(),
            "removing a session must delete its row"
        );
    }

    #[rocket::async_test]
    async fn eviction_deletes_the_persisted_row() {
        let db = TempDbPath::new();
        // Idle window short enough that the purge task fires during the test.
        let store = Store::with_idle_ttl(
            Duration::from_millis(20),
            Arc::new(Metrics::new()),
            Some(db.as_str()),
        );
        store.create("session-5".into(), populated_filestate());
        assert!(read_back(db.as_str(), "session-5").is_some());

        // Poll rather than sleep a fixed interval: the purge task is a real
        // background task, and a loaded CI runner can be slow to schedule it.
        let mut evicted = false;
        for _ in 0..100 {
            rocket::tokio::time::sleep(Duration::from_millis(20)).await;
            if read_back(db.as_str(), "session-5").is_none() {
                evicted = true;
                break;
            }
        }
        assert!(
            evicted,
            "the purge task must delete the row of a session it evicts"
        );
        assert!(
            store.get("session-5").is_none(),
            "in-memory eviction should have happened too"
        );
    }

    #[rocket::async_test]
    async fn persistence_is_a_noop_without_a_configured_database() {
        // The `usage_db`-unset deployment keeps the old in-memory behaviour;
        // every persistence call has to degrade to nothing rather than panic.
        let store = Store::new(Arc::new(Metrics::new()));
        store.create("session-6".into(), populated_filestate());
        let handle = store.get("session-6").expect("live session");
        {
            let state = handle.lock().await;
            store.persist_session("session-6", &state);
        }
        store.remove("session-6");
        assert!(store.get("session-6").is_none());
    }

    #[rocket::async_test]
    async fn schema_is_created_on_boot_and_survives_reopening() {
        let db = TempDbPath::new();
        {
            // First boot creates the schema in a database file that does not
            // exist yet.
            let store = store_with_db(db.as_str());
            store.create("session-7".into(), populated_filestate());
        }
        // Second boot must find the table already there (CREATE TABLE IF NOT
        // EXISTS) and leave the existing row alone. Reading the row back is
        // all this step promises — rebuilding sessions from it is #303.
        let store = store_with_db(db.as_str());
        assert!(
            store.get("session-7").is_none(),
            "restore-on-boot is postguard#303 and must not happen yet"
        );
        assert!(
            read_back(db.as_str(), "session-7").is_some(),
            "the row must still be there after a reopen"
        );
    }

    #[rocket::async_test]
    async fn a_usage_only_database_gains_the_sessions_table_on_next_boot() {
        // Deployments already running with `usage_db` set have a file with
        // just the `usage` table. Opening it must add `upload_sessions` in
        // place, without disturbing the usage rows.
        let db = TempDbPath::new();
        {
            let conn = rusqlite::Connection::open(db.as_str()).expect("open bare database");
            conn.execute(
                "CREATE TABLE usage (
                     email     TEXT    NOT NULL,
                     timestamp INTEGER NOT NULL,
                     bytes     INTEGER NOT NULL
                 )",
                [],
            )
            .expect("create legacy usage table");
            conn.execute(
                "INSERT INTO usage (email, timestamp, bytes) VALUES ('old@example.com', 1000, 4242)",
                [],
            )
            .expect("seed a usage row");
        }

        let store = store_with_db(db.as_str());
        assert_eq!(
            store.get_usage("old@example.com", 1_000).used_bytes,
            4242,
            "pre-existing usage rows must still load"
        );
        store.create("session-8".into(), populated_filestate());
        assert!(
            read_back(db.as_str(), "session-8").is_some(),
            "the upload_sessions table must be created in an existing database"
        );
    }
}
