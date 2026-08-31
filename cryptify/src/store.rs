use crate::email;
use crate::metrics::Metrics;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rocket::tokio::{sync::Notify, time::Instant};

/// Default idle window for an in-memory upload session when no value is
/// provided in config. Each successful chunk PUT resets it; if no activity
/// is seen for this long the session is evicted (the on-disk file is left
/// alone — `FileState.expires` covers that).
#[cfg(test)]
pub const DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS: u64 = 60 * 60;

/// What the uploader proved about the sender identity a container claims.
///
/// cryptify holds no decryption key and never opens an upload, so nothing
/// inside the container can say who uploaded it: the header names a sender
/// and, on its own, that is the uploader's word. This is the answer to the
/// challenge minted at `upload_init` — either the uploader signed it with the
/// key belonging to the identity the container's signing policy derives to, or
/// they did not.
///
/// The values in `Proven` are canonical (see
/// [`pg_core::identity::canonicalize`]), not the spellings the container
/// happens to carry. `Policy::derive_ibs` canonicalizes before deriving the
/// identity a signature is checked against, so a container spelling the
/// address `Alice@Example.COM` verifies under a key issued for
/// `alice@example.com`: the raw spelling is not what the proof pinned, and
/// carrying it inside `Proven` would put an uploader-chosen string there. The
/// spelling the container used stays available as [`FileState::sender`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum SenderClaim {
    /// The uploader answered the challenge with a signature that verifies
    /// under the identity the container's signing policy derives to.
    Proven {
        /// The proven sender email, canonicalized.
        email: String,
        /// The remaining attributes of the proven identity, canonicalized.
        attrs: Vec<(String, String)>,
    },
    /// No proof was presented, or the one presented did not verify. Both are
    /// this: what a deployment *does* about an unproven sender is decided
    /// elsewhere, and this type only records what was established.
    Unproven,
}

/// The durable encoding of [`SenderClaim::Unproven`]. Only reached when
/// encoding a claim fails, which cannot happen for the owned strings this enum
/// holds — but a `Proven` must not survive such a failure as one.
/// `sender_claim_unproven_encodes_to_the_fallback` pins the two together.
const UNPROVEN_JSON: &str = r#"{"kind":"Unproven"}"#;

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
    /// `sha256` of the bearer token for the cross-refresh-resume status
    /// endpoint (`GET /fileupload/{uuid}/status`), hex-encoded. The plaintext
    /// is minted at `upload_init`, returned to the client alongside the first
    /// `cryptifytoken`, and then dropped — the server keeps only this digest,
    /// so a session restored from SQLite holds exactly what a live one does
    /// and both authenticate the same way. The path UUID alone isn't
    /// authoritative (URLs leak), so any read of session state requires the
    /// client to present the plaintext in an `X-Recovery-Token` header;
    /// `upload_status` hashes what it was given and compares the two digests
    /// in constant time.
    pub recovery_token_hash: String,
    /// The upload challenge minted at `upload_init` and handed to the client
    /// in the init response, hex-encoded 32-byte random. The uploader signs
    /// the *decoded* bytes, so the hex is a transport spelling only and
    /// `upload_finalize` decodes it before verifying.
    ///
    /// `None` for a session restored from a row written before the column
    /// existed. Such an upload was never given anything to answer, so it
    /// finalizes as [`SenderClaim::Unproven`] however it is presented.
    pub challenge: Option<String>,
    /// What the uploader proved about the sender identity, established at
    /// finalize. `None` until finalize has run, the same way [`sender`] is —
    /// the two are populated by the same step.
    ///
    /// [`sender`]: FileState::sender
    pub sender_claim: Option<SenderClaim>,
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
/// One field is deliberately *not* a verbatim copy of `FileState`:
/// `sender_attributes` is the JSON encoding of `FileState`'s
/// `Vec<(String, String)>`, so a variable-length list fits one column.
///
/// [`Store::with_idle_ttl`] reads these rows back at boot and turns each one
/// that is still live into a `FileState` again via
/// [`PersistedSession::into_state`].
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
    /// Verbatim copy of [`FileState::recovery_token_hash`] — the digest of a
    /// bearer credential, stored the way a password would be. The plaintext
    /// never reaches the process's memory after `upload_init` answers, let
    /// alone this table.
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
    /// Verbatim copy of [`FileState::challenge`]. `None` on a row written
    /// before the column existed — the session it describes predates the
    /// challenge and has none.
    challenge: Option<String>,
    /// JSON encoding of [`SenderClaim`], written at finalize alongside
    /// `sender`. `None` before then, and on a row written before the column
    /// existed.
    sender_claim: Option<String>,
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
            recovery_token_hash: state.recovery_token_hash.clone(),
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
            challenge: state.challenge.clone(),
            sender_claim: state.sender_claim.as_ref().map(|claim| {
                // Infallible for the owned strings a claim holds. A `Proven`
                // that somehow failed to encode must not be read back as one,
                // and `None` would read as "finalize has not run yet", so
                // degrade to the encoding of `Unproven`.
                serde_json::to_string(claim).unwrap_or_else(|e| {
                    log::error!("Cannot encode the sender claim for {}: {}", uuid, e);
                    UNPROVEN_JSON.to_owned()
                })
            }),
        }
    }

    /// Rebuild the live [`FileState`] this row was projected from, so an
    /// upload interrupted by a restart can carry on where it left off.
    ///
    /// `None` when a column cannot be read back — a recipient list that no
    /// longer parses, or a `mail_lang` this binary does not know. Such a
    /// session cannot be served correctly, so the caller leaves both the row
    /// and the file alone and lets the normal expiry sweep collect them
    /// rather than guessing at a value.
    fn into_state(self) -> Option<FileState> {
        let uuid = self.uuid;

        let recipients = match self.recipients.parse::<lettre::message::Mailboxes>() {
            Ok(recipients) => recipients,
            Err(e) => {
                log::error!("Cannot restore upload session {}: recipients: {}", uuid, e);
                return None;
            }
        };

        let Some(mail_lang) = email::Language::from_code(&self.mail_lang) else {
            log::error!(
                "Cannot restore upload session {}: unknown mail_lang {:?}",
                uuid,
                self.mail_lang
            );
            return None;
        };

        // The three replay columns are written and cleared as a unit, so a
        // partial trio means a hand-edited row: drop the replay record rather
        // than resume with half of one, which would misjudge a retry.
        let last_chunk = match (self.prev_token, self.prev_uploaded, self.response_token) {
            (Some(prev_token), Some(prev_uploaded), Some(response_token)) => {
                Some(LastChunkRecord {
                    prev_token,
                    prev_uploaded,
                    response_token,
                })
            }
            _ => None,
        };

        // Attributes only feed the notification email's rendering, so a
        // corrupt value is not worth failing an otherwise resumable upload
        // over — but it is worth shouting about.
        let sender_attributes = serde_json::from_str(&self.sender_attributes).unwrap_or_else(|e| {
            log::error!(
                "Restored upload session {} has unreadable sender_attributes: {}",
                uuid,
                e
            );
            Vec::new()
        });

        // Same reasoning as the attributes above, one step further: a claim
        // that cannot be read is not evidence of anything, so it comes back as
        // `Unproven` rather than dropping the session.
        let sender_claim = self.sender_claim.as_deref().map(|encoded| {
            serde_json::from_str(encoded).unwrap_or_else(|e| {
                log::error!(
                    "Restored upload session {} has an unreadable sender_claim: {}",
                    uuid,
                    e
                );
                SenderClaim::Unproven
            })
        });

        Some(FileState {
            uploaded: self.uploaded,
            cryptify_token: self.cryptify_token,
            expires: self.expires,
            recipients,
            mail_content: self.mail_content,
            mail_lang,
            sender: self.sender,
            sender_attributes,
            confirm: self.confirm,
            source_channel: self.source_channel,
            client_version: self.client_version,
            client_app: self.client_app,
            notify_recipients: self.notify_recipients,
            api_key_tenant: self.api_key_tenant,
            api_key_validation_failed: self.api_key_validation_failed,
            last_chunk,
            recovery_token_hash: self.recovery_token_hash,
            challenge: self.challenge,
            sender_claim,
        })
    }
}

/// Hex-encoded SHA-256 of an upload session's recovery token. The only place
/// the plaintext credential is ever turned into what the server stores and
/// compares — see [`FileState::recovery_token_hash`].
pub fn hash_recovery_token(token: &str) -> String {
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
/// Sessions work the same way: every state transition is written through
/// ([`StateDb::upsert_session`]), eviction deletes the row
/// ([`StateDb::delete_session`]), and startup loads the surviving rows back
/// ([`StateDb::load_sessions`]) so an upload interrupted by a redeploy can be
/// resumed instead of 404-ing.
///
/// The connection is wrapped in a `Mutex` because `rusqlite::Connection`
/// is `Send` but not `Sync`, and `SharedState` is shared across the purge
/// task via an `Arc`.
struct StateDb {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

/// Column list of `upload_sessions`, in the order [`session_from_row`] reads
/// them. Shared by every SELECT so a reordered column cannot silently pair a
/// value with its neighbour's field.
const SESSION_COLUMNS: &str = "uuid, cryptify_token, prev_token, prev_uploaded, response_token,
     recovery_token_hash, uploaded, expires, recipients, mail_content,
     mail_lang, confirm, notify_recipients, source_channel, client_version,
     client_app, api_key_tenant, api_key_validation_failed, sender,
     sender_attributes, created_at, last_active_at, challenge, sender_claim";

fn session_from_row(row: &rusqlite::Row) -> rusqlite::Result<PersistedSession> {
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
        challenge: row.get(22)?,
        sender_claim: row.get(23)?,
    })
}

/// Columns added to `upload_sessions` after the table first shipped, each with
/// the statement that adds it.
///
/// `CREATE TABLE IF NOT EXISTS` leaves an existing table exactly as it is, so a
/// deployed database never gains a column from the create statement — every
/// column added later has to be `ALTER TABLE`d on. Both are nullable, which is
/// what `ADD COLUMN` can do without a default and also what the rows deserve:
/// a session that predates the challenge has none, and one that predates the
/// claim never had its sender proved either way.
const SESSION_COLUMN_MIGRATIONS: &[(&str, &str)] = &[
    (
        "challenge",
        "ALTER TABLE upload_sessions ADD COLUMN challenge TEXT",
    ),
    (
        "sender_claim",
        "ALTER TABLE upload_sessions ADD COLUMN sender_claim TEXT",
    ),
];

impl StateDb {
    /// Open (creating if necessary) the SQLite database at `path` and ensure
    /// the schema exists. Called once at startup, so an existing database from
    /// before upload-session persistence simply gains the new table, and one
    /// whose table predates a column gains the column
    /// ([`StateDb::migrate_sessions`]).
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
                 last_active_at            INTEGER NOT NULL,
                 challenge                 TEXT,
                 sender_claim              TEXT
             )",
            [],
        )?;
        Self::migrate_sessions(&conn)?;
        Ok(StateDb {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Add any [`SESSION_COLUMN_MIGRATIONS`] column the table is missing.
    ///
    /// Driven off what the table actually has rather than off a stored schema
    /// version, so it is a no-op on a database the create statement above just
    /// built, a no-op on a second boot, and correct on a database whose table
    /// was created by any earlier version — there is no version bookkeeping to
    /// get out of step with the columns.
    fn migrate_sessions(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        let mut present = std::collections::HashSet::new();
        {
            let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('upload_sessions')")?;
            let names = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for name in names {
                present.insert(name?);
            }
        }

        for (column, statement) in SESSION_COLUMN_MIGRATIONS {
            if present.contains(*column) {
                continue;
            }
            conn.execute(statement, [])?;
            log::info!("Added column {} to upload_sessions", column);
        }

        Ok(())
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
                 sender_attributes, created_at, last_active_at, challenge, sender_claim
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                 ?23, ?24
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
                 last_active_at            = excluded.last_active_at,
                 challenge                 = excluded.challenge,
                 sender_claim              = excluded.sender_claim",
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
                session.challenge,
                session.sender_claim,
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

    /// Read one persisted session back. Only tests need this: production
    /// restores the whole table at once through [`StateDb::load_sessions`].
    #[cfg(test)]
    fn load_session(&self, uuid: &str) -> Option<PersistedSession> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {SESSION_COLUMNS} FROM upload_sessions WHERE uuid = ?1"),
            rusqlite::params![uuid],
            session_from_row,
        )
        .ok()
    }

    /// Read every persisted session back, for the boot-time restore. Ordered
    /// by insertion time so restored sessions enter the in-memory maps in the
    /// order they were created, as a process that never restarted would have
    /// them.
    fn load_sessions(&self) -> rusqlite::Result<Vec<PersistedSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SESSION_COLUMNS} FROM upload_sessions ORDER BY created_at ASC"
        ))?;
        let rows = stmt.query_map([], session_from_row)?;
        rows.collect()
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
    fn record_usage(&self, email: &str, bytes: u64, now: i64, rolling_window_secs: i64) {
        let conn = self.conn.lock().unwrap();
        if let Err(e) = conn.execute(
            "INSERT INTO usage (email, timestamp, bytes) VALUES (?1, ?2, ?3)",
            rusqlite::params![email, now, bytes as i64],
        ) {
            log::error!("Failed to persist usage record for {}: {}", email, e);
            return;
        }
        let cutoff = now - rolling_window_secs;
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
    rolling_window_secs: i64,
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
    pub fn new(metrics: Arc<Metrics>, rolling_window_secs: i64) -> Self {
        Self::with_idle_ttl(
            Duration::from_secs(DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS),
            metrics,
            None,
            Path::new(""),
            rolling_window_secs,
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
    ///
    /// Startup is also where persisted sessions come back
    /// ([`Store::restore_sessions`]). `data_dir` is the upload directory the
    /// handlers write chunks into; the restore needs it to delete the partial
    /// file of a session that expired while the process was down. It is
    /// unused when `db_path` is `None`, since without a database there is
    /// nothing to restore from.
    pub fn with_idle_ttl(
        idle_ttl: Duration,
        metrics: Arc<Metrics>,
        db_path: Option<&str>,
        data_dir: &Path,
        rolling_window_secs: i64,
    ) -> Self {
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
                rolling_window_secs,
                metrics,
                db,
            }),
        };

        // Before the purge task exists, so a restored session's deadline is
        // in place the first time the task looks at the map.
        result.restore_sessions(data_dir);

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
        insert_session(
            &mut state,
            id,
            filestate,
            Instant::now() + self.shared.idle_ttl,
        );
        drop(state);
        self.shared.notify.notify_one()
    }

    /// Rebuild the in-memory session map from the `upload_sessions` table, so
    /// a chunk PUT that arrives after a redeploy resumes the upload instead of
    /// 404-ing (the class behind postguard-website#117).
    ///
    /// A row survives when both of its deadlines are still in the future: the
    /// idle window (`last_active_at + idle_ttl`, the durable stand-in for the
    /// `Instant` the purge task uses, which cannot outlive a process) and the
    /// 14-day `expires`. Because the idle window is measured from the stored
    /// timestamp rather than restarted here, downtime counts against a session
    /// exactly as an idle client would — a restart cannot be used to keep a
    /// dead session alive.
    ///
    /// Everything else expired while the process was down. Its row goes, and
    /// so does its file in `data_dir` — but only when the session never
    /// reached finalize (`sender` is still unset). A finalized session's file
    /// is a completed upload waiting for its recipient to download it, not an
    /// orphan, and it is the 14-day expiry rather than this sweep that governs
    /// it. Nothing else in `data_dir` is touched: the sweep only ever names
    /// files it has a row for, so a stray file — or the state database itself,
    /// which deployments may keep in the same directory — is never a
    /// candidate.
    fn restore_sessions(&self, data_dir: &Path) {
        let Some(db) = &self.shared.db else {
            return;
        };

        let rows = match db.load_sessions() {
            Ok(rows) => rows,
            Err(e) => {
                // Sessions stay lost, as they were before restore existed;
                // usage already loaded, and uploads still work. Not worth
                // refusing to boot over.
                log::error!("Failed to load persisted upload sessions: {}", e);
                return;
            }
        };

        let now = chrono::offset::Utc::now().timestamp();
        let idle_ttl_secs = self.shared.idle_ttl.as_secs() as i64;
        let (mut expired, mut partials_removed, mut unreadable) = (0usize, 0usize, 0usize);
        let mut restored: Vec<(String, FileState, Instant)> = Vec::new();

        for row in rows {
            let idle_deadline = row.last_active_at.saturating_add(idle_ttl_secs);
            if now >= idle_deadline || now >= row.expires {
                expired += 1;
                if row.sender.is_none() {
                    // Never finalized: nobody can resume it and nobody can
                    // download it, so the bytes on disk are the orphan class
                    // encryption4all/cryptify#125 describes.
                    match std::fs::remove_file(data_dir.join(&row.uuid)) {
                        Ok(()) => partials_removed += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => log::warn!(
                            "Could not remove the partial upload of expired session {}: {}",
                            row.uuid,
                            e
                        ),
                    }
                    // Counted the same way the purge task counts a session it
                    // evicts while running, so downtime does not hide them.
                    self.shared.metrics.record_expired();
                }
                db.delete_session(&row.uuid);
                continue;
            }

            let uuid = row.uuid.clone();
            let Some(state) = row.into_state() else {
                // `into_state` has already logged why. Leave the row and the
                // file where they are: once the session's deadlines pass, the
                // branch above collects both.
                unreadable += 1;
                continue;
            };
            let deadline = Instant::now() + Duration::from_secs((idle_deadline - now) as u64);
            restored.push((uuid, state, deadline));
        }

        let restored_count = restored.len();
        if !restored.is_empty() {
            let mut state = self.shared.state.lock().unwrap();
            for (uuid, filestate, deadline) in restored {
                insert_session(&mut state, uuid, filestate, deadline);
            }
        }

        log::info!(
            "Restored {} upload session(s); dropped {} that expired while down ({} partial file(s) removed, {} row(s) unreadable)",
            restored_count,
            expired,
            partials_removed,
            unreadable
        );
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
            db.record_usage(&email, bytes, now, self.shared.rolling_window_secs);
        }
        let mut state = self.shared.state.lock().unwrap();
        let entry = state.usage.entry(email).or_default();
        prune_records(entry, now, self.shared.rolling_window_secs);
        entry.push_back(UploadRecord {
            timestamp: now,
            bytes,
        });
    }

    pub fn get_usage(&self, email: &str, now: i64) -> UsageSnapshot {
        let window = self.shared.rolling_window_secs;
        let mut state = self.shared.state.lock().unwrap();
        match state.usage.get_mut(email) {
            Some(entry) => {
                prune_records(entry, now, window);
                let used_bytes = entry.iter().map(|r| r.bytes).sum();
                let oldest_expires_at = entry.front().map(|r| r.timestamp + window);
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

/// Register a session in the live maps with `deadline` as its idle-eviction
/// time. Shared by [`Store::create`] and [`Store::restore_sessions`] so a
/// restored entry is indistinguishable from a freshly created one — the two
/// cannot drift on which maps an entry has to appear in.
fn insert_session(state: &mut StoreState, id: String, filestate: FileState, deadline: Instant) {
    let removal_id = state.next_id;
    state.next_id += 1;
    state.files.insert(
        id.clone(),
        Arc::new(rocket::tokio::sync::Mutex::new(filestate)),
    );
    state.expirations.insert((deadline, removal_id), id.clone());
    state.expiration_keys.insert(id, (deadline, removal_id));
}

fn prune_records(records: &mut VecDeque<UploadRecord>, now: i64, rolling_window_secs: i64) {
    let cutoff = now - rolling_window_secs;
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
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
        assert_eq!(
            store.get_usage("unknown@example.com", 1_000_000).used_bytes,
            0
        );
    }

    #[rocket::async_test]
    async fn usage_sums_records_in_window() {
        let window = 14 * 24 * 60 * 60;
        let store = Store::new(Arc::new(Metrics::new()), window);
        let now: i64 = 2_000_000;
        store.record_upload("a@example.com".into(), 1_000_000_000, now - 3600);
        store.record_upload("a@example.com".into(), 2_000_000_000, now - 60);
        let snap = store.get_usage("a@example.com", now);
        assert_eq!(snap.used_bytes, 3_000_000_000);
        assert_eq!(snap.oldest_expires_at, Some(now - 3600 + window));
    }

    #[rocket::async_test]
    async fn usage_excludes_records_outside_window() {
        let window = 14 * 24 * 60 * 60;
        let store = Store::new(Arc::new(Metrics::new()), window);
        let now: i64 = 2_000_000;
        store.record_upload("b@example.com".into(), 5_000_000_000, now - window - 1);
        store.record_upload("b@example.com".into(), 1_000_000_000, now - 60);
        assert_eq!(
            store.get_usage("b@example.com", now).used_bytes,
            1_000_000_000
        );
    }

    #[rocket::async_test]
    async fn usage_is_isolated_per_email() {
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
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
            recovery_token_hash: String::new(),
            challenge: None,
            sender_claim: None,
        }
    }

    #[rocket::async_test]
    async fn touch_extends_eviction_deadline() {
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
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
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
        store.touch("nope");
        let s = store.shared.state.lock().unwrap();
        assert!(s.expirations.is_empty());
        assert!(s.expiration_keys.is_empty());
    }

    #[rocket::async_test]
    async fn remove_cleans_up_expirations() {
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
        store.create("u2".into(), dummy_filestate());
        store.remove("u2");
        let s = store.shared.state.lock().unwrap();
        assert!(s.files.is_empty());
        assert!(s.expirations.is_empty());
        assert!(s.expiration_keys.is_empty());
    }

    /// A unique temp directory holding a test database, laid out the way a
    /// deployment does it: `usage_db` inside the upload `data_dir`, so a test
    /// that exercises the boot-time partial-file sweep also proves the sweep
    /// leaves the database sitting next to those files alone. Removed on drop.
    struct TempDbPath {
        dir: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    impl TempDbPath {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("cryptify-state-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create temp state dir");
            let path = dir.join("state.db");
            TempDbPath { dir, path }
        }

        fn as_str(&self) -> &str {
            self.path.to_str().unwrap()
        }

        /// The `data_dir` uploads are written into — also where the database
        /// and its WAL/SHM sidecars live.
        fn data_dir(&self) -> &std::path::Path {
            &self.dir
        }
    }

    impl Drop for TempDbPath {
        fn drop(&mut self) {
            // Takes the database, its WAL/SHM sidecars and any partial upload
            // files a test left behind with it.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn store_with_db(db: &TempDbPath) -> Store {
        store_with_db_and_window(db, 14 * 24 * 60 * 60)
    }

    /// [`store_with_db`] with the rolling window spelled out. The usage tests
    /// assert against the same binding they pass here, so the window they
    /// enforce and the window they expect cannot disagree.
    fn store_with_db_and_window(db: &TempDbPath, rolling_window_secs: i64) -> Store {
        store_with_db_and_ttl(
            db,
            Duration::from_secs(DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS),
            rolling_window_secs,
        )
    }

    fn store_with_db_and_ttl(
        db: &TempDbPath,
        idle_ttl: Duration,
        rolling_window_secs: i64,
    ) -> Store {
        Store::with_idle_ttl(
            idle_ttl,
            Arc::new(Metrics::new()),
            Some(db.as_str()),
            db.data_dir(),
            rolling_window_secs,
        )
    }

    #[rocket::async_test]
    async fn usage_survives_simulated_restart() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;
        let window = 14 * 24 * 60 * 60;

        {
            let store = store_with_db_and_window(&db, window);
            store.record_upload("a@example.com".into(), 1_000_000_000, now - 3600);
            store.record_upload("a@example.com".into(), 2_000_000_000, now - 60);
            store.record_upload("b@example.com".into(), 500, now - 10);
            // store dropped here — simulates the pod going away.
        }

        // Fresh Store opening the same database file — simulates restart.
        let store = store_with_db_and_window(&db, window);
        let snap = store.get_usage("a@example.com", now);
        assert_eq!(
            snap.used_bytes, 3_000_000_000,
            "usage for a@ must be reloaded from the database after restart"
        );
        assert_eq!(snap.oldest_expires_at, Some(now - 3600 + window));
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
            let store = store_with_db(&db);
            store.record_upload("a@example.com".into(), 1_000, now - 100);
        }

        let store = store_with_db(&db);
        // A record made after the restart must add to the reloaded total.
        store.record_upload("a@example.com".into(), 2_000, now);
        assert_eq!(store.get_usage("a@example.com", now).used_bytes, 3_000);
    }

    #[rocket::async_test]
    async fn rolling_window_eviction_persists_across_restart() {
        let db = TempDbPath::new();
        let now: i64 = 2_000_000;
        let window = 14 * 24 * 60 * 60;

        {
            let store = store_with_db_and_window(&db, window);
            // One record well outside the window, one inside.
            store.record_upload("c@example.com".into(), 9_000, now - window - 10);
            store.record_upload("c@example.com".into(), 1_000, now - 60);
            // A later record at `now` triggers the database-side prune of the
            // stale row (DELETE WHERE timestamp < now - window).
            store.record_upload("c@example.com".into(), 2_000, now);
        }

        // After restart only the two in-window records should remain — the
        // expired one must have been evicted from the database, not just the
        // in-memory cache.
        let store = store_with_db_and_window(&db, window);
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
        let window = 14 * 24 * 60 * 60;

        {
            let store = store_with_db_and_window(&db, window);
            // Record that is in-window now but will fall out by `later`.
            store.record_upload("d@example.com".into(), 4_000, now);
        }

        let store = store_with_db_and_window(&db, window);
        // Immediately after reload the record counts.
        assert_eq!(store.get_usage("d@example.com", now).used_bytes, 4_000);
        // Far in the future it has rolled out of the window.
        let later = now + window + 1;
        assert_eq!(store.get_usage("d@example.com", later).used_bytes, 0);
    }

    #[rocket::async_test]
    async fn pruning_removes_only_expired_records() {
        let window = 14 * 24 * 60 * 60;
        let store = Store::new(Arc::new(Metrics::new()), window);
        let now: i64 = 2_000_000;
        store.record_upload("c@example.com".into(), 1_000, now - window - 10);
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
    /// A stand-in for the hex the real mint produces, distinguishable from
    /// every other string in the row.
    const CHALLENGE_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    /// 2100-01-01, so the 14-day on-disk expiry never lapses mid-test and a
    /// restore that drops the session is the idle window's doing, not this.
    const EXPIRES_AT: i64 = 4_102_444_800;

    /// A `FileState` with every persisted field set to something
    /// distinguishable, so a column swapped for its neighbour fails.
    fn populated_filestate() -> FileState {
        FileState {
            uploaded: 0,
            cryptify_token: "init-token".to_owned(),
            expires: EXPIRES_AT,
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
            recovery_token_hash: hash_recovery_token(RECOVERY_TOKEN),
            challenge: Some(CHALLENGE_HEX.to_owned()),
            sender_claim: None,
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
        let store = store_with_db(&db);
        store.create("session-1".into(), populated_filestate());

        let row = read_back(db.as_str(), "session-1").expect("row visible after init");
        assert_eq!(row.uuid, "session-1");
        assert_eq!(row.cryptify_token, "init-token");
        assert_eq!(row.uploaded, 0);
        assert_eq!(row.expires, EXPIRES_AT);
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
        assert_eq!(row.challenge.as_deref(), Some(CHALLENGE_HEX));
        assert_eq!(
            row.sender_claim, None,
            "nothing is proved until finalize verifies it"
        );
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
        let store = store_with_db(&db);
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
        let store = store_with_db(&db);
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
        let store = store_with_db(&db);
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
        let store = store_with_db(&db);
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
        let store = store_with_db_and_ttl(&db, Duration::from_millis(20), 14 * 24 * 60 * 60);
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
        let store = Store::new(Arc::new(Metrics::new()), 14 * 24 * 60 * 60);
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
            let store = store_with_db(&db);
            store.create("session-7".into(), populated_filestate());
        }
        // Second boot must find the table already there (CREATE TABLE IF NOT
        // EXISTS) and the row with it.
        let store = store_with_db(&db);
        assert!(
            read_back(db.as_str(), "session-7").is_some(),
            "the row must still be there after a reopen"
        );
        assert!(
            store.get("session-7").is_some(),
            "a live session must come back into memory on the next boot"
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

        let store = store_with_db(&db);
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

    // ---------------------------------------------------------------------
    // Restore on boot (postguard#303).
    //
    // Same shape as the write-through tests above: state is written by one
    // `Store`, that `Store` is dropped, and a second one opens the same file —
    // so these assert what a restarting process finds on disk, not what the
    // writer believed it wrote.
    // ---------------------------------------------------------------------

    /// Backdate a row's `last_active_at` through a second connection, so the
    /// next boot sees a session that idled out while the process was down.
    /// Rewriting the column beats sleeping through a real idle window.
    fn backdate_last_active(db: &TempDbPath, uuid: &str, seconds_ago: i64) {
        let conn = rusqlite::Connection::open(db.as_str()).expect("open state database");
        let now = chrono::offset::Utc::now().timestamp();
        let changed = conn
            .execute(
                "UPDATE upload_sessions SET last_active_at = ?2 WHERE uuid = ?1",
                rusqlite::params![uuid, now - seconds_ago],
            )
            .expect("backdate last_active_at");
        assert_eq!(changed, 1, "backdating must hit exactly one row");
    }

    /// Write a stand-in for the partial upload a chunk PUT would have left in
    /// `data_dir`, named after the session the way the handlers name it.
    fn write_partial(db: &TempDbPath, uuid: &str) {
        std::fs::write(db.data_dir().join(uuid), b"half an upload").expect("write partial file");
    }

    fn partial_exists(db: &TempDbPath, uuid: &str) -> bool {
        db.data_dir().join(uuid).exists()
    }

    #[rocket::async_test]
    async fn a_live_session_is_restored_field_for_field() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("live-1".into(), populated_filestate());
        }

        let store = store_with_db(&db);
        let handle = store.get("live-1").expect("session restored on boot");
        let state = handle.lock().await;

        // Every column that a later request reads has to come back intact,
        // not just the ones the resume path happens to touch first.
        assert_eq!(state.cryptify_token, "init-token");
        assert_eq!(state.uploaded, 0);
        assert_eq!(state.expires, EXPIRES_AT);
        assert_eq!(
            state.recipients.to_string(),
            RECIPIENTS
                .parse::<lettre::message::Mailboxes>()
                .unwrap()
                .to_string()
        );
        assert_eq!(state.mail_content, "hello <b>world</b>");
        assert_eq!(state.mail_lang, email::Language::Nl);
        assert!(state.confirm);
        assert!(!state.notify_recipients);
        assert_eq!(state.source_channel, "website");
        assert_eq!(state.client_version.as_deref(), Some("web,1.2,pg-js,2.3.3"));
        assert_eq!(state.client_app.as_deref(), Some("pg-js"));
        assert_eq!(state.api_key_tenant.as_deref(), Some("tenant-a"));
        assert!(!state.api_key_validation_failed);
        assert_eq!(state.sender, None);
        assert!(state.sender_attributes.is_empty());
        assert_eq!(
            state.challenge.as_deref(),
            Some(CHALLENGE_HEX),
            "an upload interrupted by a restart must still be able to answer \
             the challenge it was given"
        );
        assert_eq!(state.sender_claim, None);
        assert!(state.last_chunk.is_none(), "no chunk was committed");
        assert_eq!(
            state.recovery_token_hash,
            hash_recovery_token(RECOVERY_TOKEN),
            "the digest the status endpoint authenticates against must survive"
        );
    }

    /// A finalized session carries both halves of the proof — the challenge it
    /// issued and the claim it settled on — and a restart must not turn a
    /// `Proven` sender into anything else.
    #[rocket::async_test]
    async fn a_restored_session_keeps_its_challenge_and_claim() {
        let claim = SenderClaim::Proven {
            email: "bob@example.com".to_owned(),
            attrs: vec![(
                "pbdf.gemeente.personalData.name".to_owned(),
                "Bob".to_owned(),
            )],
        };

        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("live-claim".into(), populated_filestate());
            let handle = store.get("live-claim").expect("live session");
            let mut state = handle.lock().await;
            // What `upload_finalize` writes once the proof has been checked.
            state.sender = Some("bob@example.com".to_owned());
            state.sender_claim = Some(claim.clone());
            store.persist_session("live-claim", &state);
        }

        let store = store_with_db(&db);
        let handle = store.get("live-claim").expect("session restored on boot");
        let state = handle.lock().await;
        assert_eq!(state.challenge.as_deref(), Some(CHALLENGE_HEX));
        assert_eq!(state.sender_claim, Some(claim));
    }

    /// An `Unproven` claim has to survive as `Unproven` rather than as "no
    /// claim yet": the two are different states, and only the first means
    /// finalize has already run and settled the question.
    #[rocket::async_test]
    async fn a_restored_session_keeps_an_unproven_claim() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("live-unproven".into(), populated_filestate());
            let handle = store.get("live-unproven").expect("live session");
            let mut state = handle.lock().await;
            state.sender_claim = Some(SenderClaim::Unproven);
            store.persist_session("live-unproven", &state);
        }

        let store = store_with_db(&db);
        let handle = store
            .get("live-unproven")
            .expect("session restored on boot");
        assert_eq!(
            handle.lock().await.sender_claim,
            Some(SenderClaim::Unproven)
        );
    }

    /// The fallback in `PersistedSession::from_state` is a literal, so it has
    /// to keep matching what serde actually writes for `Unproven`.
    #[test]
    fn sender_claim_unproven_encodes_to_the_fallback() {
        assert_eq!(
            serde_json::to_string(&SenderClaim::Unproven).expect("encode Unproven"),
            UNPROVEN_JSON
        );
    }

    /// A deployed database has its `upload_sessions` table already, so
    /// `CREATE TABLE IF NOT EXISTS` never adds a column to it — the migration
    /// has to. Build the table as the version before this change wrote it,
    /// seed a row, and boot: the row must survive and load, and new writes
    /// must reach the added columns.
    #[rocket::async_test]
    async fn a_sessions_table_without_the_proof_columns_gains_them() {
        let db = TempDbPath::new();
        let now = chrono::offset::Utc::now().timestamp();
        {
            let conn = rusqlite::Connection::open(db.as_str()).expect("open bare database");
            conn.execute(
                "CREATE TABLE upload_sessions (
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
            )
            .expect("create the pre-migration sessions table");
            conn.execute(
                "INSERT INTO upload_sessions (
                     uuid, cryptify_token, recovery_token_hash, uploaded, expires,
                     recipients, mail_content, mail_lang, confirm, notify_recipients,
                     source_channel, api_key_validation_failed, sender_attributes,
                     created_at, last_active_at
                 ) VALUES (
                     'legacy-1', 'legacy-token', 'legacy-hash', 17, ?1,
                     ?2, 'legacy content', 'EN', 1, 1,
                     'website', 0, '[]',
                     ?3, ?3
                 )",
                rusqlite::params![EXPIRES_AT, RECIPIENTS, now],
            )
            .expect("seed a pre-migration row");
        }

        let store = store_with_db(&db);

        // The row a deployment already had must come back, and come back
        // without a challenge or a claim — there is nothing else it could have.
        let handle = store.get("legacy-1").expect("pre-migration row restored");
        {
            let state = handle.lock().await;
            assert_eq!(state.cryptify_token, "legacy-token");
            assert_eq!(state.uploaded, 17);
            assert_eq!(state.challenge, None);
            assert_eq!(state.sender_claim, None);
        }

        // And the added columns are writable, so a session created after the
        // migration persists its challenge into the migrated table.
        store.create("after-migration".into(), populated_filestate());
        let row = read_back(db.as_str(), "after-migration").expect("row written after migration");
        assert_eq!(row.challenge.as_deref(), Some(CHALLENGE_HEX));
    }

    /// Booting twice must not try to add the columns again — `ADD COLUMN` on a
    /// column that exists is an error, so a second boot would fail the open.
    #[rocket::async_test]
    async fn the_proof_column_migration_is_a_no_op_on_a_migrated_database() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("twice-1".into(), populated_filestate());
        }

        let store = store_with_db(&db);
        assert_eq!(
            store
                .get("twice-1")
                .expect("session restored on the second boot")
                .lock()
                .await
                .challenge
                .as_deref(),
            Some(CHALLENGE_HEX)
        );
    }

    #[rocket::async_test]
    async fn a_restored_session_keeps_its_replay_record() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("live-2".into(), populated_filestate());
            let handle = store.get("live-2").expect("live session");
            let mut state = handle.lock().await;
            state.cryptify_token = "chunk-1-token".to_owned();
            state.uploaded = 1_048_576;
            state.last_chunk = Some(LastChunkRecord {
                prev_token: "init-token".to_owned(),
                prev_uploaded: 0,
                response_token: "chunk-1-token".to_owned(),
            });
            store.persist_session("live-2", &state);
        }

        let store = store_with_db(&db);
        let handle = store.get("live-2").expect("session restored on boot");
        let state = handle.lock().await;
        assert_eq!(state.cryptify_token, "chunk-1-token");
        assert_eq!(state.uploaded, 1_048_576);
        // Without this the first thing a reconnecting client does — retry the
        // chunk whose response it never saw — is rejected as a token mismatch.
        let last = state.last_chunk.as_ref().expect("replay record restored");
        assert_eq!(last.prev_token, "init-token");
        assert_eq!(last.prev_uploaded, 0);
        assert_eq!(last.response_token, "chunk-1-token");
    }

    #[rocket::async_test]
    async fn a_restored_session_can_still_be_touched_and_evicted() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("live-3".into(), populated_filestate());
        }

        // A restored entry has to land in `expirations` and `expiration_keys`
        // too, or it would never be evicted and `touch` would silently do
        // nothing on every chunk PUT after the restart.
        let store = store_with_db(&db);
        let before = store.deadline_for("live-3").expect("restored deadline");
        rocket::tokio::time::sleep(Duration::from_millis(10)).await;
        store.touch("live-3");
        let after = store.deadline_for("live-3").expect("deadline after touch");
        assert!(
            after > before,
            "touch must move a restored session's deadline"
        );

        store.remove("live-3");
        assert!(store.get("live-3").is_none());
        assert!(read_back(db.as_str(), "live-3").is_none());
    }

    #[rocket::async_test]
    async fn the_idle_window_keeps_running_while_the_process_is_down() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("idled-out".into(), populated_filestate());
        }
        // Idle for longer than the window, all of it while down.
        backdate_last_active(
            &db,
            "idled-out",
            DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS as i64 + 60,
        );

        let store = store_with_db(&db);
        assert!(
            store.get("idled-out").is_none(),
            "a restart must not hand a dead session a fresh idle window"
        );
        assert!(
            read_back(db.as_str(), "idled-out").is_none(),
            "the row of a session that expired while down must be deleted"
        );
    }

    #[rocket::async_test]
    async fn a_session_that_idled_out_while_down_loses_its_partial_file() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("orphan".into(), populated_filestate());
        }
        write_partial(&db, "orphan");
        backdate_last_active(
            &db,
            "orphan",
            DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS as i64 + 60,
        );

        let store = store_with_db(&db);
        assert!(store.get("orphan").is_none());
        assert!(
            !partial_exists(&db, "orphan"),
            "the half-written file of an unresumable session must not be left behind"
        );
        // The sweep only ever names files it holds a row for, so the state
        // database living in the same directory is untouched.
        assert!(
            std::path::Path::new(db.as_str()).exists(),
            "the sweep must not touch anything in data_dir it has no row for"
        );
    }

    #[rocket::async_test]
    async fn a_live_session_keeps_its_partial_file() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("resumable".into(), populated_filestate());
        }
        write_partial(&db, "resumable");

        let store = store_with_db(&db);
        assert!(store.get("resumable").is_some());
        assert!(
            partial_exists(&db, "resumable"),
            "the bytes an in-flight upload already sent must survive the restart"
        );
    }

    #[rocket::async_test]
    async fn an_expired_finalized_session_keeps_its_file() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("finalized".into(), populated_filestate());
            let handle = store.get("finalized").expect("live session");
            let mut state = handle.lock().await;
            state.sender = Some("bob@example.com".to_owned());
            store.persist_session("finalized", &state);
        }
        write_partial(&db, "finalized");
        backdate_last_active(
            &db,
            "finalized",
            DEFAULT_UPLOAD_SESSION_IDLE_TIMEOUT_SECS as i64 + 60,
        );

        let store = store_with_db(&db);
        assert!(
            store.get("finalized").is_none(),
            "the session still idled out"
        );
        assert!(
            partial_exists(&db, "finalized"),
            "a finalized upload's file is waiting to be downloaded for 14 days, not an orphan"
        );
    }

    #[rocket::async_test]
    async fn a_session_past_its_on_disk_expiry_is_not_restored() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            let mut filestate = populated_filestate();
            // Active seconds ago, but past the 14-day deadline: the two
            // clocks are independent and either one alone must drop it.
            filestate.expires = chrono::offset::Utc::now().timestamp() - 1;
            store.create("aged-out".into(), filestate);
        }
        write_partial(&db, "aged-out");

        let store = store_with_db(&db);
        assert!(store.get("aged-out").is_none());
        assert!(read_back(db.as_str(), "aged-out").is_none());
        assert!(!partial_exists(&db, "aged-out"));
    }

    #[rocket::async_test]
    async fn an_unreadable_row_is_skipped_without_losing_the_file() {
        let db = TempDbPath::new();
        {
            let store = store_with_db(&db);
            store.create("corrupt".into(), populated_filestate());
        }
        write_partial(&db, "corrupt");
        {
            let conn = rusqlite::Connection::open(db.as_str()).expect("open state database");
            conn.execute(
                "UPDATE upload_sessions SET mail_lang = 'XX' WHERE uuid = 'corrupt'",
                [],
            )
            .expect("corrupt the row");
        }

        // Nothing can be resumed from a row this binary cannot read, but
        // guessing is worse than waiting: leave both the row and the file for
        // the expiry sweep rather than deleting data over a parse failure.
        let store = store_with_db(&db);
        assert!(store.get("corrupt").is_none());
        assert!(
            read_back(db.as_str(), "corrupt").is_some(),
            "an unreadable row must not be deleted"
        );
        assert!(partial_exists(&db, "corrupt"));
    }

    #[rocket::async_test]
    async fn restoring_sessions_does_not_disturb_the_usage_table() {
        let db = TempDbPath::new();
        let now: i64 = chrono::offset::Utc::now().timestamp();
        {
            let store = store_with_db(&db);
            store.record_upload("a@example.com".into(), 7_000, now - 60);
            store.create("both-tables".into(), populated_filestate());
        }

        let store = store_with_db(&db);
        assert_eq!(store.get_usage("a@example.com", now).used_bytes, 7_000);
        assert!(store.get("both-tables").is_some());
    }
}
