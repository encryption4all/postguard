use std::path::Path;

use rocket::tokio::{
    fs::{File, OpenOptions},
    io::{AsyncSeekExt, AsyncWriteExt},
};

use crate::error::Error;
use crate::GENERIC_INTERNAL_ERROR_MSG;

/// The only way `main.rs` touches an upload file's bytes: opening it and
/// writing a chunk both go through here, and there is no accessor, `Deref`,
/// or standalone `flush()` that would let a caller obtain a write that
/// bypasses it.
///
/// `rocket::tokio::fs::File` is buffered: `write_all` copies the bytes into
/// a buffer, queues the write onto the blocking pool, and returns before the
/// write syscall runs — dropping the file does not wait for it either.
/// `upload_finalize` opens the same file later, so a chunk PUT that
/// acknowledges before this happens can hand that later open a short or
/// empty file. Flushing makes the write **visible to a subsequent open in
/// this process**; it says nothing about durability across a crash, which is
/// a different property this type does not claim.
///
/// This is a wrapper rather than a flush call plus a test because the
/// violation window cannot be reliably observed at the handler level:
/// measured directly, a chunk PUT's bytes are not yet on disk at the instant
/// `write_all` returns about 99.6% of the time, but a full
/// `Client::tracked` request/response round trip gives the blocking pool
/// ample await points to land the write before a test is allowed to look.
/// Twenty samples taken after such a round trip are twenty samples of the
/// post-round-trip window, not of the 99.6% one — so the property has to be
/// made structurally impossible to violate, not merely tested for.
///
/// **Open flake watch, carried over from #399/#409.** #399 closed on the
/// flush fix without ever reproducing its failure (0/200 sequential, 0/2560
/// at 64-way concurrency). If `a_malformed_proof_header_leaves_the_sender_unproven`
/// reds again on `main` at or after `bcbf10e0`, the missing-flush hypothesis
/// is dead and the cause is elsewhere. Absence of a recurrence is weak
/// evidence on its own — the original was one occurrence in weeks — so this
/// is a watch, not a countdown; do not attempt to discharge it.
pub struct UploadFile {
    file: File,
}

impl UploadFile {
    /// Opens an existing upload file for writing. `uuid` is only used to
    /// shape the not-found error when the file is missing.
    pub async fn open(path: &Path, uuid: &str) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(|_| Error::upload_session_not_found(uuid.to_owned(), "file_missing"))?;
        Ok(UploadFile { file })
    }

    /// Seeks to `start`, writes `bytes`, and flushes, as a single operation
    /// with no return point in between — so a write this method reports as
    /// `Ok` is always visible to a subsequent open.
    pub async fn write_at(&mut self, start: u64, bytes: &[u8]) -> Result<(), Error> {
        self.file
            .seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| {
                log::error!("could not seek in upload file: {}", e);
                Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
            })?;

        self.file.write_all(bytes).await.map_err(|e| {
            log::error!("could not write chunk to upload file: {}", e);
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })?;

        self.file.flush().await.map_err(|e| {
            log::error!("could not flush chunk to upload file: {}", e);
            Error::InternalServerError(Some(GENERIC_INTERNAL_ERROR_MSG.to_owned()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Calls the wrapper directly and `stat`s the file synchronously, with
    /// no `await` between the write returning and the `std::fs::metadata`
    /// call. That recovers the ~99.6% per-observation signal a route
    /// round-trip hides (see the module doc comment).
    #[rocket::async_test]
    async fn write_at_is_visible_to_a_synchronous_stat() {
        let dir = std::env::temp_dir().join(format!("upload_file_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("chunk");
        std::fs::File::create(&path).expect("create empty upload file");

        let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut file = UploadFile::open(&path, "test-uuid")
            .await
            .expect("open must succeed");
        file.write_at(0, &bytes)
            .await
            .expect("write_at must succeed");

        let on_disk = std::fs::metadata(&path)
            .expect("upload file must exist on disk")
            .len();
        assert_eq!(on_disk, bytes.len() as u64);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
