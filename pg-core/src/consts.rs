//! Constants used in the PostGuard protocol.

/// Version 0 (legacy).
///
/// This version used the Kiltz-Vahlis-1 scheme.
/// The header format was defined by Postcard, but is no longer supported.
pub const VERSION_V1: u16 = 0;

/// Version 1 (legacy).
///
/// This version uses the CGW anonymous IBE scheme to construct a KEM variant. This scheme can
/// encapsulate the same shared secret for multiple recipients. This version also supports
/// conjunctions. For this version we required the header to be dynamic.
/// The header format is defined by MessagePack.
pub const VERSION_V2: u16 = 1;

/// Version 2.
///
/// This version uses the CGW anonymous IBE scheme to construct a KEM variant.
/// The scheme supports a Sign-then-Encrypt composition using the GG-IBS scheme.
/// The binary header format is defined by Bincode.
pub const VERSION_V3: u16 = 2;

/// The size of the tag with which all PostGuard bytestreams begin.
pub const PRELUDE_SIZE: usize = 4;

/// The tag bytes with which all PostGuard bytestreams begin.
pub const PRELUDE: [u8; PRELUDE_SIZE] = [0x14, 0x8A, 0x8E, 0xA7];

/// The size of the version identifier.
pub const VERSION_SIZE: usize = core::mem::size_of::<u16>();

/// The size of the header size.
pub const HEADER_SIZE_SIZE: usize = core::mem::size_of::<u32>();

/// The size of the signature size.
pub const SIG_SIZE_SIZE: usize = core::mem::size_of::<u32>();

/// The size of the policy size.
pub const POL_SIZE_SIZE: usize = core::mem::size_of::<u32>();

/// The maximum size of the header (1 MiB).
pub const MAX_HEADER_SIZE: usize = 1024 * 1024;

/// The maximum size of symmetric segments (4 MiB).
pub const MAX_SYMMETRIC_CHUNK_SIZE: u32 = 1024 * 1024 * 4;

/// The preamble contains the following bytes:
/// * Prelude: 4 bytes,
/// * Version identifier: 2 bytes,
/// * Size of header: 4 bytes,
/// * Totalling: 4 + 2 + 4 = 10 bytes.
pub const PREAMBLE_SIZE: usize = PRELUDE_SIZE + VERSION_SIZE + HEADER_SIZE_SIZE;

/// Default size of symmetric encryption segments, if in streaming mode.
///
/// A reasonable default is 256 KiB.
pub const SYMMETRIC_CRYPTO_DEFAULT_CHUNK: u32 = 256 * 1024;

// Symmetric crypto constants.
// This library uses AES128 because BLS12-381 is only secure up to around 120 bits.

/// Size of the symmetric key.
pub const KEY_SIZE: usize = 16;

/// Size of the initialization vector.
pub const IV_SIZE: usize = 12;

// The STREAM construction needs only 12 bytes:
// A 7-byte nonce, a 4-byte counter (u32) and an all-zero or all-one byte,
// depending on if the segment is the final segment.

/// Size of the nonce in the "STREAM" encryption construction.
pub const STREAM_NONCE_SIZE: usize = 7;

/// Size of the authentication tag.
/// The authentication tag is appended to each segment.
pub const TAG_SIZE: usize = 16;
