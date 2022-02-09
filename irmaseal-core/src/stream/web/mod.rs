pub mod aesgcm;
pub mod sealer;
pub mod unsealer;

use crate::constants::*;

fn aead_nonce(nonce: &[u8], counter: u32, last_block: bool) -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];

    iv[..NONCE_SIZE].copy_from_slice(nonce);
    iv[NONCE_SIZE..IV_SIZE - 1].copy_from_slice(&counter.to_be_bytes());
    iv[IV_SIZE - 1] = last_block as u8;

    iv
}
