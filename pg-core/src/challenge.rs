//! Proving possession of a PKG-issued signing key.
//!
//! A holder of a [`SigningKeyExt`] signs a challenge chosen by the party that
//! wants the proof; that party verifies it with the [`VerifyingKey`] and the
//! [`Policy`] whose identity it expects. Nothing here touches a container: it
//! is a live proof that whoever is talking holds the signing key belonging to
//! an identity, not a statement about data at rest.
//!
//! The signing key that signs a challenge is the same one that signs container
//! headers, so a challenge signature must never be mistakable for a header
//! signature. [`CHALLENGE_DOMAIN`] is what keeps the two apart, and
//! [`sign_challenge`] applies it itself: a verifier hands over a challenge and
//! a context, never the leading bytes of the signed message. Were the domain
//! separator an argument, a malicious verifier could pass a serialized header
//! as the "challenge" and get back a signature valid on a container it wrote.
//!
//! `context` names what the proof is for — an endpoint, an upload id, a
//! session. It is signed alongside the challenge so a proof collected for one
//! purpose does not replay into another.
//!
//! ```rust
//! use pg_core::challenge::{sign_challenge, verify_challenge};
//! # use pg_core::test::TestSetup;
//!
//! let mut rng = rand::thread_rng();
//! # let setup = TestSetup::new(&mut rng);
//! let signing_key = &setup.signing_keys[0];
//!
//! // The verifier picks the challenge; the signer never chooses it.
//! let challenge = b"32 random bytes from the verifier";
//!
//! let sig = sign_challenge(signing_key, "cryptify/upload", challenge, &mut rng);
//!
//! assert!(verify_challenge(
//!     &setup.ibs_pk,
//!     &signing_key.policy,
//!     "cryptify/upload",
//!     challenge,
//!     &sig,
//! ));
//! ```

use alloc::vec::Vec;

use crate::artifacts::{SigningKeyExt, VerifyingKey};
use crate::identity::Policy;

use ibs::gg::{Signature, Signer, Verifier};
use rand::{CryptoRng, RngCore};

/// Domain separator for upload-possession challenges. Applied by the
/// signer, never taken from the verifier's input.
pub const CHALLENGE_DOMAIN: &[u8] = b"postguard/challenge/v1";

/// Builds the message a challenge signature is made over.
///
/// Both variable-length parts are length-prefixed rather than concatenated
/// raw, so exactly one `(context, challenge)` pair maps to any message. Plain
/// concatenation would make `("ab", "c")` and `("a", "bc")` the same bytes,
/// which turns a proof collected under one context into a proof under another.
fn challenge_message(context: &str, challenge: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        CHALLENGE_DOMAIN.len() + 2 * core::mem::size_of::<u64>() + context.len() + challenge.len(),
    );

    msg.extend_from_slice(CHALLENGE_DOMAIN);
    msg.extend_from_slice(&(context.len() as u64).to_be_bytes());
    msg.extend_from_slice(context.as_bytes());
    msg.extend_from_slice(&(challenge.len() as u64).to_be_bytes());
    msg.extend_from_slice(challenge);

    msg
}

/// Signs a verifier-chosen challenge, proving possession of `key`.
///
/// [`CHALLENGE_DOMAIN`] is prepended here and cannot be opted out of, so the
/// result is never a valid signature over anything else PostGuard signs — see
/// the module documentation.
///
/// # Arguments
///
/// * `key`       - The signing key to prove possession of.
/// * `context`   - What the proof is for, e.g. an endpoint or an upload id.
/// * `challenge` - The bytes chosen by the verifier.
/// * `rng`       - A cryptographically secure random number generator.
pub fn sign_challenge<R: RngCore + CryptoRng>(
    key: &SigningKeyExt,
    context: &str,
    challenge: &[u8],
    rng: &mut R,
) -> Signature {
    Signer::new()
        .chain(challenge_message(context, challenge))
        .sign(&key.key.0, rng)
}

/// Verifies a challenge signature against the identity derived from `pol`.
///
/// Returns `false` for a signature that does not verify, and for a policy no
/// identity can be derived from.
///
/// The identity comes from [`Policy::derive_ibs`], which canonicalizes
/// attribute values. So this answers "does the signer hold the key for the
/// identity this policy derives to", not "does the signer's policy read
/// exactly like this one": a policy spelling an e-mail address
/// `Alice@Example.COM` verifies against a key issued for
/// `alice@example.com`. A caller that keys on the raw attribute value has to
/// canonicalize it itself; the proof does not pin spelling.
///
/// # Arguments
///
/// * `vk`        - The IBS verifying key (master public key).
/// * `pol`       - The policy whose identity the signer is expected to hold a key for.
/// * `context`   - The same context the signature was requested under.
/// * `challenge` - The bytes this verifier chose.
/// * `sig`       - The signature to check.
pub fn verify_challenge(
    vk: &VerifyingKey,
    pol: &Policy,
    context: &str,
    challenge: &[u8],
    sig: &Signature,
) -> bool {
    let Ok(id) = pol.derive_ibs() else {
        return false;
    };

    Verifier::default()
        .chain(challenge_message(context, challenge))
        .verify(&vk.0, sig, &id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Attribute;
    use crate::test::TestSetup;
    use alloc::vec;

    const CONTEXT: &str = "cryptify/upload";
    const CHALLENGE: &[u8] = b"a verifier-chosen challenge";

    #[test]
    fn test_challenge_roundtrip() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key = &setup.signing_keys[0];

        let sig = sign_challenge(key, CONTEXT, CHALLENGE, &mut rng);

        assert!(verify_challenge(
            &setup.ibs_pk,
            &key.policy,
            CONTEXT,
            CHALLENGE,
            &sig
        ));
    }

    #[test]
    fn test_challenge_wrong_identity_fails() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key_a = &setup.signing_keys[0];
        let pol_b = &setup.signing_keys[1].policy;

        let sig = sign_challenge(key_a, CONTEXT, CHALLENGE, &mut rng);

        assert!(!verify_challenge(
            &setup.ibs_pk,
            pol_b,
            CONTEXT,
            CHALLENGE,
            &sig
        ));
    }

    #[test]
    fn test_challenge_wrong_challenge_fails() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key = &setup.signing_keys[0];

        let sig = sign_challenge(key, CONTEXT, b"challenge X", &mut rng);

        assert!(!verify_challenge(
            &setup.ibs_pk,
            &key.policy,
            CONTEXT,
            b"challenge Y",
            &sig
        ));
    }

    #[test]
    fn test_challenge_wrong_context_fails() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key = &setup.signing_keys[0];

        let sig = sign_challenge(key, "a", CHALLENGE, &mut rng);

        assert!(!verify_challenge(
            &setup.ibs_pk,
            &key.policy,
            "b",
            CHALLENGE,
            &sig
        ));
    }

    /// Length prefixes are what make the signed message unambiguous. Without
    /// them `("ab", "c")` and `("a", "bc")` concatenate to the same bytes, and
    /// a proof handed over for one context replays into the other.
    #[test]
    fn test_challenge_split_is_unambiguous() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key = &setup.signing_keys[0];

        let sig = sign_challenge(key, "ab", b"c", &mut rng);

        assert!(!verify_challenge(
            &setup.ibs_pk,
            &key.policy,
            "a",
            b"bc",
            &sig
        ));

        assert_ne!(challenge_message("ab", b"c"), challenge_message("a", b"bc"));
    }

    /// A signature over the raw challenge, as the header path would make it,
    /// is not a challenge proof: [`CHALLENGE_DOMAIN`] separates the two, which
    /// is why no caller can pass it in.
    #[test]
    fn test_challenge_domain_separates_from_undomained_signature() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);
        let key = &setup.signing_keys[0];

        let sig = Signer::new().chain(CHALLENGE).sign(&key.key.0, &mut rng);

        assert!(!verify_challenge(
            &setup.ibs_pk,
            &key.policy,
            CONTEXT,
            CHALLENGE,
            &sig
        ));
    }

    /// `derive_ibs` canonicalizes, so a policy that spells the e-mail address
    /// differently derives the same identity and verifies. Asserted rather
    /// than assumed: a consumer keying on the raw attribute value has to
    /// canonicalize it itself.
    #[test]
    fn test_challenge_verifies_under_non_canonical_policy() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // `signing_keys[0]` is issued for `alice@example.com`.
        let key = &setup.signing_keys[0];
        let non_canonical = Policy {
            timestamp: key.policy.timestamp,
            con: vec![Attribute::new(
                "pbdf.sidn-pbdf.email.email",
                Some("Alice@Example.COM"),
            )],
        };

        assert_ne!(non_canonical, key.policy);

        let sig = sign_challenge(key, CONTEXT, CHALLENGE, &mut rng);

        assert!(verify_challenge(
            &setup.ibs_pk,
            &non_canonical,
            CONTEXT,
            CHALLENGE,
            &sig
        ));
    }
}
