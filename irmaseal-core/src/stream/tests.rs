use crate::stream::{seal, Unsealer};
use futures::{executor::block_on, io::AllowStdIo};
use rand::RngCore;
use std::io::Cursor;

use crate::test_common::TestSetup;
use crate::SYMMETRIC_CRYPTO_DEFAULT_CHUNK;

fn seal_helper(setup: &TestSetup, plain: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut input = AllowStdIo::new(Cursor::new(plain));
    let mut output = AllowStdIo::new(Vec::new());

    block_on(async {
        seal(
            &setup.mpk,
            &setup.policies,
            &mut rng,
            &mut input,
            &mut output,
        )
        .await
        .unwrap();
    });

    output.into_inner()
}

fn unseal_helper(setup: &TestSetup, ct: &[u8], recipient_idx: usize) -> Vec<u8> {
    let mut input = AllowStdIo::new(Cursor::new(ct));
    let mut output = AllowStdIo::new(Vec::new());

    let ids: Vec<String> = setup.policies.keys().cloned().collect();
    let id = &ids[recipient_idx];
    let usk_id = setup.usks.get(id).unwrap();

    block_on(async {
        let mut unsealer = Unsealer::new(&mut input).await.unwrap();

        // Normally, a user would need to retrieve a usk here via the PKG,
        // but in this case we own the master key pair.
        unsealer.unseal(id, usk_id, &mut output).await.unwrap();
    });

    output.into_inner()
}

fn seal_and_unseal(setup: &TestSetup, plain: Vec<u8>) {
    let ct = seal_helper(setup, &plain);
    let plain2 = unseal_helper(setup, &ct, 0);

    assert_eq!(&plain, &plain2);
}

fn rand_vec(length: usize) -> Vec<u8> {
    let mut vec = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut vec);
    vec
}

#[test]
fn test_reflection_seal_unsealer() {
    let setup = TestSetup::default();

    seal_and_unseal(&setup, rand_vec(1));
    seal_and_unseal(&setup, rand_vec(5));
    seal_and_unseal(&setup, rand_vec(32));
    seal_and_unseal(&setup, rand_vec(33));
    seal_and_unseal(&setup, rand_vec(511));
    seal_and_unseal(&setup, rand_vec(512));
    seal_and_unseal(&setup, rand_vec(1023));
    seal_and_unseal(&setup, rand_vec(60000));
    seal_and_unseal(&setup, rand_vec(SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 3));
}

#[test]
#[should_panic]
fn test_corrupt_body() {
    let setup = TestSetup::default();

    let plain = rand_vec(100);
    let mut ct = seal_helper(&setup, &plain);

    ct[1000] += 2;

    // This should panic.
    let _plain2 = unseal_helper(&setup, &ct, 1);
}

#[test]
#[should_panic]
fn test_corrupt_mac() {
    let setup = TestSetup::default();

    let plain = rand_vec(100);
    let mut ct = seal_helper(&setup, &plain);

    let len = ct.len();
    ct[len - 5] += 2;

    // This should panic as well.
    let _plain2 = unseal_helper(&setup, &ct, 1);
}
