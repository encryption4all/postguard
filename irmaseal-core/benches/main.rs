use futures::executor::block_on;
use futures::io::AllowStdIo;
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;
use irmaseal_core::stream::seal;
use irmaseal_core::{Policy, PublicKey, RecipientIdentifier};
use rand::{CryptoRng, RngCore};
use std::io::Cursor;

use criterion::*;

// Keep in mind that for small payloads the cost of IBE will outweigh the cost of symmetric
// encryption. Also, large conjunctions will also take longer to derive an identity from.
fn bench_seal<Rng: RngCore + CryptoRng>(
    plain: &Vec<u8>,
    mpk: &PublicKey<CGWFO>,
    rng: &mut Rng,
) -> Vec<u8> {
    let mut input = AllowStdIo::new(Cursor::new(plain));
    let mut output = AllowStdIo::new(Vec::new());

    block_on(async {
        seal(
            &[&RecipientIdentifier::from("test")],
            &[&Policy {
                timestamp: 1566722350,
                con: vec![],
            }],
            &mpk,
            rng,
            &mut input,
            &mut output,
        )
        .await
        .unwrap();
    });

    output.into_inner()
}

fn rand_vec(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}

fn bench(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let (tmpk, _) = ibe::kem::cgw_fo::CGWFO::setup(&mut rng);
    let mpk = PublicKey::<CGWFO>(tmpk);

    let mut group = c.benchmark_group("throughput-seal");

    for l in [1024, 65536, 1048576, 16777216, 67108864] {
        let input = rand_vec(l);
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function(format!("seal {} KiB", input.len() / 1024), |b| {
            b.iter(|| bench_seal(&input, &mpk, &mut rng))
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
