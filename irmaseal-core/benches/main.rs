use futures::executor::block_on;
use futures::io::AllowStdIo;
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;
use irmaseal_core::artifacts::PublicKey;
use irmaseal_core::identity::{Attribute, Policy, RecipientPolicy};
use irmaseal_core::rust::stream::StreamSealerConfig;
use irmaseal_core::Sealer;
use rand::{CryptoRng, RngCore};
use std::io::Cursor;

use criterion::*;

// Keep in mind that for small payloads the cost of IBE will outweigh the cost of symmetric
// encryption. Also, large conjunctions will also take longer to derive an identity from.
fn bench_seal<Rng: RngCore + CryptoRng>(plain: &[u8], mpk: &PublicKey<CGWKV>, rng: &mut Rng) {
    let mut input = AllowStdIo::new(Cursor::new(plain));
    let mut output = futures::io::sink();

    let policies = Policy::from([(
        String::from("test id"),
        RecipientPolicy {
            timestamp: 0,
            con: vec![Attribute {
                atype: "test type".to_owned(),
                value: Some("test value".to_owned()),
            }],
        },
    )]);

    block_on(async {
        Sealer::<StreamSealerConfig>::new(mpk, &policies, rng)
            .unwrap()
            .seal(&mut input, &mut output)
            .await
            .unwrap();
    });
}

fn rand_vec(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}

fn bench(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let (tmpk, _) = ibe::kem::cgw_kv::CGWKV::setup(&mut rng);
    let mpk = PublicKey::<CGWKV>(tmpk);

    let mut group = c.benchmark_group("throughput-seal");
    group.sample_size(10);

    for blen in [10, 14, 18, 22, 26, 30] {
        let input = rand_vec(1 << blen);
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function(format!("seal {} KiB", input.len() / 1024), |b| {
            b.iter(|| bench_seal(&input, &mpk, &mut rng))
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
