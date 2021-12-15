use futures::executor::block_on;
use futures::io::AllowStdIo;
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;
use irmaseal_core::stream::seal;
use irmaseal_core::{Attribute, Policy, PublicKey};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::io::Cursor;

use criterion::*;

// Keep in mind that for small payloads the cost of IBE will outweigh the cost of symmetric
// encryption. Also, large conjunctions will also take longer to derive an identity from.
fn bench_seal<Rng: RngCore + CryptoRng>(plain: &Vec<u8>, mpk: &PublicKey<CGWFO>, rng: &mut Rng) {
    let mut input = AllowStdIo::new(Cursor::new(plain));
    let mut output = futures::io::sink();

    let policies = BTreeMap::<String, Policy>::from([(
        String::from("test id"),
        Policy {
            timestamp: 0,
            con: vec![Attribute {
                atype: "test type".to_owned(),
                value: Some("test value".to_owned()),
            }],
        },
    )]);

    block_on(async {
        seal(&mpk, &policies, rng, &mut input, &mut output)
            .await
            .unwrap();
    });
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
