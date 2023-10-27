use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::Sealer;

use futures::executor::block_on;
use futures::io::AllowStdIo;
use pg_core::test::TestSetup;
use rand::{CryptoRng, RngCore};
use std::io::Cursor;

use criterion::*;

// Keep in mind that for small payloads the cost of IBE will outweigh the cost of symmetric
// encryption. Also, large conjunctions will also take longer to derive an identity from.
fn bench_seal<Rng: RngCore + CryptoRng>(plain: &[u8], rng: &mut Rng) {
    let mut input = AllowStdIo::new(Cursor::new(plain));
    let mut output = futures::io::sink();

    let setup = TestSetup::new(rng);
    let signing_key = &setup.signing_keys[0];

    block_on(async {
        Sealer::<_, SealerStreamConfig>::new(&setup.ibe_pk, &setup.policy, signing_key, rng)
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

    let mut group = c.benchmark_group("throughput-seal");
    group.sample_size(10);

    for blen in [10, 14, 18, 22, 26, 30] {
        let input = rand_vec(1 << blen);
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function(format!("seal {} KiB", input.len() / 1024), |b| {
            b.iter(|| bench_seal(&input, &mut rng))
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
