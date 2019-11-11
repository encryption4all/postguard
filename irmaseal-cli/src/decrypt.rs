use clap::ArgMatches;
use irmaseal_core::api::*;
use irmaseal_core::stream::OpenerSealed;

use futures::future::{loop_fn, ok, Either, Future, Loop};
use std::time::{Duration, Instant};
use tokio::timer::Delay;

use crate::client::OwnedKeyChallenge;

fn print_qr(s: &str) {
    let code = qrcode::QrCode::new(s).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    println!("\n\n{}", scode);
}

pub fn exec(m: &ArgMatches) {
    let input = m.value_of("INPUT").unwrap();
    let output = m.value_of("OUTPUT").unwrap();

    let r = crate::util::FileReader::new(std::fs::File::open(input).unwrap());

    let (identity, o) = OpenerSealed::new(r).unwrap();
    let timestamp = identity.timestamp;

    let client = crate::client::Client::new("http://localhost:8087").unwrap();

    let res = client
        .request(&KeyRequest {
            attribute: identity.attribute,
        })
        .and_then(move |sp: OwnedKeyChallenge| {
            print_qr(&sp.qr);

            loop_fn(120, move |i: u8| {
                client
                    .result(&sp.token, timestamp)
                    .and_then(move |r: KeyResponse| {
                        if r.status != KeyStatus::DoneValid && i > 0 {
                            Either::A(
                                Delay::new(Instant::now() + Duration::new(0, 500_000_000))
                                    .then(move |_| Ok(Loop::Continue(i - 1))),
                            )
                        } else {
                            Either::B(ok(Loop::Break(r)))
                        }
                    })
            })
        })
        .and_then(move |r: KeyResponse| {
            let mut o = o.unseal(&r.key.unwrap()).unwrap();

            let mut of = crate::util::FileWriter::new(std::fs::File::create(output).unwrap());
            o.write_to(&mut of).unwrap();

            eprintln!("Succesfully decrypted {}", output);

            Ok(())
        });

    let mut rt = tokio::runtime::current_thread::Runtime::new().expect("new rt");
    rt.block_on(res).unwrap();
}
