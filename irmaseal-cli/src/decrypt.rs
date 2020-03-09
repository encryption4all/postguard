use clap::ArgMatches;
use irmaseal_core::api::*;
use irmaseal_core::stream::OpenerSealed;

use std::time::Duration;
use tokio::time::delay_for;

use crate::client::{Client, ClientError, OwnedKeyChallenge};

fn print_qr(s: &str) {
    let code = qrcode::QrCode::new(s).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    println!("\n\n{}", scode);
}

async fn wait_on_session(
    client: Client<'_>,
    sp: &OwnedKeyChallenge,
    timestamp: u64,
) -> Result<Option<KeyResponse>, ClientError> {
    for _ in 0..120 {
        let r: KeyResponse = client.result(&sp.token, timestamp).await?;

        if r.status != KeyStatus::DoneValid {
            delay_for(Duration::new(0, 500_000_000)).await;
        } else {
            return Ok(Some(r));
        }
    }

    Ok(None)
}

pub async fn exec(m: &ArgMatches<'_>) {
    let input = m.value_of("INPUT").unwrap();
    let output = m.value_of("OUTPUT").unwrap();
    let server = m.value_of("server").unwrap();

    eprintln!("Opening {}", input);

    let r = crate::util::FileReader::new(std::fs::File::open(input).unwrap());

    let (identity, o) = OpenerSealed::new(r).unwrap();
    let timestamp = identity.timestamp;

    let client = Client::new(server).unwrap();

    eprintln!("Requesting private key for {:#?}", identity.attribute);

    let sp: OwnedKeyChallenge = client
        .request(&KeyRequest {
            attribute: identity.attribute,
        })
        .await
        .unwrap();

    eprintln!("Please scan the following QR-code with IRMA:");

    print_qr(&sp.qr);

    if let Some(r) = wait_on_session(client, &sp, timestamp).await.unwrap() {
        eprintln!("Disclosure successful, decrypting {} to {}", input, output);

        let mut o = o.unseal(&r.key.unwrap()).unwrap();

        let mut of = crate::util::FileWriter::new(std::fs::File::create(output).unwrap());
        o.write_to(&mut of).unwrap();

        eprintln!("Succesfully decrypted {}", output);
    } else {
        eprintln!("Did not scan the QR code and disclose in time");
    };
}
