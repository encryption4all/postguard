use clap::ArgMatches;
use irmaseal_core::api::*;
use irmaseal_core::stream::OpenerSealed;
use tar::Archive;

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
    let server = m.value_of("server").unwrap();

    eprintln!("Opening {}", input);

    let r = crate::util::FileReader::new(std::fs::File::open(input).unwrap());

    let (metadata, sealed) = OpenerSealed::new(r).unwrap();

    let timestamp = metadata.identity.timestamp;

    let client = Client::new(server).unwrap();

    eprintln!(
        "Requesting private key for {:#?}",
        metadata.identity.attribute
    );

    let sp: OwnedKeyChallenge = client
        .request(&KeyRequest {
            attribute: metadata.identity.attribute.clone(),
        })
        .await
        .unwrap();

    eprintln!("Please scan the following QR-code with IRMA:");

    print_qr(&sp.qr);

    if let Some(r) = wait_on_session(client, &sp, timestamp).await.unwrap() {
        eprintln!("Disclosure successful, decrypting {}", input);

        let unsealed =
            crate::util::FileUnsealerRead::new(sealed.unseal(&metadata, &r.key.unwrap()).unwrap());

        let mut tar = Archive::new(unsealed);
        tar.unpack("./").unwrap();

        eprintln!("Succesfully decrypted.");
    } else {
        eprintln!("Did not scan the QR code and disclose in time");
    };
}
