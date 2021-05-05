use clap::ArgMatches;
use irmaseal_core::stream::Unsealer;
use irmaseal_core::{api::*, stream::Readable, MetadataReader, MetadataReaderResult};

use core::panic;
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

    let file_ext = format!(".{}", crate::util::IRMASEALEXT);

    let out_file_name = if input.ends_with(&file_ext) {
        &input[..input.len() - file_ext.len()]
    } else {
        panic!("Input file name does not end with .irma")
    };

    let mut r = crate::util::FileReader::new(std::fs::File::open(input).unwrap());

    let read_blocks_size = 32;
    let mut meta_reader = MetadataReader::new();

    let (_, header, metadata) = loop {
        let read_size = std::cmp::min(read_blocks_size, meta_reader.get_safe_write_size());
        match meta_reader
            .write(r.read_bytes_strict(read_size).unwrap())
            .unwrap()
        {
            MetadataReaderResult::Hungry => continue,
            MetadataReaderResult::Saturated {
                unconsumed,
                header,
                metadata,
            } => break (unconsumed, header, metadata),
        }
    };

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

    if let Some(kr) = wait_on_session(client, &sp, timestamp).await.unwrap() {
        eprintln!("Disclosure successful, decrypting {}", input);

        let mut unsealer = crate::util::FileUnsealerRead::new(
            Unsealer::new(&metadata, header, &kr.key.unwrap(), r).unwrap(),
        );

        std::io::copy(
            &mut unsealer,
            &mut std::fs::File::create(out_file_name).unwrap(),
        )
        .unwrap();

        eprintln!("Succesfully decrypted.");
    } else {
        eprintln!("Did not scan the QR code and disclose in time");
    };
}
