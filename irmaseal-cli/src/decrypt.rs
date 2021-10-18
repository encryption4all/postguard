use core::panic;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tokio::time::delay_for;

use crate::client::{Client, ClientError, OwnedKeyChallenge};
use crate::opts::DecOpts;
use crate::util::*;

use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;

use irmaseal_core::stream::Unsealer;
use irmaseal_core::{api::*, stream::Readable, Metadata, MetadataReader, MetadataReaderResult};

#[cfg(feature = "v1")]
use ibe::kem::kiltz_vahlis_one::KV1;

fn print_qr(s: &str) {
    let code = qrcode::QrCode::new(s).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    println!("\n\n{}", scode);
}

async fn wait_on_session<K: IBKEM>(
    client: &Client<'_>,
    sp: &OwnedKeyChallenge,
    timestamp: u64,
) -> Result<Option<KeyResponse<K>>, ClientError>
where
    KeyResponse<K>: DeserializeOwned,
{
    for _ in 0..120 {
        let r: KeyResponse<K> = client.result(&sp.token, timestamp).await?;

        if r.status != KeyStatus::DoneValid {
            delay_for(Duration::new(0, 500_000_000)).await;
        } else {
            return Ok(Some(r));
        }
    }

    Ok(None)
}

pub async fn exec(dec_opts: DecOpts) {
    let DecOpts { input, pkg } = dec_opts;

    eprintln!("Opening {}", input);

    let file_ext = format!(".{}", crate::util::IRMASEALEXT);

    let out_file_name = if input.ends_with(&file_ext) {
        &input[..input.len() - file_ext.len()]
    } else {
        panic!("Input file name does not end with .irma")
    };

    let mut r = crate::util::FileReader::new(std::fs::File::open(&input).unwrap());

    let read_blocks_size = 32;
    let mut meta_reader = MetadataReader::new();

    let (_, header, metadata, version) = loop {
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
                version,
            } => break (unconsumed, header, metadata, version),
        }
    };

    eprintln!("IRMASeal format version: {:#?}", version + 1);

    let identity = match metadata {
        #[cfg(feature = "v1")]
        Metadata::V1(ref m) => &m.identity,
        Metadata::V2(ref m) => &m.identity,
    };

    let timestamp = identity.timestamp;
    let client = Client::new(&pkg).unwrap();

    eprintln!("Requesting private key for {:#?}", identity.attribute);

    let sp: OwnedKeyChallenge = client
        .request(&KeyRequest {
            attribute: identity.attribute.clone(),
        })
        .await
        .unwrap();

    eprintln!("Please scan the following QR-code with IRMA:");

    print_qr(&sp.qr);

    let mut unsealer = match metadata {
        #[cfg(feature = "v1")]
        Metadata::V1(m) => {
            let kr = wait_on_session::<KV1>(&client, &sp, timestamp)
                .await
                .unwrap();
            FileUnsealerRead::new(
                Unsealer::new_v1(&m, header, &kr.unwrap().key.unwrap(), r).unwrap(),
            )
        }
        Metadata::V2(m) => {
            let kr = wait_on_session::<CGWFO>(&client, &sp, timestamp)
                .await
                .unwrap();
            let pars = client.parameters::<CGWFO>().await.unwrap();
            FileUnsealerRead::new(
                Unsealer::new_v2(&m, header, &kr.unwrap().key.unwrap(), &pars.public_key, r)
                    .unwrap(),
            )
        }
    };

    std::io::copy(
        &mut unsealer,
        &mut std::fs::File::create(out_file_name).unwrap(),
    )
    .unwrap();

    eprintln!("Successful decryption")
}
