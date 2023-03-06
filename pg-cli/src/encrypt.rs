use pg_core::api::IrmaAuthRequest;
use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::Sealer;
use pg_core::identity::{Attribute, Policy};

use crate::opts::EncOpts;
use crate::util::print_qr;
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::time::SystemTime;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn exec(enc_opts: EncOpts) {
    let mut rng = rand::thread_rng();

    let EncOpts {
        input,
        identity,
        pub_sign_id,
        priv_sign_id,
        pkg,
    } = enc_opts;

    let timestamp = now();

    let x: BTreeMap<String, Vec<Attribute>> = serde_json::from_str(&identity).unwrap();
    let identifiers: Vec<String> = x.keys().cloned().collect();
    let policies: BTreeMap<String, Policy> = x
        .iter()
        .map(|(id, con)| {
            (
                id.clone(),
                Policy {
                    timestamp,
                    con: con.clone(),
                },
            )
        })
        .collect();

    let pub_sig_id: Vec<Attribute> = serde_json::from_str(&pub_sign_id).unwrap();
    let client = crate::client::Client::new(&pkg).unwrap();

    let parameters = client.parameters().await.unwrap();

    eprintln!("Fetched parameters from {}", pkg);
    eprintln!(
        "Encrypting for the following recipients:\n{:#?}\n using the following policies:\n{}",
        identifiers,
        serde_json::to_string_pretty(&policies).unwrap()
    );

    eprintln!("retrieving signing keys...");

    let sd = client
        .request_start(&IrmaAuthRequest {
            con: pub_sig_id,
            validity: None,
        })
        .await
        .unwrap();

    print_qr(&sd.session_ptr);

    let pub_sign_key = client.wait_on_signing_key(&sd).await.unwrap().key.unwrap();

    let priv_sign_key = match priv_sign_id {
        Some(id) => {
            let priv_sign_id: Vec<Attribute> = serde_json::from_str(&id).unwrap();

            dbg!(&priv_sign_id);
            let sd = client
                .request_start(&IrmaAuthRequest {
                    con: priv_sign_id,
                    validity: None,
                })
                .await
                .unwrap();

            print_qr(&sd.session_ptr);

            let priv_sign_key = client.wait_on_signing_key(&sd).await.unwrap().key.unwrap();

            Some(priv_sign_key)
        }
        None => None,
    };

    let input_path = Path::new(&input);
    let file_name_path = input_path.file_name().unwrap();
    let file_name = file_name_path.to_str().unwrap();

    let output = format!("{}.{}", file_name, "enc");

    let source = File::open(input_path).unwrap();
    let destination = File::create(&output).unwrap();

    let pb = ProgressBar::new(source.metadata().unwrap().len());

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)")
        .progress_chars("#>-"));

    let r = AllowStdIo::new(pb.wrap_read(source));
    let w = AllowStdIo::new(destination);

    eprintln!("Encrypting {}...", input);

    let mut sealer = Sealer::<_, SealerStreamConfig>::new(
        &parameters.public_key,
        &policies,
        &pub_sign_key,
        &mut rng,
    )
    .unwrap();

    if let Some(key) = priv_sign_key {
        sealer = sealer.with_priv_signing_key(&key);
    };

    sealer.seal(r, w).await.unwrap();
}
