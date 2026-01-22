use pg_core::api::{IrmaAuthRequest, SigningKeyRequest, SigningKeyResponse};
use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::Sealer;
use pg_core::identity::{Attribute, Policy};

use crate::opts::EncOpts;
use crate::util::print_qr;
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use pg_core::artifacts::SigningKeyExt;
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
        pub_sign_id: pub_sign_id_str,
        priv_sign_id,
        api_key,
        pkg,
    } = enc_opts;

    let timestamp = now();

    let x: BTreeMap<String, Vec<Attribute>> = match serde_json::from_str(identity.as_str()) {
        Ok(map) => map,
        Err(e) => {
            eprintln!(
                "Failed to parse `identity` JSON: {}\nInput was: {}",
                e, identity
            );
            std::process::exit(1);
        }
    };

    for (id, con) in &x {
        if con.is_empty() {
            eprintln!(
                "WARNING: Recipient '{}' has no attribute constraints. \
            It may be impossible to decrypt the file this way.",
                id
            );
        }
    }
    
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

    let pub_sign_id: Vec<Attribute> = serde_json::from_str(&pub_sign_id_str).unwrap();
    let mut total_id = pub_sign_id.clone();

    let priv_sign_id = if let Some(priv_sign_id_str) = priv_sign_id {
        let priv_id: Vec<Attribute> = serde_json::from_str(&priv_sign_id_str).unwrap();
        total_id.extend(priv_id.clone());
        Some(priv_id)
    } else {
        None
    };

    let client = crate::client::Client::new(&pkg).unwrap();
    let parameters = client.parameters().await.unwrap();

    eprintln!("Fetched parameters from {}", pkg);
    eprintln!(
        "Encrypting for the following recipients:\n{:#?}\n using the following policies:\n{}",
        identifiers,
        serde_json::to_string_pretty(&policies).unwrap()
    );

    eprintln!("Retrieving signing keys...");

    let pub_sign_key: Option<SigningKeyExt>;
    let priv_sign_key: Option<SigningKeyExt>;

    if api_key.is_some() {
        eprintln!("Using API key");

        SigningKeyResponse {
            pub_sign_key,
            priv_sign_key,
            ..
        } = client
            .request_signing_key(
                &api_key.unwrap(),
                &SigningKeyRequest {
                    pub_sign_id,
                    priv_sign_id,
                },
            )
            .await
            .unwrap();
    } else {
        eprintln!("Using app auth...");

        let sd = client
            .request_start(&IrmaAuthRequest {
                con: total_id,
                validity: None,
            })
            .await
            .unwrap();

        print_qr(&sd.session_ptr);

        let skr = SigningKeyRequest {
            pub_sign_id,
            priv_sign_id,
        };

        SigningKeyResponse {
            pub_sign_key,
            priv_sign_key,
            ..
        } = client.wait_on_signing_keys(&sd, &skr).await.unwrap();
    }

    let input_path = Path::new(&input);
    let file_name_path = input_path.file_name().unwrap();
    let file_name = file_name_path.to_str().unwrap();

    let output = format!("{}.{}", file_name, "enc");

    let source = File::open(input_path).unwrap();
    let destination = File::create(&output).unwrap();

    let pb = ProgressBar::new(source.metadata().unwrap().len());

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)").unwrap()
        .progress_chars("#>-"));

    let r = AllowStdIo::new(pb.wrap_read(source));
    let w = AllowStdIo::new(destination);

    eprintln!("Encrypting {}...", input);

    let mut sealer = Sealer::<_, SealerStreamConfig>::new(
        &parameters.public_key,
        &policies,
        &pub_sign_key.expect("no public signing key"),
        &mut rng,
    )
    .unwrap();

    if let Some(psk) = priv_sign_key {
        sealer = sealer.with_priv_signing_key(psk);
    };

    sealer.seal(r, w).await.unwrap();
}
