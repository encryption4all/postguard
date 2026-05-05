use pg_core::api::{DisclosureAttribute, IrmaAuthRequest, SigningKeyRequest, SigningKeyResponse};
use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::Sealer;
use pg_core::identity::{Attribute, Policy};

use crate::opts::EncOpts;
use crate::util::print_qr;
use anyhow::{anyhow, Context, Result};
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use pg_core::artifacts::SigningKeyExt;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::time::SystemTime;

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system clock is set before the UNIX epoch")?
        .as_secs())
}

pub async fn exec(enc_opts: EncOpts) -> Result<()> {
    let mut rng = rand::thread_rng();

    let EncOpts {
        input,
        identity,
        pub_sign_id: pub_sign_id_str,
        priv_sign_id,
        api_key,
        pkg,
    } = enc_opts;

    let timestamp = now()?;

    let x: BTreeMap<String, Vec<Attribute>> = match serde_json::from_str(identity.as_str()) {
        Ok(map) => map,
        Err(e) => {
            return Err(anyhow!(
                "failed to parse `identity` JSON: {}\ninput was: {}",
                e,
                identity
            ));
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

    let pub_sign_id: Vec<Attribute> =
        serde_json::from_str(&pub_sign_id_str).context("failed to parse `pub_sign_id` JSON")?;
    let mut total_id = pub_sign_id.clone();

    let priv_sign_id = if let Some(priv_sign_id_str) = priv_sign_id {
        let priv_id: Vec<Attribute> = serde_json::from_str(&priv_sign_id_str)
            .context("failed to parse `priv_sign_id` JSON")?;
        total_id.extend(priv_id.clone());
        Some(priv_id)
    } else {
        None
    };

    let client = crate::client::Client::new(&pkg)
        .with_context(|| format!("failed to create PKG client for '{}'", pkg))?;
    let parameters = client
        .parameters()
        .await
        .with_context(|| format!("failed to fetch parameters from '{}'", pkg))?;

    eprintln!("Fetched parameters from {}", pkg);
    eprintln!(
        "Encrypting for the following recipients:\n{:#?}\n using the following policies:\n{}",
        identifiers,
        serde_json::to_string_pretty(&policies).context("failed to format policies for display")?
    );

    eprintln!("Retrieving signing keys...");

    let pub_sign_key: Option<SigningKeyExt>;
    let priv_sign_key: Option<SigningKeyExt>;

    if let Some(api_key) = api_key {
        eprintln!("Using API key...");

        SigningKeyResponse {
            pub_sign_key,
            priv_sign_key,
            ..
        } = client
            .request_signing_key(
                &api_key,
                &SigningKeyRequest {
                    pub_sign_id,
                    priv_sign_id,
                },
            )
            .await
            .context("failed to retrieve signing keys via API key")?;
    } else {
        eprintln!("Using app auth...");

        let sd = client
            .request_start(&IrmaAuthRequest {
                con: total_id
                    .into_iter()
                    .map(|a| DisclosureAttribute {
                        atype: a.atype,
                        value: a.value,
                        optional: false,
                    })
                    .collect(),
                validity: None,
            })
            .await
            .context("failed to start IRMA session at PKG")?;

        print_qr(&sd.session_ptr)?;

        let skr = SigningKeyRequest {
            pub_sign_id,
            priv_sign_id,
        };

        SigningKeyResponse {
            pub_sign_key,
            priv_sign_key,
            ..
        } = client
            .wait_on_signing_keys(&sd, &skr)
            .await
            .context("failed waiting on signing keys")?;
    }

    let input_path = Path::new(&input);
    let file_name_path = input_path
        .file_name()
        .ok_or_else(|| anyhow!("input path '{}' has no file name component", input))?;
    let file_name = file_name_path.to_str().ok_or_else(|| {
        anyhow!(
            "input file name '{}' is not valid UTF-8",
            file_name_path.to_string_lossy()
        )
    })?;

    let output = format!("{}.{}", file_name, "enc");

    let source =
        File::open(input_path).with_context(|| format!("failed to open input file '{}'", input))?;
    let destination = File::create(&output)
        .with_context(|| format!("failed to create output file '{}'", output))?;

    let metadata = source
        .metadata()
        .with_context(|| format!("failed to read metadata for '{}'", input))?;
    let pb = ProgressBar::new(metadata.len());

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)")
        .context("invalid progress bar template")?
        .progress_chars("#>-"));

    let r = AllowStdIo::new(pb.wrap_read(source));
    let w = AllowStdIo::new(destination);

    eprintln!("Encrypting {}...", input);

    let pub_sign_key =
        pub_sign_key.ok_or_else(|| anyhow!("PKG response did not include a public signing key"))?;

    let mut sealer = Sealer::<_, SealerStreamConfig>::new(
        &parameters.public_key,
        &policies,
        &pub_sign_key,
        &mut rng,
    )
    .map_err(|e| anyhow!("failed to construct sealer: {:?}", e))?;

    if let Some(psk) = priv_sign_key {
        sealer = sealer.with_priv_signing_key(psk);
    };

    sealer
        .seal(r, w)
        .await
        .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

    Ok(())
}
