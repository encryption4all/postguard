use crate::client::Client;
use crate::opts::DecOpts;
use crate::util::print_qr;

use anyhow::{anyhow, Context, Result};
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Select, Text};
use pg_core::artifacts::UserSecretKey;
use pg_core::client::rust::stream::UnsealerStreamConfig;
use std::fs::File;

use pg_core::api::*;
use pg_core::client::Unsealer;
use pg_core::kem::cgw_kv::CGWKV;

const ENC_EXT: &str = ".enc";

pub fn strip_enc_extension(input: &str) -> Result<&str> {
    input
        .strip_suffix(ENC_EXT)
        .ok_or_else(|| anyhow!("input file '{}' does not end with '{}'", input, ENC_EXT))
}

pub async fn exec(dec_opts: DecOpts) -> Result<()> {
    let DecOpts { input, pkg } = dec_opts;

    let client =
        Client::new(&pkg).with_context(|| format!("failed to create PKG client for '{}'", pkg))?;

    eprintln!("Retrieving signing public key");
    let parameters_sign = client
        .signing_parameters()
        .await
        .with_context(|| format!("failed to fetch signing parameters from '{}'", pkg))?;

    eprintln!("Opening {}", input);

    let out_file_name = strip_enc_extension(&input)?;

    let source =
        File::open(&input).with_context(|| format!("failed to open input file '{}'", input))?;
    let mut async_read = AllowStdIo::new(&source);

    let unsealer =
        Unsealer::<_, UnsealerStreamConfig>::new(&mut async_read, &parameters_sign.public_key)
            .await
            .map_err(|e| anyhow!("failed to read PostGuard header: {:?}", e))?;

    eprintln!("PostGuard format version: {:#?}", unsealer.version);
    eprintln!(
        "Header: {}",
        serde_json::to_string_pretty(&unsealer.header)
            .context("failed to format header for display")?
    );

    let hidden_policies = &unsealer.header.recipients;
    let options: Vec<_> = hidden_policies.keys().cloned().collect();
    let id = Select::new("What's your recipient identifier?", options)
        .prompt()
        .context("recipient selection cancelled")?;

    let rec_info = hidden_policies
        .get(&id)
        .ok_or_else(|| anyhow!("selected recipient '{}' is not present in header", id))?;
    let mut reconstructed_policy = rec_info.policy.clone();
    for attr in reconstructed_policy.con.iter_mut() {
        attr.value = Text::new(&format!("Enter value for {}?", attr.atype))
            .prompt()
            .ok();
    }

    let keyrequest = IrmaAuthRequest {
        con: reconstructed_policy
            .con
            .iter()
            .map(|attr| {
                ConItem::Single(DisclosureAttribute {
                    atype: attr.atype.clone(),
                    value: attr.value.clone(),
                    optional: false,
                })
            })
            .collect(),
        validity: None,
    };

    eprintln!("Requesting key for {:?}", &keyrequest);

    let sd: irma::SessionData = client
        .request_start(&keyrequest)
        .await
        .context("failed to start IRMA session at PKG")?;

    eprintln!("Please scan the following QR-code with IRMA/Yivi:");
    print_qr(&sd.session_ptr)?;

    let key_resp: KeyResponse<UserSecretKey<CGWKV>> = client
        .wait_on_decryption_key(&sd, rec_info.policy.timestamp)
        .await
        .context("failed waiting on decryption key")?;

    let usk = key_resp
        .key
        .ok_or_else(|| anyhow!("PKG returned no decryption key"))?;

    let destination = File::create(out_file_name)
        .with_context(|| format!("failed to create output file '{}'", out_file_name))?;

    let metadata = source
        .metadata()
        .with_context(|| format!("failed to read metadata for '{}'", input))?;
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)")
        .context("invalid progress bar template")?
        .progress_chars("#>-"));

    let w = AllowStdIo::new(pb.wrap_write(destination));

    eprintln!("Decrypting {}...", input);

    let verified_policy = unsealer
        .unseal(&id, &usk, w)
        .await
        .map_err(|e| anyhow!("decryption failed: {:?}", e))?;

    println!(
        "The message was signed using: {}",
        serde_json::to_string_pretty(&verified_policy)
            .context("failed to format verified policy for display")?
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_enc_suffix() {
        assert_eq!(strip_enc_extension("hello.txt.enc").unwrap(), "hello.txt");
    }

    #[test]
    fn rejects_input_without_enc_suffix() {
        let err = strip_enc_extension("hello.txt").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("does not end with"), "got: {}", msg);
    }

    #[test]
    fn rejects_empty_input() {
        let err = strip_enc_extension("").unwrap_err();
        assert!(format!("{}", err).contains("does not end with"));
    }
}
