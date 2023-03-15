use crate::client::Client;
use crate::opts::DecOpts;
use crate::util::print_qr;

use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Select, Text};
use pg_core::artifacts::UserSecretKey;
use pg_core::client::rust::stream::UnsealerStreamConfig;
use pg_core::identity::Attribute;
use std::fs::File;

use pg_core::api::*;
use pg_core::client::Unsealer;
use pg_core::kem::cgw_kv::CGWKV;

pub async fn exec(dec_opts: DecOpts) {
    let DecOpts { input, pkg } = dec_opts;

    let client = Client::new(&pkg).unwrap();

    eprintln!("Retrieving signing public key");
    let parameters_sign = client.signing_parameters().await.unwrap();

    eprintln!("Opening {}", input);

    let file_ext = format!(".{}", "enc");

    let out_file_name = if input.ends_with(&file_ext) {
        &input[..input.len() - file_ext.len()]
    } else {
        panic!("Input file name does not end with .enc")
    };

    let source = File::open(&input).unwrap();
    let mut async_read = AllowStdIo::new(&source);

    let unsealer =
        Unsealer::<_, UnsealerStreamConfig>::new(&mut async_read, &parameters_sign.public_key)
            .await
            .unwrap();

    eprintln!("PostGuard format version: {:#?}", unsealer.version);
    eprintln!(
        "Header: {}",
        serde_json::to_string_pretty(&unsealer.header).unwrap()
    );

    let hidden_policies = &unsealer.header.policies;
    let options: Vec<_> = hidden_policies.keys().cloned().collect();
    let id = Select::new("What's your recipient identifier?", options)
        .prompt()
        .unwrap();

    let rec_info = hidden_policies.get(&id).unwrap();
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
            .map(|attr| Attribute {
                atype: attr.atype.clone(),
                value: attr.value.clone(),
            })
            .collect(),
        validity: None,
    };

    eprintln!("Requesting key for {:?}", &keyrequest);

    let mut sd: irma::SessionData = client.request_start(&keyrequest).await.unwrap();

    if pkg.contains("ihub.ru.nl") {
        sd.session_ptr.u = format!("https://ihub.ru.nl/irma/1/{}", sd.session_ptr.u);
    }

    eprintln!("Please scan the following QR-code with IRMA/Yivi:");
    print_qr(&sd.session_ptr);

    let key_resp: KeyResponse<UserSecretKey<CGWKV>> = client
        .wait_on_decryption_key(&sd, rec_info.policy.timestamp)
        .await
        .unwrap();

    let usk = key_resp.key.unwrap();

    let destination = File::create(out_file_name).unwrap();

    let pb = ProgressBar::new(source.metadata().unwrap().len());
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)").unwrap()
        .progress_chars("#>-"));

    let w = AllowStdIo::new(pb.wrap_write(destination));

    eprintln!("Decrypting {}...", input);

    let verified_policy = unsealer.unseal(&id, &usk, w).await.unwrap();

    println!(
        "The message was signed using: {}",
        serde_json::to_string_pretty(&verified_policy).unwrap()
    );
}
