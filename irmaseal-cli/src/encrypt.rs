use crate::opts::EncOpts;
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use irmaseal_core::stream::seal;
use irmaseal_core::{Attribute, Policy};
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

    let client = crate::client::Client::new(&pkg).unwrap();

    let parameters = client.parameters().await.unwrap();

    eprintln!("Fetched parameters from {}", pkg);
    eprintln!(
        "Encrypting for the following recipients:\n{:#?}\n using the following policy:\n{:?}",
        identifiers, policies
    );

    let input_path = Path::new(&input);
    let file_name_path = input_path.file_name().unwrap();
    let file_name = file_name_path.to_str().unwrap();

    let output = format!("{}.{}", file_name, "irma");

    let source = File::open(&input_path).unwrap();
    let destination = File::create(&output).unwrap();

    let pb = ProgressBar::new(source.metadata().unwrap().len());

    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)")
        .progress_chars("#>-"));

    let r = AllowStdIo::new(pb.wrap_read(source));
    let w = AllowStdIo::new(destination);

    eprintln!("Encrypting {}...", input);

    seal(&parameters.public_key, &policies, &mut rng, r, w)
        .await
        .unwrap();
}
