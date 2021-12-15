use crate::client::Client;
use crate::opts::DecOpts;
use futures::io::AllowStdIo;
use indicatif::{ProgressBar, ProgressStyle};
use irmaseal_core::kem::cgw_fo::CGWFO;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::stream::Unsealer;
use irmaseal_core::{api::*, Attribute};
use qrcode::render::Pixel;
use qrcode::Color;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::time::Duration;
use tokio::time::delay_for;

fn print_qr(qr: &irma::Qr) {
    let code = qrcode::QrCode::new(serde_json::to_string(qr).unwrap()).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .light_color(Pixel::default_color(Color::Dark))
        .dark_color(Pixel::default_color(Color::Light))
        .build();

    eprintln!("\n\n{}", scode);
}

async fn wait_on_session<K: IBKEM>(
    client: &Client<'_>,
    sp: &irma::SessionData,
    timestamp: u64,
) -> Option<KeyResponse<K>>
where
    KeyResponse<K>: DeserializeOwned,
{
    for _ in 0..120 {
        let r: KeyResponse<K> = client.result(&sp.token, timestamp).await.ok()?;

        if r.status != KeyStatus::DoneValid {
            delay_for(Duration::new(0, 500_000_000)).await;
        } else {
            return Some(r);
        }
    }

    None
}

pub async fn exec(dec_opts: DecOpts) {
    let DecOpts { input, pkg } = dec_opts;

    eprintln!("Opening {}", input);

    let file_ext = format!(".{}", "irma");

    let out_file_name = if input.ends_with(&file_ext) {
        &input[..input.len() - file_ext.len()]
    } else {
        panic!("Input file name does not end with .irma")
    };

    let source = File::open(&input).unwrap();
    let mut async_read = AllowStdIo::new(&source);

    let mut recipient_id = String::new();
    eprintln!("Enter recipient_id:");
    std::io::stdin().read_line(&mut recipient_id).unwrap();
    let unsealer = Unsealer::new(&mut async_read, &recipient_id.trim().to_string())
        .await
        .unwrap();

    eprintln!("IRMASeal format version: {:#?}", unsealer.version);

    let recipient_info = &unsealer.meta.recipient_info;
    eprintln!(
        "Policy: {}",
        serde_json::to_string_pretty(&recipient_info.policy).unwrap()
    );

    let client = Client::new(&pkg).unwrap();
    let parameters = client.parameters().await.unwrap();

    let mut reconstructed_policy = recipient_info.policy.clone();
    for attr in reconstructed_policy.con.iter_mut() {
        let mut line = String::new();
        eprintln!("Enter value for {}:", &attr.atype);
        let val = std::io::stdin().read_line(&mut line).unwrap();
        attr.hidden_value = (val > 0).then(|| line.strip_suffix("\n").unwrap().to_string());
    }

    let keyrequest = KeyRequest {
        con: reconstructed_policy
            .con
            .iter()
            .map(|attr| Attribute {
                atype: attr.atype.clone(),
                value: attr.hidden_value.clone(),
            })
            .collect(),
    };

    eprintln!("Requesting key for {:?}", &keyrequest);

    let sd: irma::SessionData = client.request(&keyrequest).await.unwrap();

    eprintln!("Please scan the following QR-code with IRMA:");
    print_qr(&sd.session_ptr);

    let key_resp: KeyResponse<CGWFO> =
        wait_on_session::<CGWFO>(&client, &sd, recipient_info.policy.timestamp)
            .await
            .unwrap();

    let usk = key_resp.key.unwrap();

    let destination = File::create(&out_file_name).unwrap();

    let pb = ProgressBar::new(source.metadata().unwrap().len() - unsealer.meta_buf.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} {binary_bytes_per_sec} ({eta} left)")
        .progress_chars("#>-"));

    let w = AllowStdIo::new(pb.wrap_write(destination));

    eprintln!("Decrypting {}...", input);

    unsealer
        .unseal(&usk, &parameters.public_key, w)
        .await
        .unwrap();
}
