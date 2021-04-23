use clap::ArgMatches;
use irmaseal_core::stream::Sealer;
use irmaseal_core::Identity;
use std::path::Path;
use std::time::SystemTime;
use tar::Builder;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn exec(m: &ArgMatches<'_>) {
    let mut rng = rand::thread_rng();

    let input = m.value_of("INPUT").unwrap();
    let email = m.value_of("email");
    let bsn = m.value_of("bsn");
    let server = m.value_of("server").unwrap();
    let timestamp = now();

    let i = match (email, bsn) {
        (Some(email), None) => {
            Identity::new(timestamp, "pbdf.sidn-pbdf.email.email", Some(email)).unwrap()
        }
        (None, Some(bsn)) => {
            Identity::new(timestamp, "pbdf.gemeente.personalData.bsn", Some(bsn)).unwrap()
        }
        _ => {
            eprintln!("Expected either email or BSN");
            return;
        }
    };

    let client = crate::client::Client::new(server).unwrap();

    let parameters = client.parameters().await.unwrap();
    eprintln!("Fetched parameters from {}", server);
    eprintln!("Encrypting for recipient {:#?}", i);

    let input_path = Path::new(input);
    let file_name_path = input_path.file_name().unwrap();
    let file_name = file_name_path.to_str().unwrap();

    let output = format!("{}.{}", file_name, crate::util::IRMASEALEXT);

    let mut w = crate::util::FileWriter::new(std::fs::File::create(&output).unwrap());

    let sealer_write = crate::util::FileSealerWrite::new(
        Sealer::new(i, &parameters.public_key, &mut rng, &mut w).unwrap(),
    );

    eprintln!("Encrypting {}...", input);

    let mut archive = Builder::new(sealer_write);
    archive
        .append_path_with_name(input_path, file_name_path)
        .unwrap();
    archive.finish().unwrap();

    eprintln!("Finished encrypting.");
}
