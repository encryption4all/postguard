use crate::opts::EncOpts;
use irmaseal_core::stream::Sealer;
use irmaseal_core::Identity;
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

    // TODO: value should be optional
    let i = Identity::new(now(), &identity.0, Some(&identity.1)).unwrap();
    let client = crate::client::Client::new(&pkg).unwrap();

    let parameters = client.parameters().await.unwrap();
    eprintln!("Fetched parameters from {}", pkg);
    eprintln!("Encrypting for recipient {:#?}", i);

    let input_path = Path::new(&input);
    let file_name_path = input_path.file_name().unwrap();
    let file_name = file_name_path.to_str().unwrap();

    let output = format!("{}.{}", file_name, crate::util::IRMASEALEXT);

    let mut w = crate::util::FileWriter::new(std::fs::File::create(&output).unwrap());

    let mut sealer_write = crate::util::FileSealerWrite::new(
        Sealer::new(i, &parameters.public_key, &mut rng, &mut w).unwrap(),
    );

    eprintln!("Encrypting {}...", input);

    std::io::copy(
        &mut std::fs::File::open(input_path).unwrap(),
        &mut sealer_write,
    )
    .unwrap();

    eprintln!("Finished encrypting.");
}
