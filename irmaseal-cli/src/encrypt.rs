use clap::ArgMatches;
use irmaseal_core::stream::Sealer;
use irmaseal_core::Identity;
use std::time::SystemTime;

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
            Identity::new(timestamp, "pbdf.pbdf.email.email", Some(email)).unwrap()
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
    let output = format!("{}.irma", input);
    let mut w = crate::util::FileWriter::new(std::fs::File::create(output).unwrap());

    let mut sealer = Sealer::new(&i, &parameters.public_key, &mut rng, &mut w).unwrap();

    use std::io::Read;
    let mut src = std::fs::File::open(input).unwrap();
    let mut buf = [0u8; 512];
    loop {
        let len = src.read(&mut buf).unwrap();

        if len == 0 {
            break;
        }

        use irmaseal_core::Writable;
        sealer.write(&buf[0..len]).unwrap();
    }
}
