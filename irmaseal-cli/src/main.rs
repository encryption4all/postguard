mod client;
mod decrypt;
mod encrypt;
mod util;

use clap::{load_yaml, App};
use tokio::runtime::Runtime;

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let mut rt = Runtime::new().unwrap();

    rt.block_on(async {
        if let Some(matches) = matches.subcommand_matches("encrypt") {
            crate::encrypt::exec(matches).await;
        } else if let Some(matches) = matches.subcommand_matches("decrypt") {
            crate::decrypt::exec(matches).await;
        }
    });
}
