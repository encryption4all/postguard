mod client;
mod decrypt;
mod encrypt;
mod util;

use clap::{load_yaml, App};

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        crate::encrypt::exec(matches);
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        crate::decrypt::exec(matches);
    }
}
