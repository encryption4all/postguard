mod error;
mod generate;
mod handlers;
mod server;
mod util;

pub use crate::error::*;

use clap::{load_yaml, App};

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    if let Some(matches) = matches.subcommand_matches("generate") {
        crate::generate::exec(matches);
    } else if let Some(matches) = matches.subcommand_matches("server") {
        crate::server::exec(matches);
    }
}
