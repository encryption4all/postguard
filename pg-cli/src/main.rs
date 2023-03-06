mod client;
mod decrypt;
mod encrypt;
mod opts;
mod util;

use crate::opts::{Opts, Subcommand};
use clap::Parser;

#[tokio::main]
async fn main() {
    let opts = Opts::parse();

    match opts.subcmd {
        Subcommand::Enc(o) => crate::encrypt::exec(o).await,
        Subcommand::Dec(o) => crate::decrypt::exec(o).await,
    }
}
