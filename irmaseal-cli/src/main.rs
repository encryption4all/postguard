mod client;
mod decrypt;
mod encrypt;
mod opts;
//mod util;

use crate::opts::{Opts, Subcommand};
use clap::Parser;
use tokio::runtime::Runtime;

fn main() {
    let opts = Opts::parse();

    let mut rt = Runtime::new().unwrap();

    rt.block_on(async {
        match opts.subcmd {
            Subcommand::Enc(o) => crate::encrypt::exec(o).await,
            Subcommand::Dec(o) => crate::decrypt::exec(o).await,
        }
    });
}
