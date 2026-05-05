mod client;
mod decrypt;
mod encrypt;
mod opts;
mod util;

use crate::opts::{Opts, Subcommand};
use clap::Parser;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let opts = Opts::parse();

    let result = match opts.subcmd {
        Subcommand::Enc(o) => crate::encrypt::exec(o).await,
        Subcommand::Dec(o) => crate::decrypt::exec(o).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {:#}", err);
            ExitCode::FAILURE
        }
    }
}
