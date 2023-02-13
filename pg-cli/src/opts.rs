use clap::{Parser, ValueHint};

/// Command line interface for PostGuard, an Identity-Based Encryption protocol.
#[derive(Parser, Debug)]
#[clap(
    name = "pg-cli",
    version = "0.2",
    author = "Wouter Geraedts <w.geraedts@sarif.nl>, Leon Botros <l.botros@cs.ru.nl>"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: Subcommand,
}

#[derive(Parser, Debug)]
pub enum Subcommand {
    Enc(EncOpts),
    Dec(DecOpts),
}

/// Encrypt a file.
#[derive(Parser, Debug)]
#[clap(name = "Encrypt")]
pub struct EncOpts {
    /// Input file.
    #[clap(index = 1)]
    pub input: String,

    /// JSON representation of recipients and policies.
    #[clap(short = 'I', long)]
    pub identity: String,

    /// Private key generator (PKG) server URL.
    #[clap(short, long, default_value = "https://stable.irmaseal-pkg.ihub.ru.nl", value_hint = ValueHint::Url)]
    pub pkg: String,
}

/// Encrypt a file.
#[derive(Parser, Debug)]
#[clap(name = "Decrypt")]
pub struct DecOpts {
    /// Input file.
    #[clap(index = 1)]
    pub input: String,

    /// Private key generator (PKG) server URL.
    #[clap(short, long, default_value = "https://stable.irmaseal-pkg.ihub.ru.nl", value_hint = ValueHint::Url)]
    pub pkg: String,
}
