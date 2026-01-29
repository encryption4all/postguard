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
    #[clap(short, long)]
    pub identity: String,

    /// JSON representation of public signing identity.
    #[clap(short = 'P', long)]
    pub pub_sign_id: String,

    /// JSON representation of private signing identity.
    #[clap(short = 'S', long)]
    pub priv_sign_id: Option<String>,

    #[clap(short, long)]
    pub api_key: Option<String>,

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
