use clap::{Parser, ValueHint};

/// Private Key Generator (PKG) for IRMAseal, an Identity Based Encryption standard.
#[derive(Parser, Debug)]
#[clap(
    name = "irmaseal-pkg",
    version = "0.2",
    author = "Wouter Geraedts <w.geraedts@sarif.nl>, Leon Botros <l.botros@cs.ru.nl>"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: Subcommand,
}

#[derive(Parser, Debug)]
pub enum Subcommand {
    Gen(GenOpts),
    Server(ServerOpts),
}

/// Generate a master key pair.
#[derive(Parser, Debug)]
#[clap(name = "Gen")]
pub struct GenOpts {
    /// Version of the protocol.
    #[clap(short = 's', long, possible_values = &["1", "2"], default_value = "2")]
    pub scheme: String,

    /// Path to store the private key.
    #[clap(short = 'S', long, default_value = "./pkg.sec")]
    pub secret: String,

    /// Path to store the public key.
    #[clap(short = 'P', long, default_value = "./pkg.pub")]
    pub public: String,
}

/// Run the IRMASeal PKG HTTP service.
#[derive(Parser, Debug)]
#[clap(name = "Server")]
pub struct ServerOpts {
    /// Host to bind this service to.
    #[clap(short = 'H', long, default_value = "0.0.0.0", value_hint = ValueHint::Hostname)]
    pub host: String,

    /// Port to bind this service to.
    #[clap(short, long, default_value = "8087")]
    pub port: String,

    /// IRMA server used to verify identities.
    #[clap(short, long, default_value = "https://irmacrypt.nl/irma", value_hint = ValueHint::Url)]
    pub irma: String,

    /// Master secret key file path.
    #[clap(short = 'S', long, default_value = "./pkg.sec")]
    pub secret: String,

    /// Master public key file path.
    #[clap(short = 'P', long, default_value = "./pkg.pub", value_hint = ValueHint::FilePath)]
    pub public: String,
}