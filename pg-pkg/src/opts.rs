use clap::{Parser, ValueHint};

/// Private Key Generator (PKG) for PostGuard, an Identity Based Encryption standard.
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
    #[clap(short = 's', long, possible_values = &["3"], default_value = "3")]
    pub scheme: String,

    /// Path to store the IBE private key.
    #[clap(long, default_value = "./pkg_ibe.sec")]
    pub ibe_secret_path: String,

    /// Path to store the IBE public key.
    #[clap(long, default_value = "./pkg_ibe.pub")]
    pub ibe_public_path: String,

    /// Path to store the IBS private key.
    #[clap(long, default_value = "./pkg_ibs.sec")]
    pub ibs_secret_path: String,

    /// Path to store the IBS public key.
    #[clap(long, default_value = "./pkg_ibs.pub")]
    pub ibs_public_path: String,
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

    /// Path to store the IBS private key.
    #[clap(long, default_value = "./pkg_ibe.sec", value_hint = ValueHint::FilePath)]
    pub ibe_secret_path: String,

    /// Path to store the IBS public key.
    #[clap(long, default_value = "./pkg_ibe.pub", value_hint = ValueHint::FilePath)]
    pub ibe_public_path: String,

    /// Path to store the IBS private key.
    #[clap(long, default_value = "./pkg_ibs.sec", value_hint = ValueHint::FilePath)]
    pub ibs_secret_path: String,

    /// Path to store the IBS public key.
    #[clap(long, default_value = "./pkg_ibs.pub", value_hint = ValueHint::FilePath)]
    pub ibs_public_path: String,
}
