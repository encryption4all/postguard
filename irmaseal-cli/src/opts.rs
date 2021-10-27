use clap::{Parser, ValueHint};
use std::error::Error;

/// Command line interface for IRMAseal, an Identity Based Encryption standard.
#[derive(Parser, Debug)]
#[clap(
    name = "irmaseal-cli",
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

/// Parse a single key-value pair
///
/// Can extend this for multiple recipient - key/value combinations (multi-recipient),
/// or even multiple recipient - multiple key/value combinations (requires conjunctions).
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

/// Encrypt a file.
#[derive(Parser, Debug)]
#[clap(name = "Encrypt")]
pub struct EncOpts {
    /// Input file.
    #[clap(index = 1)]
    pub input: String,

    /// Identity, currently limited to one key-value attribute.
    #[clap(short = 'I', long, parse(try_from_str = parse_key_val))]
    pub identity: (String, String),

    /// Private key generator (PKG) server URL.
    #[clap(short, long, default_value = "https://irmacrypt.nl/pkg", value_hint = ValueHint::Url)]
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
    #[clap(short, long, default_value = "https://irmacrypt.nl/pkg", value_hint = ValueHint::Url)]
    pub pkg: String,
}
