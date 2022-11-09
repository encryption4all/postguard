use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PKGConfig {
    /// Path to the IBE master key pair.
    ibe_kp: (String, String),

    /// Path to the IBS master key pair.
    ibs_kp: (String, String),

    /// Host
    host: String,

    /// Port
    port: u16,

    /// IRMA url.
    irma_url: String,
}
