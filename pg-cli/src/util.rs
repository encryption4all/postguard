use anyhow::{Context, Result};
use qrcode::render::Pixel;
use qrcode::Color;

pub(crate) fn print_qr(qr: &irma::Qr) -> Result<()> {
    let json = serde_json::to_string(qr).context("failed to serialize QR session pointer")?;
    let code = qrcode::QrCode::new(json).context("failed to encode QR code")?;
    let scode = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .light_color(Pixel::default_color(Color::Dark))
        .dark_color(Pixel::default_color(Color::Light))
        .build();

    eprintln!("\n\n{}", scode);
    Ok(())
}
