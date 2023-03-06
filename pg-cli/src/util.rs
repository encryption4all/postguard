use qrcode::render::Pixel;
use qrcode::Color;

pub(crate) fn print_qr(qr: &irma::Qr) {
    let code = qrcode::QrCode::new(serde_json::to_string(qr).unwrap()).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .light_color(Pixel::default_color(Color::Dark))
        .dark_color(Pixel::default_color(Color::Light))
        .build();

    eprintln!("\n\n{}", scode);
}
