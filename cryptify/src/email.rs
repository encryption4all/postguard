use crate::config::CryptifyConfig;
use crate::store::{FileState, SenderClaim};

use askama::Template;

use chrono::{format::Locale, TimeZone};

use lettre::{
    message::{
        header::{ContentType, Header, HeaderName, HeaderValue},
        Attachment, Mailbox, MultiPart, SinglePart,
    },
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};

/// `X-PostGuard: <version>` header. Set on every outgoing notification so the
/// Outlook add-in's `OnMessageRead` launch event (which filters on this
/// header name) fires for PostGuard mail. See encryption4all/cryptify#52.
#[derive(Clone, Debug)]
struct XPostGuard(String);

impl Header for XPostGuard {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("X-PostGuard")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(XPostGuard(s.to_owned()))
    }

    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), self.0.clone())
    }
}

const X_POSTGUARD_VERSION: &str = env!("PG_CORE_VERSION");

/// `Auto-Submitted: auto-generated` per RFC 3834. Signals to receiving MTAs
/// and mail clients that this is a machine-generated transactional message,
/// suppresses vacation-responder loops, and is one of the deliverability
/// signals Gmail's bulk-sender heuristics look for.
#[derive(Clone, Debug)]
struct AutoSubmitted;

impl Header for AutoSubmitted {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Auto-Submitted")
    }

    fn parse(_s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(AutoSubmitted)
    }

    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), "auto-generated".to_owned())
    }
}

/// Embedded PostGuard logo, served inline via a `Content-ID: <pg-logo>`
/// MIME part rather than fetched from postguard.eu. Removes the
/// HTML-only-plus-remote-image spam signal flagged in postguard#197.
const LOGO_PNG: &[u8] = include_bytes!("../templates/email/pg_logo.png");

/// Inline checkmark glyph shown next to the *proven* sender email in the
/// HTML email, referenced via `cid:pg-check`. Attached only to the
/// attributed rendering, so a mail that certifies nothing carries no
/// checkmark for a client to display.
const CHECK_PNG: &[u8] = include_bytes!("../templates/email/check.png");

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Language {
    #[serde(rename = "EN")]
    En,
    #[serde(rename = "NL")]
    Nl,
}

impl Language {
    /// Stable two-letter code, deliberately identical to the serde
    /// representation the `mailLang` field uses on the wire. Persisting the
    /// same token means a restored session and a fresh one carry the same
    /// value, and `language_code_matches_serde_representation` keeps the two
    /// from drifting apart.
    pub fn code(&self) -> &'static str {
        match self {
            Language::En => "EN",
            Language::Nl => "NL",
        }
    }

    /// Inverse of [`Language::code`], used when a session is restored from
    /// SQLite. `None` for anything else: a row this binary cannot read must
    /// leave the session unrestored rather than quietly resume it in the
    /// wrong language.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "EN" => Some(Language::En),
            "NL" => Some(Language::Nl),
            _ => None,
        }
    }
}

struct MailStrings<'a> {
    expires_str: &'a str,
    download_str: &'a str,
    link_str: &'a str,
    header_confirm: &'a str,
    subject_confirm: &'a str,
    confirm: &'a str,
    /// Opens the attribution block, and so appears on the attributed
    /// rendering only. Body copy: the proven address must not reach `From`
    /// or the subject, where Microsoft 365 Defender scores a display name
    /// resembling a known contact from an external domain.
    on_behalf_of: &'a str,
    /// Subject *and* headline of every recipient notification, both
    /// renderings. Brand-only, so what an upload proved changes the body
    /// and nothing a mail filter reads.
    subject_neutral: &'a str,
}

const NL_STRINGS: MailStrings = MailStrings {
    expires_str: "Verloopt op",
    download_str: "Download jouw bestanden",
    link_str: "Download link",
    header_confirm: "Je hebt het volgende gestuurd aan",
    subject_confirm: "Je bestanden zijn verstuurd via PostGuard",
    confirm: "Je kunt nog steeds bij je bestanden",
    on_behalf_of: "PostGuard stuurt je versleutelde bestanden namens",
    subject_neutral: "Je hebt versleutelde bestanden ontvangen via PostGuard",
};

const EN_STRINGS: MailStrings = MailStrings {
    expires_str: "Expires on",
    download_str: "Download your files",
    link_str: "Download link",
    header_confirm: "You sent files to",
    subject_confirm: "Your files have been sent via PostGuard",
    confirm: "You can still access your files",
    on_behalf_of: "PostGuard is sending you encrypted files on behalf of",
    subject_neutral: "You have received encrypted files via PostGuard",
};

fn strings_for(lang: &Language) -> MailStrings<'static> {
    match lang {
        Language::En => EN_STRINGS,
        Language::Nl => NL_STRINGS,
    }
}

/// The neutral rendering: what an upload gets when nothing about its sender
/// was proven. `email.html` carries no attribution block, and this struct
/// carries no address to put in one.
#[derive(Template)]
#[template(path = "email/email.html")]
struct NeutralEmailTemplate<'a> {
    header: &'a str,
    expires_str: &'a str,
    download_str: &'a str,
    link_str: &'a str,
    file_size: &'a str,
    expiry_date: &'a str,
    html_content: &'a str,
    url: &'a str,
    confirm: &'a str,
}

/// The attributed rendering: the neutral body plus the tick, the attribution
/// line and the proven attributes as chips.
///
/// The arms are two structs and two templates rather than one of each with
/// optional fields, and deliberately so (postguard#365): the tick lives in a
/// template only this struct can render, so no expression in the program can
/// put one on an upload that proved nothing — a render site added later
/// cannot forget a flag that does not exist.
#[derive(Template)]
#[template(path = "email/email_attributed.html")]
struct AttributedEmailTemplate<'a> {
    header: &'a str,
    expires_str: &'a str,
    download_str: &'a str,
    link_str: &'a str,
    file_size: &'a str,
    expiry_date: &'a str,
    html_content: &'a str,
    url: &'a str,
    confirm: &'a str,
    on_behalf_of: &'a str,
    sender_email: &'a str,
    sender_attributes: &'a [(String, String)],
}

#[derive(Template)]
#[template(path = "email/email.txt", escape = "none")]
struct NeutralEmailTextTemplate<'a> {
    header: &'a str,
    expires_str: &'a str,
    download_str: &'a str,
    link_str: &'a str,
    file_size: &'a str,
    expiry_date: &'a str,
    html_content: &'a str,
    url: &'a str,
    confirm: &'a str,
}

#[derive(Template)]
#[template(path = "email/email_attributed.txt", escape = "none")]
struct AttributedEmailTextTemplate<'a> {
    header: &'a str,
    expires_str: &'a str,
    download_str: &'a str,
    link_str: &'a str,
    file_size: &'a str,
    expiry_date: &'a str,
    html_content: &'a str,
    url: &'a str,
    confirm: &'a str,
    on_behalf_of: &'a str,
    sender_email: &'a str,
    sender_attributes: &'a [(String, String)],
}

/// Assemble the MIME body: a `multipart/alternative` whose HTML branch is
/// itself a `multipart/related` carrying the HTML part plus the PostGuard
/// logo as an inline image referenced via `cid:pg-logo`. This shape avoids
/// the HTML-only + remote-image spam signal flagged in postguard#197 while
/// keeping graceful degradation for text-only clients.
///
/// `attributed` says whether the HTML references `cid:pg-check`, and the
/// tick image is attached only then. A neutral body naming no sender must
/// not ship a checkmark: an inline part nothing references is one some
/// clients offer as an attachment.
fn build_body(
    html: String,
    text: String,
    attributed: bool,
) -> Result<MultiPart, Box<dyn std::error::Error>> {
    let logo = Attachment::new_inline("pg-logo".to_string())
        .body(LOGO_PNG.to_vec(), "image/png".parse::<ContentType>()?);

    let mut related = MultiPart::related()
        .singlepart(SinglePart::html(html))
        .singlepart(logo);

    if attributed {
        related = related.singlepart(
            Attachment::new_inline("pg-check".to_string())
                .body(CHECK_PNG.to_vec(), "image/png".parse::<ContentType>()?),
        );
    }

    Ok(MultiPart::alternative()
        .singlepart(SinglePart::plain(text))
        .multipart(related))
}

fn format_file_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    if size == 0 {
        return "0 B".to_owned();
    }
    let i = ((size as f64).log10() / (1024_f64).log10()).floor() as usize;
    let i = i.min(UNITS.len() - 1);
    format!(
        "{:.1} {}",
        (size as f64 / (1024_f64).powi(i as i32)),
        UNITS[i]
    )
}

fn format_date(date: i64, lang: &Language) -> String {
    let dt = chrono::Utc.timestamp_opt(date, 0).unwrap();
    let locale = match lang {
        Language::En => Locale::en_GB,
        Language::Nl => Locale::nl_NL,
    };
    dt.format_localized("%e %B %Y", locale).to_string()
}

/// One rendered notification email, in the shape `send_email` would
/// hand to the SMTP layer. Returned by [`render_recipient_email`] and
/// [`render_confirmation_email`]; consumed by `send_email` for real
/// delivery and by the staging `/staging/preview/<uuid>` endpoint so
/// developers can inspect what cryptify would have sent without
/// reaching for the logs.
#[derive(Serialize, Clone, Debug)]
pub struct RenderedEmail {
    /// The recipient address this rendering targets (the per-recipient
    /// notification's `To`, or the sender's address for confirmation).
    pub recipient: String,
    pub subject: String,
    /// Formatted `Name <email>` form of the configured `email_from`.
    pub from: String,
    /// The *proven* sender's address on a per-recipient notification, so
    /// replies reach them. `None` when the upload proved nothing, when the
    /// kill switch is off, and on the sender's own confirmation copy.
    pub reply_to: Option<String>,
    /// True when this rendering carries the attribution block and so
    /// references `cid:pg-check`. `build_body` attaches the tick image only
    /// then; the staging preview reports it so a developer can see which
    /// rendering an upload got without reading the HTML.
    pub attributed: bool,
    pub html: String,
    pub text: String,
}

/// Build the `/download?uuid=…&recipient=…` link cryptify embeds in the
/// notification body. Extracted from `send_email` so the preview endpoint
/// constructs URLs the same way and they cannot drift.
fn build_download_url(
    config: &CryptifyConfig,
    uuid: &str,
    recipient: &str,
) -> Result<String, url::ParseError> {
    let base = Url::parse(config.server_url())?;
    let mut url = base.join("/download")?;
    url.query_pairs_mut()
        .append_pair("uuid", uuid)
        .append_pair("recipient", recipient);
    Ok(url.to_string())
}

/// Render the per-recipient notification email (subject + HTML + text)
/// for a single recipient on an upload. Pure: no SMTP, no IO beyond URL
/// parsing.
pub fn render_recipient_email(
    state: &FileState,
    config: &CryptifyConfig,
    recipient_email: &str,
    uuid: &str,
) -> Result<RenderedEmail, url::ParseError> {
    let url = build_download_url(config, uuid, recipient_email)?;
    let body = email_templates(state, config, &url);
    let attributed = body.attributed_to.is_some();
    Ok(RenderedEmail {
        recipient: recipient_email.to_owned(),
        subject: body.subject,
        from: config.email_from().to_string(),
        // Replies go to the proven address or nowhere. `state.sender` is the
        // uploader's own spelling of an identity nobody checked, so pointing
        // a reply at it is the same unverified assertion the body no longer
        // makes.
        reply_to: body.attributed_to,
        attributed,
        html: body.html,
        text: body.text,
    })
}

/// Render the sender's confirmation copy (only emitted when
/// `state.confirm` is set on upload). Returns `Ok(None)` when no sender
/// address is known — confirmation has nowhere to go.
pub fn render_confirmation_email(
    state: &FileState,
    config: &CryptifyConfig,
    uuid: &str,
) -> Result<Option<RenderedEmail>, url::ParseError> {
    let Some(sender_email) = state.sender.clone() else {
        return Ok(None);
    };
    let url = build_download_url(config, uuid, &sender_email)?;
    let body = email_confirm(state, config, &url);
    Ok(Some(RenderedEmail {
        recipient: sender_email,
        subject: body.subject,
        from: config.email_from().to_string(),
        reply_to: None,
        attributed: body.attributed_to.is_some(),
        html: body.html,
        text: body.text,
    }))
}

/// One mail's rendered bodies, its subject, and the address the attributed
/// arm put in them.
///
/// `attributed_to` is read back off the arm that ran rather than handed to
/// it. The `Reply-To` and the `cid:pg-check` MIME part are both keyed off
/// this one value, so neither can drift from the body that was actually
/// rendered.
struct RenderedBody {
    html: String,
    text: String,
    subject: String,
    attributed_to: Option<String>,
}

/// What a mail may attribute this upload to, once the config kill switch has
/// had its say.
///
/// The switch is a one-way valve: it is applied *after* the claim resolves and
/// can only discard it, so no configuration turns an upload that proved
/// nothing into an attributed mail. `None` — finalize has not run — renders
/// exactly as `Unproven` does, because only a verified proof may produce a
/// tick.
fn attributable_claim<'a>(
    state: &'a FileState,
    config: &CryptifyConfig,
) -> Option<&'a SenderClaim> {
    if config.attributed_email() {
        state.sender_claim.as_ref()
    } else {
        None
    }
}

/// Render one mail's two bodies and pick its subject, splitting on what the
/// upload proved. Both the recipient notification and the sender's
/// confirmation copy come through here, so an attribution the one loses
/// cannot survive on the other.
fn render_body(
    state: &FileState,
    config: &CryptifyConfig,
    strings: &MailStrings<'_>,
    url: &str,
    header: &str,
    confirm: &str,
    subject: &str,
) -> RenderedBody {
    let file_size = format_file_size(state.uploaded);
    let expiry_date = format_date(state.expires, &state.mail_lang);

    match attributable_claim(state, config) {
        Some(SenderClaim::Proven { email, attrs }) => RenderedBody {
            html: AttributedEmailTemplate {
                header,
                expires_str: strings.expires_str,
                download_str: strings.download_str,
                link_str: strings.link_str,
                file_size: &file_size,
                expiry_date: &expiry_date,
                html_content: &state.mail_content,
                url,
                confirm,
                on_behalf_of: strings.on_behalf_of,
                sender_email: email,
                sender_attributes: attrs,
            }
            .to_string(),
            text: AttributedEmailTextTemplate {
                header,
                expires_str: strings.expires_str,
                download_str: strings.download_str,
                link_str: strings.link_str,
                file_size: &file_size,
                expiry_date: &expiry_date,
                html_content: &state.mail_content,
                url,
                confirm,
                on_behalf_of: strings.on_behalf_of,
                sender_email: email,
                sender_attributes: attrs,
            }
            .to_string(),
            subject: subject.to_owned(),
            attributed_to: Some(email.clone()),
        },
        Some(SenderClaim::Unproven) | None => RenderedBody {
            html: NeutralEmailTemplate {
                header,
                expires_str: strings.expires_str,
                download_str: strings.download_str,
                link_str: strings.link_str,
                file_size: &file_size,
                expiry_date: &expiry_date,
                html_content: &state.mail_content,
                url,
                confirm,
            }
            .to_string(),
            text: NeutralEmailTextTemplate {
                header,
                expires_str: strings.expires_str,
                download_str: strings.download_str,
                link_str: strings.link_str,
                file_size: &file_size,
                expiry_date: &expiry_date,
                html_content: &state.mail_content,
                url,
                confirm,
            }
            .to_string(),
            subject: subject.to_owned(),
            attributed_to: None,
        },
    }
}

fn email_templates(state: &FileState, config: &CryptifyConfig, url: &str) -> RenderedBody {
    let strings = strings_for(&state.mail_lang);
    render_body(
        state,
        config,
        &strings,
        url,
        // The headline says only that encrypted files arrived. Who they came
        // from is the attribution block's business, and only once proven.
        strings.subject_neutral,
        "",
        strings.subject_neutral,
    )
}

fn email_confirm(state: &FileState, config: &CryptifyConfig, url: &str) -> RenderedBody {
    let strings = strings_for(&state.mail_lang);
    let header = format!("{} {}", strings.header_confirm, state.recipients);
    render_body(
        state,
        config,
        &strings,
        url,
        &header,
        strings.confirm,
        strings.subject_confirm,
    )
}

pub async fn send_email(
    config: &CryptifyConfig,
    state: &FileState,
    uuid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if config.staging_mode() {
        return Ok(staging_log_email(config, state, uuid));
    }

    // setup SMTP connection
    log::info!(
        "Setting up SMTP: host={}, port={}, tls={}, credentials={}",
        config.smtp_url(),
        config.smtp_port(),
        config.smtp_tls(),
        config.smtp_username().is_some()
    );
    let mut mailer_builder = if config.smtp_tls() {
        SmtpTransport::starttls_relay(config.smtp_url())?.port(config.smtp_port())
    } else {
        SmtpTransport::builder_dangerous(config.smtp_url()).port(config.smtp_port())
    };

    mailer_builder = mailer_builder.timeout(Some(std::time::Duration::from_secs(10)));

    // add credentials, if present
    if let (Some(username), Some(password)) = (config.smtp_username(), config.smtp_password()) {
        let credentials = Credentials::new(username.to_owned(), password.to_owned());
        mailer_builder = mailer_builder.credentials(credentials);
    }

    if state.notify_recipients {
        for recipient in state.recipients.iter() {
            let recipient_email = recipient.email.to_string();
            let rendered = render_recipient_email(state, config, &recipient_email, uuid)?;

            let mut builder = Message::builder()
                .header(XPostGuard(X_POSTGUARD_VERSION.to_owned()))
                .header(AutoSubmitted)
                .from(config.email_from()) // checked in config
                .to(recipient.clone())
                .subject(&rendered.subject);
            if let Some(sender) = rendered.reply_to.as_deref() {
                match sender.parse::<Mailbox>() {
                    Ok(mailbox) => builder = builder.reply_to(mailbox),
                    Err(e) => log::warn!(
                        "Skipping Reply-To: sender `{}` did not parse as Mailbox: {}",
                        sender,
                        e
                    ),
                }
            }
            let email = builder.multipart(build_body(
                rendered.html,
                rendered.text,
                rendered.attributed,
            )?)?;

            // send email
            log::info!("Sending email to {}", recipient.email);
            let mailer = mailer_builder.clone().build();
            mailer.send(&email).map_err(|e| {
                log::error!("Failed to send email to {}: {}", recipient.email, e);
                e
            })?;
            log::info!("Email sent to {}", recipient.email);
        }
    } else {
        log::info!(
            "notify_recipients disabled — skipping notification mail for {} recipient(s) on upload {}",
            state.recipients.iter().count(),
            uuid
        );
    }

    if state.confirm {
        // `state.confirm` is only set on uploads that captured a sender
        // address, so render_confirmation_email returns `Some` here. Log
        // loudly on the `None` arm so a future invariant breach surfaces
        // instead of silently dropping the sender's confirmation copy.
        match render_confirmation_email(state, config, uuid)? {
            None => log::error!(
                "state.confirm=true but no sender on FileState for upload {} — confirmation email dropped",
                uuid
            ),
            Some(rendered) => {
                let to_mailbox: Mailbox = rendered.recipient.parse()?;
                let email = Message::builder()
                    .header(XPostGuard(X_POSTGUARD_VERSION.to_owned()))
                    .header(AutoSubmitted)
                    .from(config.email_from())
                    .to(to_mailbox)
                    .subject(&rendered.subject)
                    .multipart(build_body(
                        rendered.html,
                        rendered.text,
                        rendered.attributed,
                    )?)?;

                log::info!("Sending confirmation email to {}", rendered.recipient);
                let mailer = mailer_builder.build();
                mailer.send(&email).map_err(|e| {
                    log::error!(
                        "Failed to send confirmation email to {}: {}",
                        rendered.recipient,
                        e
                    );
                    e
                })?;
                log::info!("Confirmation email sent to {}", rendered.recipient);
            }
        }
    }

    Ok("Email successfully sent".to_owned())
}

/// Staging-mode replacement for actual SMTP delivery. Logs a clearly
/// marked record of the email that *would* have been sent (recipients,
/// sender, attributes, expiry, download URL) so operators of a staging
/// deployment can observe the full flow without contacting an SMTP
/// server. Returns a summary string in the same `Result::Ok` shape as
/// real sends.
fn staging_log_email(config: &CryptifyConfig, state: &FileState, uuid: &str) -> String {
    let sender = state.sender.as_deref().unwrap_or("<unknown>");
    let lang = match state.mail_lang {
        Language::En => "EN",
        Language::Nl => "NL",
    };
    let recipients: Vec<String> = state
        .recipients
        .iter()
        .map(|m| m.email.to_string())
        .collect();
    let attrs: Vec<String> = state
        .sender_attributes
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    let base = Url::parse(config.server_url()).ok();
    let download_url = base
        .and_then(|b| b.join("/download").ok())
        .map(|mut u| {
            u.query_pairs_mut().append_pair("uuid", uuid);
            u.to_string()
        })
        .unwrap_or_else(|| format!("(unparseable server_url={})", config.server_url()));

    let summary = format!(
        "[STAGING] Email NOT sent (staging_mode=true). Would have notified recipients={:?} \
         from sender={} (attributes=[{}]) lang={} expires={} confirm={} notify_recipients={} \
         download_url={} uuid={}",
        recipients,
        sender,
        attrs.join(", "),
        lang,
        state.expires,
        state.confirm,
        state.notify_recipients,
        download_url,
        uuid,
    );

    log::info!("{}", summary);
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_postguard_header_name_matches_outlook_filter() {
        assert_eq!(format!("{}", XPostGuard::name()), "X-PostGuard");
    }

    #[test]
    fn auto_submitted_header_emits_auto_generated() {
        use lettre::message::Mailbox;
        let msg = Message::builder()
            .from("noreply@example.com".parse::<Mailbox>().unwrap())
            .to("to@example.com".parse::<Mailbox>().unwrap())
            .subject("t")
            .header(AutoSubmitted)
            .body(String::from("hi"))
            .expect("build");
        let raw = String::from_utf8(msg.formatted()).expect("utf8");
        assert!(
            raw.contains("Auto-Submitted: auto-generated"),
            "expected Auto-Submitted header, got: {}",
            raw
        );
    }

    #[test]
    fn x_postguard_header_round_trips() {
        let parsed = XPostGuard::parse(X_POSTGUARD_VERSION).expect("parse");
        assert_eq!(parsed.0, X_POSTGUARD_VERSION);
    }

    #[test]
    fn x_postguard_header_serialises_into_message() {
        use lettre::message::Mailbox;
        let msg = Message::builder()
            .from("noreply@example.com".parse::<Mailbox>().unwrap())
            .to("to@example.com".parse::<Mailbox>().unwrap())
            .subject("t")
            .header(XPostGuard(X_POSTGUARD_VERSION.to_owned()))
            .body(String::from("hi"))
            .expect("build");
        let raw = String::from_utf8(msg.formatted()).expect("utf8");
        let expected = format!("X-PostGuard: {}", X_POSTGUARD_VERSION);
        assert!(
            raw.contains(&expected),
            "expected `{}` header in message, got: {}",
            expected,
            raw
        );
    }

    #[test]
    fn format_file_size_zero() {
        assert_eq!(format_file_size(0), "0 B");
    }

    #[test]
    fn format_file_size_bytes() {
        assert_eq!(format_file_size(1), "1.0 B");
        assert_eq!(format_file_size(1023), "1023.0 B");
    }

    #[test]
    fn format_file_size_kibibytes() {
        assert_eq!(format_file_size(1024), "1.0 kB");
        assert_eq!(format_file_size(1536), "1.5 kB");
    }

    #[test]
    fn format_file_size_mebibytes() {
        assert_eq!(format_file_size(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn format_file_size_gibibytes() {
        assert_eq!(format_file_size(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_file_size_tebibytes() {
        assert_eq!(format_file_size(1024_u64.pow(4)), "1.0 TB");
    }

    fn staging_filestate() -> FileState {
        use lettre::message::{Mailbox, Mailboxes};
        let mut mboxes = Mailboxes::new();
        mboxes.push("alice@example.com".parse::<Mailbox>().unwrap());
        mboxes.push("bob@example.com".parse::<Mailbox>().unwrap());
        FileState {
            uploaded: 1234,
            cryptify_token: String::new(),
            expires: 1_700_000_000,
            recipients: mboxes,
            mail_content: String::new(),
            mail_lang: Language::En,
            sender: Some("sender@example.com".to_owned()),
            sender_attributes: vec![
                ("orgName".to_owned(), "Acme".to_owned()),
                ("phone".to_owned(), "+31123".to_owned()),
            ],
            confirm: true,
            source_channel: String::new(),
            client_version: None,
            client_app: None,
            notify_recipients: true,
            api_key_tenant: None,
            api_key_validation_failed: false,
            last_chunk: None,
            recovery_token_hash: String::new(),
            challenge: None,
            sender_claim: None,
        }
    }

    #[rocket::async_test]
    async fn staging_mode_skips_smtp_and_returns_summary() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let state = staging_filestate();
        let res = send_email(&config, &state, "uuid-abc")
            .await
            .expect("staging mode should return Ok without contacting SMTP");
        assert!(res.starts_with("[STAGING]"), "got: {}", res);
        assert!(res.contains("alice@example.com"), "got: {}", res);
        assert!(res.contains("bob@example.com"), "got: {}", res);
        assert!(res.contains("sender@example.com"), "got: {}", res);
        assert!(res.contains("orgName=Acme"), "got: {}", res);
        assert!(res.contains("uuid=uuid-abc"), "got: {}", res);
        assert!(
            res.contains("https://staging.example.com/download?uuid=uuid-abc"),
            "got: {}",
            res
        );
    }

    #[test]
    fn render_recipient_email_embeds_download_url_with_uuid_and_recipient() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let state = staging_filestate();
        let rendered = render_recipient_email(&state, &config, "alice@example.com", "uuid-abc")
            .expect("render");
        assert_eq!(rendered.recipient, "alice@example.com");
        assert!(
            rendered.reply_to.is_none(),
            "the fixture proves nothing, so there is no address to reply to"
        );
        // HTML escapes `&` to `&amp;`; the plain-text branch is the
        // cleanest place to assert URL composition.
        assert!(
            rendered.text.contains(
                "https://staging.example.com/download?uuid=uuid-abc&recipient=alice%40example.com"
            ),
            "text missing download URL: {}",
            rendered.text
        );
        assert_eq!(rendered.subject, EN_STRINGS.subject_neutral);
        // The download-link block must render as a prominent, selectable
        // monospace code block that is not smaller than the 16px primary
        // button (see issue #186). Pin a contiguous substring unique to the
        // restyled `<a>` (the primary button is `display:inline-block` and not
        // monospace), so a font-size regression here genuinely fails — a bare
        // `font-size:16px` check would pass on the button alone.
        assert!(
            rendered.html.contains(
                "display:block;font-family:'Courier New',Consolas,Monaco,monospace;font-size:16px;"
            ),
            "download-link block should be a >=16px monospace code block: {}",
            rendered.html
        );
    }

    #[test]
    fn render_confirmation_email_targets_sender_and_drops_reply_to() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let state = staging_filestate();
        let rendered = render_confirmation_email(&state, &config, "uuid-xyz")
            .expect("render")
            .expect("confirmation present when state.sender is Some");
        assert_eq!(rendered.recipient, "sender@example.com");
        assert!(
            rendered.reply_to.is_none(),
            "confirmation should not set Reply-To"
        );
        assert!(
            rendered.html.contains("uuid=uuid-xyz"),
            "html missing uuid: {}",
            rendered.html
        );
    }

    #[test]
    fn render_confirmation_email_returns_none_without_sender() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let mut state = staging_filestate();
        state.sender = None;
        let rendered = render_confirmation_email(&state, &config, "uuid-xyz").expect("render");
        assert!(rendered.is_none());
    }

    /// A `Proven` claim whose address and attribute value appear nowhere else
    /// in the fixtures, so a test that finds either in the output knows the
    /// proof put it there and not the container's own claimed attributes.
    fn proven_claim() -> SenderClaim {
        SenderClaim::Proven {
            email: "proven@example.com".to_owned(),
            attrs: vec![(
                "pbdf.sidn-pbdf.email.domain".to_owned(),
                "example.org".to_owned(),
            )],
        }
    }

    fn state_with_claim(claim: Option<SenderClaim>) -> FileState {
        let mut state = staging_filestate();
        state.sender_claim = claim;
        state
    }

    /// The whole 3x2: every claim a session can carry, against both positions
    /// of the kill switch. Exactly one cell — a proven claim with the switch
    /// on — may render attributed, and the other five must be byte-identical
    /// neutral output.
    ///
    /// This is the guard that the switch is a one-way valve. Were it an input
    /// to the verification instead of a downgrade applied after it, switch-on
    /// could lift an `Unproven` upload into the attributed arm and those cells
    /// would stop matching each other.
    #[test]
    fn only_a_proven_claim_with_the_switch_on_renders_attributed() {
        let mut attributed: Vec<(String, String)> = Vec::new();
        let mut neutral: Vec<(String, String)> = Vec::new();

        for switch_on in [true, false] {
            let config = CryptifyConfig::for_test("https://staging.example.com/", true)
                .with_attributed_email(switch_on);
            // `None` is not a fourth case to invent a rule for: it means
            // finalize has not run, which proves exactly as much as
            // `Unproven` does.
            for claim in [Some(proven_claim()), Some(SenderClaim::Unproven), None] {
                let proven = matches!(claim, Some(SenderClaim::Proven { .. }));
                let state = state_with_claim(claim);
                let rendered =
                    render_recipient_email(&state, &config, "alice@example.com", "uuid-abc")
                        .expect("render");
                let cell = format!("(proven={proven}, switch_on={switch_on})");
                let json = serde_json::to_string(&rendered).expect("serialize rendering");
                if proven && switch_on {
                    attributed.push((cell, json));
                } else {
                    neutral.push((cell, json));
                }
            }
        }

        assert_eq!(
            attributed.len(),
            1,
            "exactly one cell of the 3x2 may be attributed"
        );
        assert_eq!(neutral.len(), 5);

        let (first_cell, first_json) = &neutral[0];
        for (cell, json) in &neutral[1..] {
            assert_eq!(
                json, first_json,
                "{cell} must render byte-identically to {first_cell}"
            );
        }
        assert_ne!(
            &attributed[0].1, first_json,
            "the attributed cell must actually differ from the neutral ones"
        );
    }

    /// What a neutral notification must not contain: the tick, an address of
    /// any kind, or a `Reply-To` pointing at one.
    #[test]
    fn a_neutral_notification_carries_no_tick_no_address_and_no_reply_to() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        for claim in [Some(SenderClaim::Unproven), None] {
            let state = state_with_claim(claim);
            let rendered = render_recipient_email(&state, &config, "alice@example.com", "uuid-abc")
                .expect("render");
            assert!(!rendered.attributed);
            assert!(
                !rendered.html.contains("cid:pg-check"),
                "html tick: {}",
                rendered.html
            );
            // The download URL percent-encodes the recipient, so an `@` left
            // anywhere in a neutral body is an address the mail asserts.
            assert!(!rendered.html.contains('@'), "html: {}", rendered.html);
            assert!(!rendered.text.contains('@'), "text: {}", rendered.text);
            assert!(rendered.reply_to.is_none());
        }
    }

    /// The attributed rendering shows the proven address, and shows it in the
    /// body only: the subject stays the brand-only one, because a display name
    /// resembling a known contact from an external domain is what Microsoft
    /// 365 Defender's user-impersonation rule scores.
    #[test]
    fn a_proven_notification_carries_the_address_the_tick_and_a_neutral_subject() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let state = state_with_claim(Some(proven_claim()));
        let rendered = render_recipient_email(&state, &config, "alice@example.com", "uuid-abc")
            .expect("render");

        assert!(rendered.attributed);
        assert!(rendered.html.contains("cid:pg-check"), "{}", rendered.html);
        assert!(rendered.html.contains(EN_STRINGS.on_behalf_of));
        assert!(rendered.html.contains("proven@example.com"));
        assert!(rendered.text.contains(EN_STRINGS.on_behalf_of));
        assert!(rendered.text.contains("proven@example.com"));
        assert_eq!(rendered.reply_to.as_deref(), Some("proven@example.com"));
        assert_eq!(rendered.subject, EN_STRINGS.subject_neutral);

        // The chips come off the proof. `staging_filestate`'s own
        // `sender_attributes` are the container's word and stay out.
        assert!(rendered.html.contains("example.org"), "{}", rendered.html);
        assert!(
            !rendered.html.contains("Acme"),
            "claimed attributes must not render: {}",
            rendered.html
        );
    }

    /// A string missing from one locale ships that language an empty line, so
    /// pin both new keys in both — and pin that a Dutch upload actually reads
    /// the Dutch ones.
    #[test]
    fn both_locales_define_the_attribution_strings() {
        for (code, strings) in [("EN", EN_STRINGS), ("NL", NL_STRINGS)] {
            assert!(!strings.on_behalf_of.is_empty(), "{code}.on_behalf_of");
            assert!(
                !strings.subject_neutral.is_empty(),
                "{code}.subject_neutral"
            );
        }

        let config = CryptifyConfig::for_test("https://staging.example.com/", true);
        let mut state = state_with_claim(Some(proven_claim()));
        state.mail_lang = Language::Nl;
        let rendered = render_recipient_email(&state, &config, "alice@example.com", "uuid-abc")
            .expect("render");
        assert_eq!(rendered.subject, NL_STRINGS.subject_neutral);
        assert!(
            rendered.html.contains(NL_STRINGS.on_behalf_of),
            "{}",
            rendered.html
        );
    }

    /// The sender's own confirmation copy goes through the same split, so it
    /// cannot keep an unconditional tick after the notification lost one.
    #[test]
    fn the_confirmation_copy_splits_the_same_way() {
        let config = CryptifyConfig::for_test("https://staging.example.com/", true);

        let neutral = render_confirmation_email(&state_with_claim(None), &config, "uuid-xyz")
            .expect("render")
            .expect("confirmation present when state.sender is Some");
        assert!(!neutral.attributed);
        assert!(
            !neutral.html.contains("cid:pg-check"),
            "html tick: {}",
            neutral.html
        );
        assert!(!neutral.html.contains(EN_STRINGS.on_behalf_of));

        let attributed =
            render_confirmation_email(&state_with_claim(Some(proven_claim())), &config, "uuid-xyz")
                .expect("render")
                .expect("confirmation present when state.sender is Some");
        assert!(attributed.attributed);
        assert!(attributed.html.contains("cid:pg-check"));
        assert!(attributed.html.contains("proven@example.com"));
        // Still the sender's own copy: no Reply-To, and the subject is the
        // confirmation one, address-free either way.
        assert!(attributed.reply_to.is_none());
        assert_eq!(attributed.subject, EN_STRINGS.subject_confirm);
    }

    /// The tick is a MIME part as much as a line of HTML. A neutral body
    /// references no checkmark, and an inline image nothing references is one
    /// some clients offer to the reader as an attachment.
    #[test]
    fn the_tick_image_is_attached_only_to_an_attributed_body() {
        for attributed in [true, false] {
            let body = build_body("<p>hi</p>".to_owned(), "hi".to_owned(), attributed)
                .expect("build body");
            let msg = Message::builder()
                .from("noreply@example.com".parse::<Mailbox>().unwrap())
                .to("to@example.com".parse::<Mailbox>().unwrap())
                .subject("t")
                .multipart(body)
                .expect("build message");
            let raw = String::from_utf8(msg.formatted()).expect("utf8");
            assert_eq!(
                raw.contains("pg-check"),
                attributed,
                "attributed={attributed}: {raw}"
            );
            assert!(raw.contains("pg-logo"), "the logo is on both renderings");
        }
    }

    /// `Language::code` is what `store.rs` persists in the `mail_lang`
    /// column, and the wire uses the serde representation. They have to be
    /// the same token, or a restored session would come back with a
    /// `mailLang` no client sent — so pin them to each other rather than to
    /// two hand-written literals.
    #[test]
    fn language_code_matches_serde_representation() {
        for lang in [Language::En, Language::Nl] {
            let serialized = serde_json::to_string(&lang).expect("serialize language");
            assert_eq!(serialized, format!("\"{}\"", lang.code()));
        }
    }

    /// Restoring a session reads `mail_lang` back through `from_code`, so
    /// every code `code()` can write has to come back as the same variant —
    /// and nothing else may be accepted, or a corrupt row would resume in a
    /// language the sender never chose.
    #[test]
    fn language_code_round_trips_through_from_code() {
        for lang in [Language::En, Language::Nl] {
            assert_eq!(Language::from_code(lang.code()), Some(lang.clone()));
        }
        for unknown in ["", "en", "nl", "DE", "EN "] {
            assert_eq!(
                Language::from_code(unknown),
                None,
                "{unknown:?} is not a language this binary writes"
            );
        }
    }

    #[test]
    fn format_file_size_clamps_above_tb() {
        // u64 max is ~16 EB, far beyond TB — previously UNITS[i] would panic.
        // The clamp keeps us at TB and produces a sensible large-TB number.
        let result = format_file_size(u64::MAX);
        assert!(result.ends_with(" TB"), "got {}", result);
    }
}
