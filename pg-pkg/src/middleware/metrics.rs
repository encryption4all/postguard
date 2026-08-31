use crate::server::POSTGUARD_CLIENTS;
use crate::util::*;
use actix_http::header::HeaderValue;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse},
};
use futures::Future;
use futures_util::future::FutureExt;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, PoisonError, RwLock};

/// Label value for a field the request did not identify: the client header
/// absent, unreadable or not exactly four fields, or a URI actix matched no
/// route for. This is the spelling `util::client_version` and cryptify's
/// `CHANNEL_UNKNOWN` already use, so the two services keep one vocabulary for
/// the header they share.
const UNKNOWN: &str = "unknown";

/// Label value for a field that was read but is not one this fleet emits.
/// Nothing that happens in normal operation may land here: `other` going
/// non-zero is a signal worth alerting on.
const OTHER: &str = "other";

/// `host` values the senders actually emit, matched case-sensitively:
/// `pg-js`'s `detectHost`, the add-ins' own override, and `dotnet` from
/// `E4A.PostGuard`'s `ClientVersion`. The literal `unknown` is one of them —
/// `pg-js` reports it for a runtime it cannot detect — so it is admitted here
/// rather than folded into `other`.
const KNOWN_HOSTS: &[&str] = &[
    "node",
    "browser",
    "bun",
    "deno",
    "Outlook",
    "Thunderbird",
    "dotnet",
    UNKNOWN,
];

/// `client` values the senders actually emit: cryptify's `KNOWN_APPS`, plus
/// `cli` and `pg-cli`. `cli` is the one that arrives today —
/// `pg-cli/src/client.rs` sends `unknown,unknown,cli,<version>`, spelling the
/// header name in mixed case, which HTTP matches all the same. `pg-cli` is
/// kept for the value the CLI would send if it ever aligns with the rest.
const KNOWN_CLIENTS: &[&str] = &[
    "pg-js",
    "pg-dotnet",
    "pg4ol",
    "pg4tb",
    "cli",
    "pg-cli",
    UNKNOWN,
];

/// Longest `client_version` emitted verbatim.
const MAX_CLIENT_VERSION_LEN: usize = 32;

/// How many distinct `client_version` values one client may create a series for.
const MAX_CLIENT_VERSIONS: usize = 64;

/// The distinct `client_version` values emitted so far, one set per `client`.
///
/// The label is kept exact rather than bucketed. `IntCounterVec` never evicts,
/// so a series created once lives until the process restarts, and the field is
/// attacker-controlled. Real versions arrive continuously from live traffic and
/// so take the slots first; an attacker minting distinct values meets the
/// ceiling and lands in `other`.
///
/// The budget is per client rather than one shared by the fleet, because 64 is
/// under what the two SDKs have published between them (55 `@e4a/pg-js`, 9
/// `E4A.PostGuard`): sharing it lets one sender's releases spend the slots a
/// second sender's real releases then miss, and `other` is only alertable while
/// nothing legitimate lands there.
///
/// Keyed on the allowlisted `client` value, which is a closed set, so the worst
/// case is bounded at 8 × 64. Keying it on the raw header field would hand out
/// a fresh budget for every client name an attacker invents.
static SEEN_CLIENT_VERSIONS: LazyLock<RwLock<HashMap<String, HashSet<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn allowlisted(field: &str, allowed: &[&str]) -> String {
    if allowed.contains(&field) {
        field.to_string()
    } else {
        OTHER.to_string()
    }
}

/// `client` is the allowlisted value, not the raw header field: it picks which
/// budget this version spends.
fn client_version_label(client: &str, field: &str) -> String {
    let well_shaped = !field.is_empty()
        && field.len() <= MAX_CLIENT_VERSION_LEN
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');

    if !well_shaped {
        return OTHER.to_string();
    }

    // Neither reserved value consumes a slot of the cap, in any bucket.
    if field == UNKNOWN || field == OTHER {
        return field.to_string();
    }

    if SEEN_CLIENT_VERSIONS
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(client)
        .is_some_and(|seen| seen.contains(field))
    {
        return field.to_string();
    }

    let mut buckets = SEEN_CLIENT_VERSIONS
        .write()
        .unwrap_or_else(PoisonError::into_inner);
    let seen = buckets.entry(client.to_string()).or_default();

    if !seen.contains(field) {
        if seen.len() >= MAX_CLIENT_VERSIONS {
            return OTHER.to_string();
        }
        seen.insert(field.to_string());
    }

    field.to_string()
}

pub(crate) fn collect_metrics<
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
>(
    req: ServiceRequest,
    srv: &S,
) -> impl Future<Output = Result<ServiceResponse<B>, actix_web::Error>> {
    // Never the raw URI as a fallback: it is attacker-controlled and
    // unbounded, where the route pattern is bounded by the route table.
    let path = req.match_pattern().unwrap_or_else(|| UNKNOWN.to_string());

    let header = req
        .headers()
        .get(PG_CLIENT_HEADER)
        .map(HeaderValue::to_str)
        .and_then(Result::ok);

    // Trimmed to match cryptify's parser: the two services read the same
    // header, and a space after a comma must not change the labels.
    let fields =
        header.and_then(
            |header| match header.split(',').map(str::trim).collect::<Vec<&str>>()[..] {
                [host, _host_version, client, client_version] => {
                    let client = allowlisted(client, KNOWN_CLIENTS);
                    let client_version = client_version_label(&client, client_version);
                    Some([allowlisted(host, KNOWN_HOSTS), client, client_version])
                }
                _ => None,
            },
        );

    let [host, client, client_version] = fields.unwrap_or_else(|| {
        [
            UNKNOWN.to_string(),
            UNKNOWN.to_string(),
            UNKNOWN.to_string(),
        ]
    });

    srv.call(req).map(move |res| {
        let status = match &res {
            Ok(resp) => resp.status(),
            Err(e) => e.as_response_error().status_code(),
        };

        POSTGUARD_CLIENTS
            .with_label_values(&[
                path.as_str(),
                host.as_str(),
                client.as_str(),
                client_version.as_str(),
                status.as_str(),
            ])
            .inc();

        res
    })
}

#[cfg(test)]
mod tests {
    // Each `#[actix_web::test]` runs on its own single-threaded runtime with no
    // other task to yield to, so blocking that thread on `EXCLUSIVE` across an
    // await is exactly what keeps the exposition exclusive to one test.
    #![allow(clippy::await_holding_lock)]

    use std::collections::BTreeSet;
    use std::str::FromStr;
    use std::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::server::tests::setup;
    use actix_http::header::HeaderName;
    use actix_http::{Request, StatusCode};
    use actix_web::test;
    use irma::SessionStatus;
    use pg_core::api::{KeyResponse, Parameters};
    use pg_core::artifacts::{PublicKey, UserSecretKey};
    use pg_core::identity::{Attribute, Policy};
    use pg_core::kem::cgw_kv::CGWKV;

    /// The two lines every `postguard_clients` scrape opens with.
    const PREAMBLE: &str = concat!(
        "# HELP postguard_clients Contains information about PostGuard clients connecting with the PKG.\n",
        "# TYPE postguard_clients counter\n",
    );

    /// `POSTGUARD_CLIENTS` and `SEEN_CLIENT_VERSIONS` are process-wide, and the
    /// assertions here are over the whole exposition: two of these tests
    /// running at once would each see the other's series. Every test takes this
    /// lock and starts from an empty counter and an empty cap.
    static EXCLUSIVE: Mutex<()> = Mutex::new(());

    fn exclusive() -> MutexGuard<'static, ()> {
        let guard = EXCLUSIVE.lock().unwrap_or_else(PoisonError::into_inner);

        POSTGUARD_CLIENTS.reset();
        SEEN_CLIENT_VERSIONS
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();

        guard
    }

    fn client_header(value: &str) -> (HeaderName, HeaderValue) {
        (
            HeaderName::from_str(PG_CLIENT_HEADER).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        )
    }

    async fn get<S>(app: &S, uri: &str, client: Option<&str>) -> StatusCode
    where
        S: Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
    {
        let mut req = test::TestRequest::get().uri(uri);
        if let Some(client) = client {
            req = req.insert_header(client_header(client));
        }

        test::call_service(app, req.to_request()).await.status()
    }

    async fn scrape<S>(app: &S) -> String
    where
        S: Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
    {
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let res = test::call_service(app, req).await;
        assert_eq!(res.status(), StatusCode::OK);

        String::from_utf8(test::read_body(res).await.to_vec()).unwrap()
    }

    /// The distinct `client_version` label values one client emitted.
    fn client_versions<'a>(exposition: &'a str, client: &str) -> BTreeSet<&'a str> {
        let label = format!("client=\"{client}\"");
        exposition
            .lines()
            .filter(|line| line.contains(&label))
            .filter_map(|line| line.split("client_version=\"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .collect()
    }

    #[actix_web::test]
    async fn test_get_metrics() {
        let _guard = exclusive();
        let (app, pk, _, _, _) = setup(true).await;
        let header_name = HeaderName::from_str(PG_CLIENT_HEADER).unwrap();

        // First request
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Second request
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Thunderbird,1234.5678.90,pg4tb,0.0.2"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Third request (same as first)
        let header = (
            header_name.clone(),
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let req = test::TestRequest::get()
            .uri("/v2/parameters")
            .insert_header(header)
            .to_request();
        let kr: Parameters<PublicKey<CGWKV>> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(&kr.public_key.0, &pk);

        // Fourth request
        let header = (
            header_name,
            HeaderValue::from_static("Outlook,1234.5678.90,pg4ol,0.0.1"),
        );
        let ts = crate::server::tests::now();
        let pol = Policy {
            timestamp: ts,
            con: vec![Attribute::new("testattribute", Some("testvalue"))],
        };
        let req_usk = test::TestRequest::get()
            .uri(&format!("/v2/key/{ts}"))
            .insert_header(header)
            .set_json(pol.clone())
            .to_request();
        let key_response: KeyResponse<UserSecretKey<CGWKV>> =
            test::call_and_read_body_json(&app, req_usk).await;
        assert_eq!(key_response.status, SessionStatus::Done);

        // Collect metrics. The `2` pins that a repeated request aggregates into
        // one series rather than creating a second.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"pg4ol\",client_version=\"0.0.1\",host=\"Outlook\",path=\"/v2/key/{{timestamp}}\",status=\"200\"}} 1\n\
            postguard_clients{{client=\"pg4ol\",client_version=\"0.0.1\",host=\"Outlook\",path=\"/v2/parameters\",status=\"200\"}} 2\n\
            postguard_clients{{client=\"pg4tb\",client_version=\"0.0.2\",host=\"Thunderbird\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_request_without_client_header_is_counted() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        assert_eq!(get(&app, "/v2/parameters", None).await, StatusCode::OK);

        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"unknown\",client_version=\"unknown\",host=\"unknown\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_malformed_client_header_shares_the_unknown_series() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        assert_eq!(get(&app, "/v2/parameters", None).await, StatusCode::OK);
        assert_eq!(
            get(&app, "/v2/parameters", Some("only,three,fields")).await,
            StatusCode::OK
        );

        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"unknown\",client_version=\"unknown\",host=\"unknown\",path=\"/v2/parameters\",status=\"200\"}} 2\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_unmatched_route_is_counted_without_its_uri() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        assert_eq!(
            get(&app, "/v2/../etc/passwd?q=1", None).await,
            StatusCode::NOT_FOUND
        );

        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"unknown\",client_version=\"unknown\",host=\"unknown\",path=\"unknown\",status=\"404\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_unrecognised_host_and_client_become_other() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        assert_eq!(
            get(&app, "/v2/parameters", Some("Emacs,1.0,pg4emacs,0.0.1")).await,
            StatusCode::OK
        );

        // The allowlist applies per label: the version is still exact.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"other\",client_version=\"0.0.1\",host=\"other\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_sender_reported_unknown_is_not_other() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        // What pg-js emits from a runtime its `detectHost` cannot place.
        assert_eq!(
            get(&app, "/v2/parameters", Some("unknown,unknown,pg-js,1.2.3")).await,
            StatusCode::OK
        );

        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"pg-js\",client_version=\"1.2.3\",host=\"unknown\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_dotnet_sdk_host_is_not_other() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        // What `E4A.PostGuard`'s `ClientVersion` puts on the wire. Its second
        // field is `RuntimeInformation.FrameworkDescription`, which carries a
        // space; that field is not a label, so the space cannot reach one.
        assert_eq!(
            get(
                &app,
                "/v2/parameters",
                Some("dotnet,.NET 8.0.7,pg-dotnet,0.6.0")
            )
            .await,
            StatusCode::OK
        );

        // The .NET SDK is a live sender, so `other` staying empty here is what
        // keeps it alertable.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"pg-dotnet\",client_version=\"0.6.0\",host=\"dotnet\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_pg_cli_client_is_not_other() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        // What `pg-cli/src/client.rs` puts on every PKG call: it detects no
        // host and names itself `cli`, not the `pg-cli` the allowlist carried.
        assert_eq!(
            get(&app, "/v2/parameters", Some("unknown,unknown,cli,0.6.3")).await,
            StatusCode::OK
        );

        // The CLI is a live sender too, so this row is the other half of what
        // keeps `other` alertable.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"cli\",client_version=\"0.6.3\",host=\"unknown\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_padded_header_fields_are_trimmed() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        assert_eq!(
            get(&app, "/v2/parameters", Some("node, 22.1.0, pg-js, 1.2.3")).await,
            StatusCode::OK
        );

        // Every field lands on its real value, not the mixed row an untrimmed
        // parse would give: a recognised host with `other` for the rest.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"pg-js\",client_version=\"1.2.3\",host=\"node\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    #[actix_web::test]
    async fn test_misshapen_client_version_becomes_other() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        // One character over the 32 the shape gate accepts.
        let too_long = "a".repeat(33);
        assert_eq!(
            get(
                &app,
                "/v2/parameters",
                Some(&format!("node,22.1.0,pg-js,{too_long}"))
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            get(
                &app,
                "/v2/parameters",
                Some("browser,1.0,pg-js,1.0.0; DROP")
            )
            .await,
            StatusCode::OK
        );

        // Both rows keep their real host and client.
        let expected = format!(
            "{PREAMBLE}\
            postguard_clients{{client=\"pg-js\",client_version=\"other\",host=\"browser\",path=\"/v2/parameters\",status=\"200\"}} 1\n\
            postguard_clients{{client=\"pg-js\",client_version=\"other\",host=\"node\",path=\"/v2/parameters\",status=\"200\"}} 1\n"
        );

        assert_eq!(expected, scrape(&app).await);
    }

    /// Spends `count` of one client's budget on distinct well-shaped versions.
    async fn mint_versions<S>(app: &S, client: &str, count: usize)
    where
        S: Service<Request, Response = ServiceResponse, Error = actix_web::Error>,
    {
        for i in 0..count {
            assert_eq!(
                get(
                    app,
                    "/v2/parameters",
                    Some(&format!("node,22.1.0,{client},9.9.{i}"))
                )
                .await,
                StatusCode::OK
            );
        }
    }

    #[actix_web::test]
    async fn test_client_version_cap_holds() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        let minted = 70;
        mint_versions(&app, "pg-js", minted).await;

        let body = scrape(&app).await;
        let versions = client_versions(&body, "pg-js");

        // 64 versions, plus everything after the cap folded into one `other`.
        assert!(versions.contains(OTHER));
        assert_eq!(versions.len(), MAX_CLIENT_VERSIONS + 1);
        assert!(body.contains(&format!(
            "postguard_clients{{client=\"pg-js\",client_version=\"other\",host=\"node\",path=\"/v2/parameters\",status=\"200\"}} {}\n",
            minted - MAX_CLIENT_VERSIONS
        )));
    }

    #[actix_web::test]
    async fn test_a_full_client_does_not_spend_another_clients_budget() {
        let _guard = exclusive();
        let (app, _, _, _, _) = setup(true).await;

        mint_versions(&app, "pg-js", MAX_CLIENT_VERSIONS).await;

        // pg-js has spent its budget to the slot; pg-dotnet has spent none of
        // its own, so its first release is still a series of its own.
        assert_eq!(
            get(&app, "/v2/parameters", Some("node,22.1.0,pg-dotnet,0.6.0")).await,
            StatusCode::OK
        );

        let body = scrape(&app).await;

        assert_eq!(client_versions(&body, "pg-js").len(), MAX_CLIENT_VERSIONS);
        assert_eq!(
            client_versions(&body, "pg-dotnet"),
            BTreeSet::from(["0.6.0"])
        );
        assert!(body.contains(
            "postguard_clients{client=\"pg-dotnet\",client_version=\"0.6.0\",host=\"node\",path=\"/v2/parameters\",status=\"200\"} 1\n"
        ));
    }
}
