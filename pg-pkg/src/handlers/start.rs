use crate::util::{IrmaToken, IrmaUrl};
use crate::Error;
use actix_web::{web::Data, web::Json, HttpResponse};
use irma::*;
use pg_core::api::{ConItem, DisclosureAttribute, IrmaAuthRequest};

/// Maximum allowed validity (in seconds) of a JWT (1 day).
const MAX_VALIDITY: u64 = 60 * 60 * 24;

/// Default validity if no validity is specified (5 min).
const DEFAULT_VALIDITY: u64 = 60 * 5;

async fn create_irma_session(
    url: &IrmaUrl,
    irma_token: &IrmaToken,
    dr: IrmaRequest,
    validity: Option<u64>,
) -> Result<HttpResponse, Error> {
    let validity = match validity {
        Some(v) if v > MAX_VALIDITY => return Err(Error::ValidityError),
        Some(v) => v,
        None => DEFAULT_VALIDITY,
    };

    let er = ExtendedIrmaRequest {
        timeout: None,
        callback_url: None,
        validity: Some(validity),
        request: dr,
    };

    let mut builder = IrmaClientBuilder::new(&url.0).map_err(|_e| Error::ClientInvalid)?;
    if let Some(token) = irma_token.0.clone() {
        builder = builder.token_authentication(token);
    }
    let client = builder.build();

    let session = client
        .request_extended(&er)
        .await
        .or(Err(Error::SessionCreationError))?;

    Ok(HttpResponse::Ok().json(session))
}

fn attr_to_request(attr: &DisclosureAttribute) -> AttributeRequest {
    AttributeRequest::Compound {
        attr_type: attr.atype.clone(),
        value: attr.value.clone().filter(|v: &String| !v.is_empty()),
        not_null: true,
    }
}

/// Map one top-level `con` entry to the Yivi discon shape
/// (`Vec<Vec<AttributeRequest>>` — OR of ANDs).
fn con_item_to_discon(item: &ConItem) -> Vec<Vec<AttributeRequest>> {
    match item {
        ConItem::Single(attr) => {
            let ar = attr_to_request(attr);
            if attr.optional {
                // An empty option lets the user skip this attribute. It goes
                // LAST: deployed Yivi apps mis-render a disjunction whose
                // empty alternative comes first (irmamobile#360) — the same
                // workaround clients apply to their own discons.
                vec![vec![ar], vec![]]
            } else {
                vec![vec![ar]]
            }
        }
        ConItem::Discon(disjuncts) => disjuncts
            .iter()
            .map(|conj| conj.iter().map(attr_to_request).collect())
            .collect(),
    }
}

// Starts a Yivi disclosure session.
// Builds a disclosure request for every attribute in the request's policy.
pub async fn start(
    url: Data<IrmaUrl>,
    irma_token: Data<IrmaToken>,
    value: Json<IrmaAuthRequest>,
) -> Result<HttpResponse, Error> {
    let kr = value.into_inner();

    let discons: Vec<Vec<Vec<AttributeRequest>>> = kr.con.iter().map(con_item_to_discon).collect();

    let dr = DisclosureRequestBuilder::new().add_discons(discons).build();

    log::debug!(
        "disclosure request: {}",
        serde_json::to_string_pretty(&dr).unwrap_or_default()
    );

    create_irma_session(&url, &irma_token, dr, kr.validity).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(t: &str) -> DisclosureAttribute {
        DisclosureAttribute {
            atype: t.to_string(),
            value: None,
            optional: false,
        }
    }

    fn extract_atype(ar: &AttributeRequest) -> &str {
        match ar {
            AttributeRequest::Compound { attr_type, .. } => attr_type.as_str(),
            AttributeRequest::Simple(s) => s.as_str(),
        }
    }

    #[test]
    fn single_required_maps_to_one_inner_conjunction() {
        let item = ConItem::Single(attr("pbdf.sidn-pbdf.email.email"));
        let dis = con_item_to_discon(&item);
        assert_eq!(dis.len(), 1, "required: one option");
        assert_eq!(dis[0].len(), 1, "one attribute");
        assert_eq!(extract_atype(&dis[0][0]), "pbdf.sidn-pbdf.email.email");
    }

    #[test]
    fn single_optional_appends_empty_alternative_last() {
        let mut a = attr("pbdf.sidn-pbdf.mobilenumber.mobilenumber");
        a.optional = true;
        let item = ConItem::Single(a);
        let dis = con_item_to_discon(&item);
        assert_eq!(dis.len(), 2, "optional: actual + empty alt");
        assert_eq!(dis[0].len(), 1, "actual attribute first");
        // LAST, not first: deployed Yivi apps mis-render an empty-first
        // alternative (irmamobile#360).
        assert!(dis[1].is_empty(), "empty alternative last");
    }

    #[test]
    fn discon_maps_each_inner_conjunction_through() {
        // Models the name disjunction: gemeente fullname OR passport firstName+lastName.
        let item = ConItem::Discon(vec![
            vec![attr("pbdf.gemeente.personalData.fullname")],
            vec![
                attr("pbdf.pbdf.passport.firstName"),
                attr("pbdf.pbdf.passport.lastName"),
            ],
        ]);
        let dis = con_item_to_discon(&item);
        assert_eq!(dis.len(), 2, "two alternatives");
        assert_eq!(dis[0].len(), 1, "first: fullname only");
        assert_eq!(dis[1].len(), 2, "second: firstName + lastName");
        assert_eq!(
            extract_atype(&dis[0][0]),
            "pbdf.gemeente.personalData.fullname"
        );
        assert_eq!(extract_atype(&dis[1][0]), "pbdf.pbdf.passport.firstName");
        assert_eq!(extract_atype(&dis[1][1]), "pbdf.pbdf.passport.lastName");
    }

    #[test]
    fn discon_with_empty_alternative_is_passed_through() {
        // Yivi-native way to mark a whole discon as optional.
        let item = ConItem::Discon(vec![vec![], vec![attr("pbdf.foo.bar.baz")]]);
        let dis = con_item_to_discon(&item);
        assert_eq!(dis.len(), 2);
        assert!(dis[0].is_empty(), "empty alternative preserved");
        assert_eq!(dis[1].len(), 1);
    }
}
