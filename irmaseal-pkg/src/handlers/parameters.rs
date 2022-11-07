use actix_http::header::Header;
use actix_web::{
    http::header::{
        CacheControl, CacheDirective, ContentType, ETag, IfModifiedSince, IfNoneMatch, LastModified,
    },
    web::Data,
    HttpRequest, HttpResponse, Responder,
};

use crate::server::ParametersData;

pub async fn parameters(req: HttpRequest, pd: Data<ParametersData>) -> impl Responder
where
{
    let if_none_match = IfNoneMatch::parse(&req);
    let if_modified_since = IfModifiedSince::parse(&req);

    match (if_none_match, if_modified_since) {
        (Ok(IfNoneMatch::Items(ref tags)), ..) if tags.iter().any(|t| t.strong_eq(&pd.etag)) => {
            HttpResponse::NotModified().finish()
        }
        (.., Ok(IfModifiedSince(ref since))) if &pd.last_modified <= since => {
            HttpResponse::NotModified().finish()
        }
        _ => HttpResponse::Ok()
            .insert_header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::NoCache,
            ]))
            .insert_header(ETag(pd.etag.clone()))
            .insert_header(LastModified(pd.last_modified))
            .content_type(ContentType::json())
            .body(pd.pp.clone()),
    }
}
