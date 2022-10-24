use actix_web::{
    http::header::{CacheControl, CacheDirective, ContentType, ETag, LastModified},
    web::Data,
    HttpResponse, Responder,
};

use crate::server::ParametersData;

pub async fn parameters(pd: Data<ParametersData>) -> impl Responder
where
{
    HttpResponse::Ok()
        .insert_header(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::NoCache,
        ]))
        .insert_header(ETag(pd.etag.clone()))
        .insert_header(LastModified(pd.last_modified.into()))
        .content_type(ContentType::json())
        .body(pd.pp.clone())
}
