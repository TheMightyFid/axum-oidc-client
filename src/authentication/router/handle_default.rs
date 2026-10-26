use axum::response::{IntoResponse, Response};
use axum_extra::extract::{PrivateCookieJar, cookie::Key};
use futures_util::future::BoxFuture;
use time::Duration;

use crate::authentication::{
    OAuthConfiguration, SESSION_KEY, cache::AuthCache, cookies::build_session_cookie,
};

use std::sync::Arc;

pub fn handle_default<F, E>(
    configuration: Arc<OAuthConfiguration>,
    _cache: Arc<dyn AuthCache + Send + Sync>,
    jar: PrivateCookieJar<Key>,
    session_id: Option<String>,
    future: F,
) -> BoxFuture<'static, Result<Response, E>>
where
    F: Future<Output = Result<Response, E>> + Send + 'static,
{
    Box::pin(async move {
        let response = future.await?;
        let jar = match session_id {
            Some(id) => {
                // Do not renew server-side expiry on ordinary requests: sessions
                // have an absolute lifetime set when authentication succeeds.
                let cookie_max_age = if configuration.session_cookie {
                    None
                } else {
                    Some(Duration::minutes(configuration.session_max_age_minutes))
                };
                jar.add(build_session_cookie(
                    SESSION_KEY,
                    Some(id),
                    configuration.lax_same_site,
                    configuration.secure_cookies,
                    cookie_max_age,
                ))
            }
            None => jar,
        };

        Ok((jar, response).into_response())
    })
}
