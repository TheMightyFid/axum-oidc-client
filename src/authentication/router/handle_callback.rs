use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;

use http::{StatusCode, Uri, request::Parts};
use reqwest::{self, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::Duration;
use uuid::Uuid;

use crate::{
    authentication::{
        cache::AuthCache,
        cookies::{build_session_cookie, build_transaction_cookie},
        session::AuthSession,
        {AUTH_TRANSACTION_KEY, OAuthConfiguration, SESSION_KEY},
    },
    errors::Error,
};

#[derive(Debug, Deserialize, PartialEq)]
struct CodeExchange {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct AccessTokenResponse {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<String>,
}

async fn get_auth_tokens(
    configuration: Arc<OAuthConfiguration>,
    cache: Arc<dyn AuthCache + Send + Sync>,
    client: Arc<Client>,
    transaction: &str,
    uri: &Uri,
) -> Result<(AccessTokenResponse, Option<String>), Error> {
    let querystring = uri.query();
    let query = querystring
        .map(|qs| {
            serde_html_form::from_str::<CodeExchange>(qs)
                .map_err(|e| Error::InvalidCodeResponse(e.to_string()))
        })
        .ok_or(Error::MissingPatameter("code".to_owned()))
        .flatten()?;

    // Split the state into the cache key (UUID) and optional post-login redirect path.
    // Format: "<uuid>" or "<uuid>|<path>".
    let (state_key, post_login_redirect) = if let Some((key, path)) = query.state.split_once('|') {
        (key.to_string(), Some(path.to_string()))
    } else {
        (query.state.clone(), None)
    };

    let OAuthConfiguration {
        redirect_uri,
        client_id,
        token_endpoint,
        client_secret,
        token_request_redirect_uri,
        ..
    } = configuration.as_ref();

    let (transaction_state, nonce) = transaction.split_once(':').ok_or_else(|| {
        Error::InvalidCodeResponse("invalid authorization transaction".to_string())
    })?;
    if transaction_state != state_key {
        return Err(Error::InvalidCodeResponse(
            "authorization state does not match initiating browser".to_string(),
        ));
    }

    let verifier = cache
        .get_code_verifier(&state_key)
        .await?
        .ok_or(Error::MissingCodeVerifier)?;

    // Invalidate immediately after retrieval — the verifier is single-use.
    // This runs before the token exchange so that a network error or a
    // rejected exchange cannot be retried with the same verifier.
    cache.invalidate_code_verifier(&state_key).await?;

    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", &query.code),
        ("client_id", client_id),
        ("code_verifier", &verifier),
    ];
    if *token_request_redirect_uri {
        params.push(("redirect_uri", redirect_uri));
    }

    let url = reqwest::Url::parse(token_endpoint)
        .map_err(|_| Error::NotValidUri(token_endpoint.to_string()))?;

    let res = client
        .post(url)
        .form(&params)
        .basic_auth(
            client_id,
            if client_secret.is_empty() {
                None
            } else {
                Some(client_secret.to_string())
            },
        )
        .send()
        .await
        .map_err(Error::from_request_error)?;

    match res.status() {
        StatusCode::OK => {
            let auth_session = res
                .json::<AccessTokenResponse>()
                .await
                .map_err(Error::from_request_error)?;

            validate_id_token(&auth_session.id_token, &configuration, nonce)?;
            Ok((auth_session, post_login_redirect))
        }
        status => {
            let err = res.text().await.map_err(Error::from_request_error)?;
            Err(Error::from_status_code(status, err))
        }
    }
}

fn validate_id_token(
    token: &str,
    configuration: &OAuthConfiguration,
    expected_nonce: &str,
) -> Result<(), Error> {
    let issuer = configuration.issuer.as_deref().ok_or_else(|| {
        Error::InvalidTokenResponse("OIDC issuer is not configured; use with_issuer".to_string())
    })?;
    let jwks = configuration.id_token_jwks.as_ref().ok_or_else(|| {
        Error::InvalidTokenResponse("OIDC JWKS is not configured; use with_issuer".to_string())
    })?;
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| Error::InvalidTokenResponse(format!("invalid ID-token header: {e}")))?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| Error::InvalidTokenResponse("ID token has no key identifier".to_string()))?;
    let key = jwks
        .decoding_key_for_kid_and_algorithm(kid, header.alg)
        .map_err(|e| Error::InvalidTokenResponse(e.to_string()))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&[&configuration.client_id]);
    validation.set_issuer(&[issuer]);
    let claims = jsonwebtoken::decode::<crate::jwt::OidcClaims>(token, &key, &validation)
        .map_err(|e| Error::InvalidTokenResponse(format!("ID-token validation failed: {e}")))?
        .claims;
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(Error::InvalidTokenResponse(
            "ID-token nonce does not match authorization transaction".to_string(),
        ));
    }
    if claims.aud.len() > 1 && claims.azp.as_deref() != Some(&configuration.client_id) {
        return Err(Error::InvalidTokenResponse(
            "multi-audience ID token is missing the expected azp claim".to_string(),
        ));
    }
    Ok(())
}

pub async fn handle_callback(parts: &mut Parts, uri: Uri) -> Result<Response, Error> {
    let configuration = parts
        .extensions
        .get::<Arc<OAuthConfiguration>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("OAuthConfiguration not configured".to_string()))?;

    let cache = parts
        .extensions
        .get::<Arc<dyn AuthCache + Send + Sync>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("AuthCache not configured".to_string()))?;

    let client = parts
        .extensions
        .get::<Arc<Client>>()
        .cloned()
        .ok_or_else(|| Error::CacheAccessError("HTTP Client not configured".to_string()))?;

    let OAuthConfiguration {
        private_cookie_key, ..
    } = configuration.as_ref();

    let jar = PrivateCookieJar::from_headers(&parts.headers, private_cookie_key.to_owned());
    let transaction = jar
        .get(AUTH_TRANSACTION_KEY)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| {
            Error::InvalidCodeResponse("missing authorization transaction".to_string())
        })?;

    let id = Uuid::new_v4().to_string();

    let (token_response, post_login_redirect) = get_auth_tokens(
        configuration.clone(),
        cache.clone(),
        client.clone(),
        &transaction,
        &uri,
    )
    .await?;

    cache
        .set_auth_session(&id, AuthSession::new(&token_response, &configuration))
        .await?;

    tracing::debug!("auth: token exchange succeeded, session stored and cookie set");

    let max_age = if configuration.session_cookie {
        // Browser-session cookie: omit Max-Age so the browser drops it on close.
        None
    } else {
        Some(Duration::minutes(configuration.session_max_age_minutes))
    };
    let jar = jar.add(build_session_cookie(
        SESSION_KEY,
        Some(id.clone()),
        configuration.lax_same_site,
        configuration.secure_cookies,
        max_age,
    ));
    let jar = jar.remove(build_transaction_cookie(None, configuration.secure_cookies));

    // Belt-and-suspenders validation: re-check the redirect path even though
    // handle_auth already validated it before embedding it in the state.  The
    // provider echoes the state back verbatim, but a defensive check here
    // prevents any open-redirect if the state were somehow tampered with.
    let redirect_to = match post_login_redirect {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => path,
        _ => "/".to_string(),
    };

    // Use a real HTTP 303 redirect rather than an HTML meta-refresh: the browser
    // commits the `Set-Cookie` header on this response before following the
    // `Location`, so the subsequent request carries the session cookie. A
    // meta-refresh can navigate before the cookie is committed, producing a
    // "no cookie" bounce back through /auth (the redirect loop).
    Ok((jar, Redirect::to(&redirect_to)).into_response())
}
