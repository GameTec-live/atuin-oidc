//! Hub-compatible browser login backed by a single OpenID Connect provider.
//!
//! Users and hashed sessions reuse upstream storage. Only the short-lived
//! browser handshakes live in memory, so deployments use one server process.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use atuin_common::url::UrlAppendExt;
use atuin_common::utils::crypto_random_string;
use atuin_domain::api::{CliCodeResponse, CliVerifyResponse, ErrorResponse};
use axum::extract::{Form, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use eyre::{Context, Result, ensure};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use parking_lot::Mutex;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use url::Url;

use crate::db::models::{HashedPassword, NewSession, NewUser, User};
use crate::db::{DbError, DynDatabase};
use crate::handlers::{ErrorResponseStatus, RespExt};
use crate::router::AppState;

const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
const COOKIE: &str = "atuin_oidc";

/// Configuring this section enables OIDC and disables password authentication.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcSettings {
    pub issuer_url: IssuerUrl,
    pub client_id: String,
    pub public_url: Url,
    #[serde(default, serialize_with = "atuin_domain::secret::serialize_option")]
    pub client_secret: Option<SecretString>,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Absolute session lifetime in seconds. Zero (the default) disables expiration.
    #[serde(default)]
    pub session_ttl_seconds: u32,
    #[serde(default = "default_max_pending")]
    pub max_pending_logins: usize,
    /// For local development only. Production uses HTTPS for all provider URLs.
    #[serde(default)]
    pub allow_http: bool,
}

const fn default_max_pending() -> usize {
    1024
}

type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct Oidc {
    client: DiscoveredClient,
    http: reqwest::Client,
    settings: OidcSettings,
    cookie_path: String,
    pending: Mutex<HashMap<String, PendingLogin>>,
}

struct PendingLogin {
    created: Instant,
    stage: Stage,
}

enum Stage {
    Waiting,
    Authenticating {
        state: CsrfToken,
        browser: SecretString,
        nonce: Nonce,
        verifier: PkceCodeVerifier,
    },
    Exchanging,
    Confirm {
        state: String,
        browser: SecretString,
        identity: String,
    },
    Complete(SecretString),
    Failed,
}

type LoginResult<T> = Result<T, ErrorResponseStatus<'static>>;

fn error(status: StatusCode, reason: &'static str) -> ErrorResponseStatus<'static> {
    ErrorResponse::reply(reason).with_status(status)
}

fn invalid_login() -> ErrorResponseStatus<'static> {
    error(StatusCode::BAD_REQUEST, "Invalid or expired login. Run atuin login again.")
}

impl Oidc {
    pub(crate) async fn discover(settings: &OidcSettings, path: &str) -> Result<Self> {
        ensure!(settings.max_pending_logins > 0, "OIDC max_pending_logins must be positive");
        ensure!(!settings.client_id.is_empty(), "OIDC client_id must not be empty");
        ensure!(
            settings.public_url.path().trim_end_matches('/') == path.trim_end_matches('/'),
            "OIDC public_url path must match the server path setting"
        );
        for url in [&settings.public_url, settings.issuer_url.url()] {
            validate_url(url, settings.allow_http)?;
        }
        ensure!(
            settings.client_secret.is_none() || settings.client_secret_file.is_none(),
            "Set only one of OIDC client_secret and client_secret_file"
        );
        let secret = match &settings.client_secret_file {
            Some(path) => {
                let contents =
                    fs_err::read_to_string(path).wrap_err("Reading OIDC client secret")?;
                let secret = contents.trim_end_matches(['\r', '\n']);
                ensure!(!secret.is_empty(), "OIDC client secret file is empty");
                Some(SecretString::from(secret))
            }
            None => settings.client_secret.clone(),
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        let transport = |request| oidc_request(http.clone(), request);
        let metadata =
            CoreProviderMetadata::discover_async(settings.issuer_url.clone(), &transport)
                .await
                .wrap_err("Discovering OIDC provider")?;
        validate_url(metadata.authorization_endpoint().url(), settings.allow_http)?;
        validate_url(metadata.jwks_uri().url(), settings.allow_http)?;
        let token_url =
            metadata.token_endpoint().ok_or_else(|| eyre::eyre!("No OIDC token endpoint"))?;
        validate_url(token_url.url(), settings.allow_http)?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(settings.client_id.clone()),
            secret.map(|secret| ClientSecret::new(secret.expose_secret().to_owned())),
        )
        .set_redirect_uri(RedirectUrl::new(
            settings.public_url.append_path("auth/cli/callback")?.to_string(),
        )?);
        Ok(Self {
            client,
            http,
            settings: settings.clone(),
            cookie_path: format!("{}/auth/cli", path.trim_end_matches('/')),
            pending: Mutex::new(HashMap::new()),
        })
    }

    fn cookie(&self, browser: &str, max_age: u32) -> String {
        let secure = if self.settings.public_url.scheme() == "https" {
            "; Secure"
        } else {
            ""
        };
        format!(
            "{COOKIE}={browser}; Path={}; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
            self.cookie_path
        )
    }
}

fn validate_url(url: &Url, allow_http: bool) -> Result<()> {
    ensure!(
        url.scheme() == "https" || (allow_http && url.scheme() == "http"),
        "OIDC URLs must use HTTPS (allow_http is for local development only)"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "OIDC URLs must not contain credentials, query parameters, or fragments"
    );
    Ok(())
}

// Adapt the workspace's reqwest version without pulling in a second HTTP/TLS stack.
async fn oidc_request(
    http: reqwest::Client,
    request: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, reqwest::Error> {
    let (parts, body) = request.into_parts();
    let response = http
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await?;
    let mut result = openidconnect::HttpResponse::new(Vec::new());
    *result.status_mut() = response.status();
    *result.headers_mut() = response.headers().clone();
    *result.body_mut() = response.bytes().await?.to_vec();
    Ok(result)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/cli/code", post(code))
        .route("/auth/cli", get(begin))
        .route("/auth/cli/callback", get(callback))
        .route("/auth/cli/approve", post(approve))
        // Current clients POST; older Hub clients GET.
        .route("/auth/cli/verify", get(verify).post(verify))
        .layer(axum::middleware::from_fn(private_response))
}

async fn private_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    response
}

async fn code(State(state): State<AppState>) -> LoginResult<Json<CliCodeResponse>> {
    let oidc = state.oidc.as_ref().ok_or_else(invalid_login)?;
    let mut pending = oidc.pending.lock();
    pending.retain(|_, login| login.created.elapsed() < LOGIN_TIMEOUT);
    if pending.len() >= oidc.settings.max_pending_logins {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many pending logins. Try again later.",
        ));
    }
    let code = crypto_random_string::<32>();
    pending.insert(digest(code.expose_secret()), PendingLogin {
        created: Instant::now(),
        stage: Stage::Waiting,
    });
    drop(pending);
    Ok(Json(CliCodeResponse { code }))
}

#[derive(Deserialize)]
struct CodeQuery {
    code: String,
}

async fn begin(
    State(state): State<AppState>,
    Query(query): Query<CodeQuery>,
) -> LoginResult<Response> {
    let oidc = state.oidc.as_ref().ok_or_else(invalid_login)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorization = oidc
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in &oidc.settings.scopes {
        if scope != "openid" {
            authorization = authorization.add_scope(Scope::new(scope.clone()));
        }
    }
    let (url, csrf, nonce) = authorization.url();
    let browser = crypto_random_string::<32>();
    let cookie = oidc.cookie(browser.expose_secret(), 600);
    let mut pending = oidc.pending.lock();
    let login = pending.get_mut(&digest(&query.code)).ok_or_else(invalid_login)?;
    if login.created.elapsed() >= LOGIN_TIMEOUT || !matches!(login.stage, Stage::Waiting) {
        return Err(invalid_login());
    }
    login.stage = Stage::Authenticating {
        state: csrf,
        browser,
        nonce,
        verifier,
    };
    drop(pending);
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to(url.as_str())).into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

fn browser_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == COOKIE).then_some(value))
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> LoginResult<Response> {
    let oidc = state.oidc.as_ref().ok_or_else(invalid_login)?;
    let (key, nonce, verifier, browser) = {
        let mut pending = oidc.pending.lock();
        let (key, login) = pending
            .iter_mut()
            .find(|(_, login)| {
                matches!(&login.stage, Stage::Authenticating { state, browser, .. }
                if state.secret() == &query.state
                    && Some(browser.expose_secret()) == browser_cookie(&headers))
            })
            .ok_or_else(invalid_login)?;
        if login.created.elapsed() >= LOGIN_TIMEOUT {
            return Err(invalid_login());
        }
        let Stage::Authenticating {
            nonce,
            verifier,
            browser,
            ..
        } = std::mem::replace(&mut login.stage, Stage::Exchanging)
        else {
            unreachable!()
        };
        let key = key.clone();
        drop(pending);
        (key, nonce, verifier, browser)
    };
    let identity = if query.error.is_none() {
        match query.code {
            Some(code) => exchange(oidc, code, &nonce, verifier).await.ok(),
            None => None,
        }
    } else {
        None
    };
    let mut pending = oidc.pending.lock();
    let login = pending.get_mut(&key).ok_or_else(invalid_login)?;
    let Some(identity) = identity else {
        login.stage = Stage::Failed;
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "OIDC authentication failed. Run atuin login again.",
        ));
    };
    if login.created.elapsed() >= LOGIN_TIMEOUT {
        return Err(invalid_login());
    }
    // Explicit consent prevents a visit to a login URL from silently authorizing a terminal.
    let approval = crypto_random_string::<32>().expose_secret().to_owned();
    login.stage = Stage::Confirm {
        state: approval.clone(),
        browser,
        identity,
    };
    drop(pending);
    Ok(Html(format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Atuin \
         login</title><h1>Authorize Atuin?</h1><p>Only approve if you ran <code>atuin \
         login</code> and opened this page yourself. Approval gives that terminal access to your \
         encrypted history.</p><form method=\"post\" action=\"approve\"><input type=\"hidden\" \
         name=\"state\" value=\"{approval}\"><button type=\"submit\">Authorize this \
         terminal</button></form></html>"
    ))
    .into_response())
}

async fn exchange(
    oidc: &Oidc,
    code: String,
    nonce: &Nonce,
    verifier: PkceCodeVerifier,
) -> Result<String> {
    let transport = |request| oidc_request(oidc.http.clone(), request);
    let tokens = oidc
        .client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(verifier)
        .request_async(&transport)
        .await?;
    let token = tokens.id_token().ok_or_else(|| eyre::eyre!("Missing ID token"))?;
    let claims = token.claims(&oidc.client.id_token_verifier(), nonce)?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            tokens.access_token(),
            token.signing_alg()?,
            token.signing_key(&oidc.client.id_token_verifier())?,
        )?;
        ensure!(&actual == expected, "Access token hash mismatch");
    }
    Ok(identity_digest(claims.issuer().as_str(), claims.subject().as_str()))
}

#[derive(Deserialize)]
struct Approval {
    state: String,
}

async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<Approval>,
) -> LoginResult<Response> {
    let oidc = state.oidc.as_ref().ok_or_else(invalid_login)?;
    let (key, identity) = {
        let mut pending = oidc.pending.lock();
        let (key, login) = pending.iter_mut().find(|(_, login)| {
            matches!(&login.stage, Stage::Confirm { state, browser, .. }
                if state == &form.state && Some(browser.expose_secret()) == browser_cookie(&headers))
        }).ok_or_else(invalid_login)?;
        if login.created.elapsed() >= LOGIN_TIMEOUT {
            return Err(invalid_login());
        }
        let Stage::Confirm { identity, .. } =
            std::mem::replace(&mut login.stage, Stage::Exchanging)
        else {
            unreachable!()
        };
        let key = key.clone();
        drop(pending);
        (key, identity)
    };
    let token = new_session_token(oidc.settings.session_ttl_seconds);
    let result = provision_session(state.database.as_ref(), &identity, &token).await;
    let mut pending = oidc.pending.lock();
    let login = pending.get_mut(&key).ok_or_else(invalid_login)?;
    if result.is_err() {
        login.stage = Stage::Failed;
        tracing::error!("Could not provision OIDC user/session");
        return Err(error(StatusCode::INTERNAL_SERVER_ERROR, "Could not create Atuin session."));
    }
    login.stage = Stage::Complete(token);
    drop(pending);
    Ok((
        [(header::SET_COOKIE, oidc.cookie("", 0))],
        Html(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Atuin \
             login</title><h1>Atuin authorized</h1><p>You can close this page and return to your \
             terminal.</p></html>",
        ),
    )
        .into_response())
}

async fn verify(
    State(state): State<AppState>,
    Query(query): Query<CodeQuery>,
) -> LoginResult<Json<CliVerifyResponse>> {
    let oidc = state.oidc.as_ref().ok_or_else(invalid_login)?;
    let key = digest(&query.code);
    let mut pending = oidc.pending.lock();
    let login = pending.get(&key).ok_or_else(invalid_login)?;
    if login.created.elapsed() >= LOGIN_TIMEOUT {
        pending.remove(&key);
        return Err(invalid_login());
    }
    let response = match &login.stage {
        Stage::Complete(_) => {
            let Some(PendingLogin {
                stage: Stage::Complete(token),
                ..
            }) = pending.remove(&key)
            else {
                unreachable!()
            };
            Ok(Json(CliVerifyResponse {
                token: Some(token),
                success: Some(true),
                error: None,
            }))
        }
        Stage::Failed => {
            pending.remove(&key);
            Ok(Json(CliVerifyResponse {
                token: None,
                success: Some(false),
                error: Some("Login failed. Run atuin login again.".into()),
            }))
        }
        _ => Err(error(StatusCode::UNAUTHORIZED, "Waiting for browser authorization")),
    };
    drop(pending);
    response
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn identity_digest(issuer: &str, subject: &str) -> String {
    // Length framing prevents distinct issuer/subject pairs hashing the same concatenation.
    digest(&format!("{}:{issuer}{subject}", issuer.len()))
}

fn new_session_token(ttl: u32) -> SecretString {
    let expires = if ttl == 0 {
        0
    } else {
        OffsetDateTime::now_utc().unix_timestamp() + i64::from(ttl)
    };
    format!("atapi_{expires}_{}", crypto_random_string::<32>().expose_secret()).into()
}

/// Zero means no expiration. The digest covers this field, so editing it invalidates the token.
fn session_key(token: &str) -> Option<SecretString> {
    let (expires, secret) = token.strip_prefix("atapi_")?.split_once('_')?;
    let expires = expires.parse::<i64>().ok()?;
    if secret.len() != 43 || (expires != 0 && expires <= OffsetDateTime::now_utc().unix_timestamp())
    {
        return None;
    }
    Some(format!("oidc:{}", digest(token)).into())
}

async fn provision_session(
    db: &dyn DynDatabase,
    identity: &str,
    token: &SecretString,
) -> Result<()> {
    // Fit Postgres's existing 32-character username limit. The complete digest is
    // checked in the password marker; a collision or pre-existing account fails closed.
    let username = format!("oidc-{}", &identity[..27]);
    let stored =
        session_key(token.expose_secret()).ok_or_else(|| eyre::eyre!("Expired session"))?;
    let user = match db.get_user(&username).await {
        Ok(user) => user,
        Err(DbError::NotFound) => {
            let new_user = NewUser {
                username: username.parse()?,
                email: format!("{identity}@oidc.invalid"),
                password: HashedPassword::oidc(identity),
            };
            match db.add_user_with_session(&new_user, &stored).await {
                Ok(_) => return Ok(()),
                // A concurrent first login may have inserted this identity already.
                Err(_) => db.get_user(&username).await?,
            }
        }
        Err(err) => return Err(err.into()),
    };
    ensure!(
        user.password.matches_oidc(identity),
        "OIDC identity conflicts with an existing account"
    );
    db.add_session(&NewSession {
        user_id: user.id,
        token: stored,
    })
    .await?;
    Ok(())
}

pub async fn authenticate(db: &dyn DynDatabase, token: &str) -> LoginResult<User> {
    let key = session_key(token)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Invalid or expired session"))?;
    db.get_session_user(&key).await.map_err(|err| match err {
        DbError::NotFound => error(StatusCode::UNAUTHORIZED, "Session not found"),
        DbError::Other(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Could not query session"),
    })
}

#[cfg(test)]
mod tests;
