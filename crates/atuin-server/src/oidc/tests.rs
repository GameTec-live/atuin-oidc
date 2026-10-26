use std::sync::Arc;

use atuin_client::api_client::{self, AuthToken};
use atuin_client::hub::{HubAuthSession, HubAuthStatus};
use atuin_domain::record::{
    EncryptedData, Host, HostId, Record, RecordId, RecordSeriesKey, RecordTag,
};
use chrono::{TimeDelta, Utc};
use openidconnect::core::{
    CoreEdDsaPrivateSigningKey, CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, PrivateSigningKey, StandardClaims,
    SubjectIdentifier,
};
use rstest::{fixture, rstest};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use wiremock::matchers::{basic_auth, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::db::{Database, DbSettings, Sqlite};
use crate::settings::{Metrics, Settings};

// Test-only Ed25519 keys; these never protect real data.
const SIGNING_KEY: &str =
    "-----BEGIN PRIVATE \
     KEY-----\nMC4CAQAwBQYDK2VwBCIEIDmESZLf0kOzpO0Dt0jTHUO9bHbAcSiML5K3emmNh24J\n-----END PRIVATE \
     KEY-----";
const OTHER_KEY: &str = "-----BEGIN PRIVATE \
                         KEY-----\nMC4CAQAwBQYDK2VwBCIEIHxOWkdL3zZc/DP+evUcTAW7LH/\
                         cBJMtasezFo2aDFA1\n-----END PRIVATE KEY-----";

fn signing_key(pem: &str) -> CoreEdDsaPrivateSigningKey {
    CoreEdDsaPrivateSigningKey::from_ed25519_pem(pem, None).unwrap()
}

struct Environment {
    provider: MockServer,
    database: Arc<dyn DynDatabase>,
    oidc: Arc<Oidc>,
    address: Url,
    browser: reqwest::Client,
    server: JoinHandle<()>,
}

impl Drop for Environment {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Environment {
    async fn new(prefix: &str, session_ttl_seconds: u32) -> Self {
        let provider = MockServer::start().await;
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": provider.uri(),
                "authorization_endpoint": format!("{}/authorize", provider.uri()),
                "token_endpoint": format!("{}/token", provider.uri()),
                "jwks_uri": format!("{}/jwks", provider.uri()),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["EdDSA"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"]
            })))
            .mount(&provider)
            .await;
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "keys": [signing_key(SIGNING_KEY).as_verification_key()]
            })))
            .mount(&provider)
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: Url =
            format!("http://{}{prefix}", listener.local_addr().unwrap()).parse().unwrap();
        let config = OidcSettings {
            issuer_url: IssuerUrl::new(provider.uri()).unwrap(),
            public_url: address.clone(),
            client_id: "test-client".into(),
            client_secret: Some("test-secret".into()),
            client_secret_file: None,
            scopes: vec!["profile".into()],
            session_ttl_seconds,
            max_pending_logins: 8,
            allow_http: true,
        };
        let oidc = Arc::new(Oidc::discover(&config, prefix).await.unwrap());
        let database: Arc<dyn DynDatabase> = Arc::new(
            Sqlite::connect(atuin_common::db::SqliteDbUrl("sqlite::memory:".into())).await.unwrap(),
        );
        let settings = Settings {
            host: "127.0.0.1".into(),
            port: 0,
            path: prefix.into(),
            // Even open_registration cannot enable password auth in OIDC mode.
            open_registration: true,
            oidc: Some(config),
            max_record_size: atuin_common::units::ByteSize::mib(1),
            register_webhook_url: None,
            register_webhook_username: String::new(),
            metrics: Metrics::default(),
            fake_version: None,
            db_settings: DbSettings {
                db_uri: "sqlite::memory:".parse().unwrap(),
                db_password_file: None,
            },
        };
        let router = crate::router::router(database.clone(), settings, Some(oidc.clone()));
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let browser =
            reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        Self {
            provider,
            database,
            oidc,
            address,
            browser,
            server,
        }
    }

    async fn begin(&self) -> BrowserLogin {
        let session = HubAuthSession::start(&self.address).await.unwrap();
        assert!(matches!(session.poll().await.unwrap(), HubAuthStatus::Pending));
        let response = self.browser.get(session.auth_url.clone()).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let params: HashMap<_, _> = Url::parse(location)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(params["client_id"], "test-client");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["redirect_uri"],
            self.address.append_path("auth/cli/callback").unwrap().as_str()
        );
        assert!(params["scope"].split(' ').any(|s| s == "openid"));
        BrowserLogin {
            session,
            cookie,
            state: params["state"].clone(),
            nonce: params["nonce"].clone(),
            challenge: params["code_challenge"].clone(),
        }
    }

    async fn tokens(&self, flow: &BrowserLogin, subject: &str, fault: TokenFault) {
        let now = Utc::now();
        let issuer = if matches!(fault, TokenFault::Issuer) {
            "https://wrong.example".to_owned()
        } else {
            self.provider.uri()
        };
        let audience = if matches!(fault, TokenFault::Audience) {
            "wrong-client"
        } else {
            "test-client"
        };
        let nonce = if matches!(fault, TokenFault::Nonce) {
            "wrong-nonce"
        } else {
            &flow.nonce
        };
        let expiry = if matches!(fault, TokenFault::Expired) {
            now - TimeDelta::hours(1)
        } else {
            now + TimeDelta::minutes(5)
        };
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(issuer).unwrap(),
            vec![Audience::new(audience.into())],
            expiry,
            now,
            StandardClaims::new(SubjectIdentifier::new(subject.into())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(nonce.to_owned())));
        let pem = if matches!(fault, TokenFault::Signature) {
            OTHER_KEY
        } else {
            SIGNING_KEY
        };
        let token = CoreIdToken::new(
            claims,
            &signing_key(pem),
            CoreJwsSigningAlgorithm::EdDsa,
            Some(&AccessToken::new("provider-token".into())),
            None,
        )
        .unwrap();
        let access_token = if matches!(fault, TokenFault::AccessTokenHash) {
            "substituted-token"
        } else {
            "provider-token"
        };
        let body = if matches!(fault, TokenFault::Missing) {
            json!({"access_token": access_token, "token_type": "Bearer"})
        } else {
            json!({"access_token": access_token, "token_type": "Bearer", "id_token": token.to_string()})
        };
        let challenge = flow.challenge.clone();
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(basic_auth("test-client", "test-secret"))
            .and(move |request: &wiremock::Request| {
                let params: HashMap<_, _> = url::form_urlencoded::parse(&request.body).collect();
                params.get("grant_type").is_some_and(|value| value == "authorization_code")
                    && params.get("code").is_some_and(|value| value == "provider-code")
                    && params.get("code_verifier").is_some_and(|value| {
                        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
                            value.to_string(),
                        ))
                        .as_str()
                            == challenge
                    })
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .up_to_n_times(1)
            .mount(&self.provider)
            .await;
    }

    async fn callback(&self, flow: &BrowserLogin) -> reqwest::Response {
        self.browser
            .get(self.address.append_path("auth/cli/callback").unwrap())
            .query(&[("state", flow.state.as_str()), ("code", "provider-code")])
            .header(header::COOKIE, &flow.cookie)
            .send()
            .await
            .unwrap()
    }

    async fn approve(&self, flow: &BrowserLogin, approval: &str) -> reqwest::Response {
        self.browser
            .post(self.address.append_path("auth/cli/approve").unwrap())
            .header(header::COOKIE, &flow.cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("state={approval}"))
            .send()
            .await
            .unwrap()
    }

    async fn login(&self, subject: &str) -> SecretString {
        let flow = self.begin().await;
        self.tokens(&flow, subject, TokenFault::None).await;
        let response = self.callback(&flow).await;
        assert_eq!(response.status(), StatusCode::OK);
        let approval = approval_state(&response.text().await.unwrap());
        assert!(matches!(flow.session.poll().await.unwrap(), HubAuthStatus::Pending));
        assert_eq!(self.approve(&flow, &approval).await.status(), StatusCode::OK);
        let HubAuthStatus::Complete(token) = flow.session.poll().await.unwrap() else {
            panic!("expected token")
        };
        token
    }

    fn client(&self, token: SecretString) -> api_client::Client {
        api_client::Client::new(
            self.address.clone(),
            &AuthToken::Bearer(token),
            Duration::from_secs(2),
            Duration::from_secs(5),
            &HashMap::new(),
            api_client::caps_client_anonymous(&self.address, &HashMap::new()).unwrap(),
        )
        .unwrap()
    }
}

struct BrowserLogin {
    session: HubAuthSession,
    cookie: String,
    state: String,
    nonce: String,
    challenge: String,
}

#[derive(Clone, Copy, Debug)]
enum TokenFault {
    None,
    Issuer,
    Audience,
    Nonce,
    Expired,
    Signature,
    AccessTokenHash,
    Missing,
}

fn approval_state(html: &str) -> String {
    html.split("name=\"state\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_owned()
}

#[fixture]
async fn environment() -> Environment {
    Environment::new("", 0).await
}

#[rstest]
#[case("")]
#[case("/atuin")]
#[tokio::test]
async fn unmodified_hub_client_logs_in_and_syncs_with_isolated_accounts(
    #[case] prefix: &str,
    #[values(0, 3600)] session_ttl_seconds: u32,
) {
    let env = Environment::new(prefix, session_ttl_seconds).await;
    let alice = env.login("alice").await;
    let key = session_key(alice.expose_secret()).unwrap();
    assert!(!key.expose_secret().contains(alice.expose_secret()));
    let user = env.database.get_session_user(&key).await.unwrap();
    assert!(user.password.matches_oidc(&identity_digest(&env.provider.uri(), "alice")));
    assert!(!user.password.verify("test-secret".into()).await);
    let first = env.client(alice.clone());
    assert_eq!(first.me().await.unwrap().username, user.username);
    let record = Record {
        id: RecordId(uuid::Uuid::now_v7()),
        host: Host::new(HostId(uuid::Uuid::now_v7())),
        idx: 0,
        timestamp: 1,
        version: "v1".into(),
        tag: RecordTag::Other("test".into()),
        data: EncryptedData {
            raw: "encrypted history".into(),
            cek: "encrypted key".into(),
        },
    };
    let series = RecordSeriesKey::new(record.host.id, record.tag.clone());
    let record_id = record.id;
    first.post_records(&[record]).await.unwrap();
    assert!(!first.record_status().await.unwrap().hosts.is_empty());
    // A second device resolves to the same account; a different subject cannot see its records.
    let second = env.client(env.login("alice").await);
    assert_eq!(second.me().await.unwrap().username, user.username);
    assert!(!second.record_status().await.unwrap().hosts.is_empty());
    let downloaded = second.records(&series).one().await.unwrap().unwrap();
    assert_eq!(downloaded.id, record_id);
    assert_eq!(downloaded.data.raw, "encrypted history");
    let other = env.client(env.login("bob").await);
    assert_ne!(other.me().await.unwrap().username, user.username);
    assert!(other.record_status().await.unwrap().hosts.is_empty());
    assert!(other.records(&series).one().await.unwrap().is_none());
    second.delete_store().await.unwrap();
    assert!(first.record_status().await.unwrap().hosts.is_empty());
    other.delete().await.unwrap();
    assert!(other.me().await.is_err());
    // Existing bearer sessions do not depend on the provider being available.
    env.provider.reset().await;
    assert!(first.me().await.is_ok());
}

#[rstest]
#[case(TokenFault::Issuer)]
#[case(TokenFault::Audience)]
#[case(TokenFault::Nonce)]
#[case(TokenFault::Expired)]
#[case(TokenFault::Signature)]
#[case(TokenFault::AccessTokenHash)]
#[case(TokenFault::Missing)]
#[tokio::test]
async fn invalid_provider_tokens_cannot_create_a_session(
    #[future(awt)] environment: Environment,
    #[case] fault: TokenFault,
) {
    let flow = environment.begin().await;
    environment.tokens(&flow, "alice", fault).await;
    assert_eq!(environment.callback(&flow).await.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(flow.session.poll().await.unwrap(), HubAuthStatus::Failed(_)));
    let name = format!("oidc-{}", &identity_digest(&environment.provider.uri(), "alice")[..27]);
    assert!(matches!(environment.database.get_user(&name).await, Err(DbError::NotFound)));
}

#[rstest]
#[tokio::test]
async fn state_cookie_consent_and_one_time_redemption_are_required(
    #[future(awt)] environment: Environment,
) {
    let env = &environment;
    let mut flow = env.begin().await;
    env.tokens(&flow, "alice", TokenFault::None).await;
    let state = std::mem::replace(&mut flow.state, "wrong-state".into());
    assert_eq!(env.callback(&flow).await.status(), StatusCode::BAD_REQUEST);
    flow.state = state;
    let cookie = std::mem::replace(&mut flow.cookie, "atuin_oidc=wrong-browser".into());
    assert_eq!(env.callback(&flow).await.status(), StatusCode::BAD_REQUEST);
    flow.cookie = cookie;
    let response = env.callback(&flow).await;
    assert_eq!(response.status(), StatusCode::OK);
    let approval = approval_state(&response.text().await.unwrap());
    assert_eq!(env.callback(&flow).await.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(flow.session.poll().await.unwrap(), HubAuthStatus::Pending));
    assert_eq!(env.approve(&flow, "wrong-state").await.status(), StatusCode::BAD_REQUEST);
    let cookie = std::mem::replace(&mut flow.cookie, "atuin_oidc=wrong-browser".into());
    assert_eq!(env.approve(&flow, &approval).await.status(), StatusCode::BAD_REQUEST);
    flow.cookie = cookie;
    assert_eq!(env.approve(&flow, &approval).await.status(), StatusCode::OK);
    assert_eq!(env.approve(&flow, &approval).await.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(flow.session.poll().await.unwrap(), HubAuthStatus::Complete(_)));
    let response = env
        .browser
        .post(env.address.append_path("auth/cli/verify").unwrap())
        .query(&[("code", flow.session.code.expose_secret())])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[tokio::test]
async fn pending_logins_expire_and_have_a_capacity_limit(#[future(awt)] environment: Environment) {
    let env = &environment;
    let first = HubAuthSession::start(&env.address).await.unwrap();
    for _ in 1..env.oidc.settings.max_pending_logins {
        HubAuthSession::start(&env.address).await.unwrap();
    }
    assert!(HubAuthSession::start(&env.address).await.is_err());
    env.oidc.pending.lock().get_mut(&digest(first.code.expose_secret())).unwrap().created =
        Instant::now() - LOGIN_TIMEOUT;
    assert_eq!(
        env.browser.get(first.auth_url).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(HubAuthSession::start(&env.address).await.is_ok());
}

#[rstest]
#[case("/login", "POST")]
#[case("/register", "POST")]
#[case("/account/password", "PATCH")]
#[case("/api/v0/login", "POST")]
#[case("/api/v0/register", "POST")]
#[tokio::test]
async fn oidc_mode_does_not_expose_password_auth(
    #[future(awt)] environment: Environment,
    #[case] endpoint: &str,
    #[case] verb: &str,
) {
    let response = environment
        .browser
        .request(
            verb.parse().unwrap(),
            format!("{}{endpoint}", environment.address.as_str().trim_end_matches('/')),
        )
        .json(&json!({"username": "alice", "password": "password", "email": "a@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[rstest]
#[tokio::test]
async fn session_hashes_expiry_and_auth_schemes_are_enforced(
    #[values(0, 3600)] session_ttl_seconds: u32,
) {
    let environment = Environment::new("", session_ttl_seconds).await;
    let env = &environment;
    let token = env.login("alice").await;
    let stored = session_key(token.expose_secret()).unwrap();
    let user = env.database.get_session_user(&stored).await.unwrap();
    let expired = format!("atapi_1_{}", crypto_random_string::<32>().expose_secret());
    // Even an expired token present in the database cannot authenticate.
    env.database
        .add_session(&NewSession {
            user_id: user.id,
            token: format!("oidc:{}", digest(&expired)).into(),
        })
        .await
        .unwrap();
    let (_, secret) =
        token.expose_secret().strip_prefix("atapi_").unwrap().split_once('_').unwrap();
    // Neither removing an expiration nor adding one can preserve the token's stored digest.
    let tampered_expiry = if session_ttl_seconds == 0 {
        OffsetDateTime::now_utc().unix_timestamp() + 3600
    } else {
        0
    };
    let tampered = format!("atapi_{tampered_expiry}_{secret}");
    for header in [
        format!("Token {}", token.expose_secret()),
        format!("Bearer {}", stored.expose_secret()),
        format!("Bearer {expired}"),
        format!("Bearer {tampered}"),
    ] {
        assert_eq!(
            env.browser
                .get(env.address.append_path("api/v0/me").unwrap())
                .header(header::AUTHORIZATION, header)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(env.database.get_session_user(&token).await.is_err());
    assert!(env.client(token).me().await.is_ok());
}

#[rstest]
#[tokio::test]
async fn a_preexisting_account_cannot_be_claimed_by_oidc(#[future(awt)] environment: Environment) {
    let env = &environment;
    let identity = identity_digest(&env.provider.uri(), "alice");
    env.database
        .add_user(&NewUser {
            username: format!("oidc-{}", &identity[..27]).parse().unwrap(),
            email: format!("{identity}@oidc.invalid"),
            password: HashedPassword::new("password".into()).await,
        })
        .await
        .unwrap();
    let flow = env.begin().await;
    env.tokens(&flow, "alice", TokenFault::None).await;
    let response = env.callback(&flow).await;
    let approval = approval_state(&response.text().await.unwrap());
    assert_eq!(env.approve(&flow, &approval).await.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(matches!(flow.session.poll().await.unwrap(), HubAuthStatus::Failed(_)));
}

#[rstest]
#[case("https://a.example", "bc", "https://a.exampleb", "c")]
#[case("https://issuer.example", "Alice", "https://issuer.example", "alice")]
#[case("https://first.example", "alice", "https://second.example", "alice")]
fn identity_mapping_separates_issuer_and_subject(
    #[case] issuer: &str,
    #[case] subject: &str,
    #[case] other_issuer: &str,
    #[case] other_subject: &str,
) {
    assert_ne!(identity_digest(issuer, subject), identity_digest(other_issuer, other_subject));
}
