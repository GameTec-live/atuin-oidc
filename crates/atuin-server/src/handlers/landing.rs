use axum::http::{HeaderMap, header};
use axum::response::Html;

use crate::Settings;

/// Browsers request HTML explicitly; clients without that preference keep the root JSON API.
pub fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|media| {
            let mut parts = media.split(';').map(str::trim);
            parts.next().is_some_and(|name| name.eq_ignore_ascii_case("text/html"))
                && parts.filter_map(|part| part.split_once('=')).all(|(name, value)| {
                    name.trim() != "q"
                        || value
                            .trim()
                            .parse::<f32>()
                            .is_ok_and(|quality| quality > 0.0 && quality <= 1.0)
                })
        })
}

pub fn page(settings: &Settings) -> Html<String> {
    let (address, protocol, login) = match &settings.oidc {
        Some(oidc) => (
            oidc.public_url.as_str().trim_end_matches('/'),
            "hub",
            "Your browser will open your identity provider. Sign in and authorize this terminal.",
        ),
        None => (
            "https://your-atuin-server.example",
            "legacy",
            "Use the username and password provided by this server's operator.",
        ),
    };
    let config = format!("sync_address = {address:?}\nsync_protocol = {protocol:?}");
    let config = config.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    Html(include_str!("landing.html").replace("{{LOGIN}}", login).replace("{{CONFIG}}", &config))
}
