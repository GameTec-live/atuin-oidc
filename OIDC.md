# Self-hosted Atuin with OpenID Connect

This fork adds OAuth 2.0 Authorization Code login with OpenID Connect (OIDC) to the
Atuin sync server. The Atuin client is unchanged. It uses its existing Hub browser
login and bearer authentication, then syncs with the normal server endpoints.
This does not implement other hosted Hub services such as AI or billing.

The upstream base is `b138f6c75c9f5d3d34566c518109b23844240e64` (workspace version
18.24.2). Use an official Atuin client with `sync_protocol = "hub"` support
(introduced in 18.13.0); 18.24.2 is the current compatibility target. Tests exercise
the upstream Hub authentication and sync client libraries directly.

## Configure the identity provider

Create an OIDC application for Atuin:

- Enable Authorization Code flow and PKCE with S256.
- Use a confidential client with `client_secret_basic` authentication. A public
  client with no secret is also supported if the provider allows it.
- Register exactly `https://atuin.example.com/auth/cli/callback` as the redirect URI.
  Wildcards and a client-side localhost callback are unnecessary.
- Allow the `openid` scope. Email and profile scopes are optional; identity comes
  from the signed `iss` and `sub` claims, never email or a changeable username.
- Restrict access to this application using your provider's users/groups policy.

Copy the exact issuer value from the provider's discovery document, including any
trailing slash. The server fetches discovery metadata and signing keys at startup.
OIDC is required: an OAuth-only provider without signed ID tokens needs a separate,
provider-specific identity adapter and is not supported by this small patch.

## Configure the server

Add this to the usual `server.toml`:

```toml
host = "0.0.0.0"
port = 8888
db_uri = "sqlite:///config/atuin.db"
open_registration = false

[oidc]
issuer_url = "https://auth.example.com/realms/home"
client_id = "atuin"
client_secret_file = "/run/secrets/oidc-client-secret"
public_url = "https://atuin.example.com"
session_ttl_seconds = 2592000 # 30 days
```

The secret file contains the client secret alone; a trailing newline is allowed.
Alternatively set `ATUIN_OIDC__CLIENT_SECRET` in the server environment and omit
`client_secret_file`. Do not set both. Omit both for a public client. Scalar settings
support the existing environment syntax, for example `ATUIN_OIDC__ISSUER_URL`,
`ATUIN_OIDC__CLIENT_ID`, and `ATUIN_OIDC__PUBLIC_URL`.

**With `[oidc]` present, verified provider users are provisioned automatically.**
`open_registration` controls upstream password registration only; it does not
restrict OIDC provisioning. Password login, password registration, and password
changes are unavailable in OIDC mode. Removing `[oidc]` restores upstream behavior;
OIDC sessions remain unusable in password mode.

Serve the public URL over HTTPS using a reverse proxy, forwarding all paths to
port 8888. Preserve the path and query string. The public URL is configured
explicitly, so forwarded host headers cannot change OAuth redirects. Configure
proxy/access logs to omit query strings for `/auth/cli*`, which carry login secrets.
The server's own request tracing omits query strings.

For a prefix, set `path = "/atuin"` on the server and use
`public_url = "https://example.com/atuin"`, callback
`https://example.com/atuin/auth/cli/callback`, and that same base URL on the client.

Additional settings under `[oidc]`:

- `scopes = ["profile"]`: optional extra scopes; `openid` is always included.
- `max_pending_logins = 1024`: maximum in-memory handshakes. Expired entries are
  reclaimed when new logins start; handshakes expire after ten minutes.
- `allow_http = true`: permits HTTP for local development. Defaults to false;
  production requires HTTPS for the public, issuer, and provider endpoint URLs.

## Run the server

Build directly with upstream's pinned Rust toolchain:

```sh
cargo build --locked --release -p atuin-server
ATUIN_CONFIG_DIR=/path/to/config target/release/atuin-server start
```

Or use the supplied Docker Compose deployment:

```sh
cp deploy/server.toml.example deploy/server.toml
# Edit deploy/server.toml; create deploy/oidc-client-secret privately.
docker compose -f deploy/compose.yaml up -d --build
```

The Compose deployment uses SQLite in a named volume and publishes port 8888 on
loopback for a local reverse proxy. `Dockerfile.oidc` builds only the server into a
`scratch` image containing its static binary and CA certificates, running as UID
65532. The original upstream Dockerfile is unchanged. PostgreSQL and MySQL remain
available through upstream's `db_uri` setting; the integration uses its existing
database abstraction and adds no migrations.

## Configure the unmodified client

In `~/.config/atuin/config.toml`:

```toml
sync_address = "https://atuin.example.com"
sync_protocol = "hub"
```

Then run:

```sh
atuin login
atuin sync
```

The CLI displays a URL and tries to open it. On a remote/headless machine, open
that URL on a different device. Sign in with your provider and choose **Authorize
this terminal**. The CLI retrieves its token by polling; no local callback port
or client changes are needed. Keep your Atuin encryption key and use the same key
on every device, as with upstream sync. The identity provider does not receive it.

If the CLI already has credentials for another server, run `atuin logout` before
switching. Do the same when a session expires, then run `atuin login` again.
Username/password flags and `atuin account link` are not OIDC migration mechanisms.
The fork does not automatically merge existing password accounts or their data.

## Identity, sessions, and operations

Each exact `(issuer, subject)` pair maps to an opaque `oidc-...` username. The name
uses 27 hex digits of SHA-256 to fit upstream PostgreSQL's 32-character limit; the
full identity digest is checked in a non-password marker in the existing password
field. An existing password account or a digest-prefix collision fails closed.
The email column contains a unique synthetic `@oidc.invalid` address. Neither
claim changes nor an unverified email can link a user to someone else's history.
Changing the issuer or the provider's subject assignment creates a new account.
Do not run `admin user set-password` on OIDC accounts: it replaces their identity
marker and prevents subsequent OIDC login.

Atuin sessions are local, random bearer credentials beginning with `atapi_`.
Only SHA-256 digests are stored in the existing session table. Expiration is bound
to that digest, so changing a token's expiration invalidates it. Provider tokens
are discarded after ID-token validation; the server neither stores refresh tokens
nor sends provider access tokens to the CLI. Sessions survive server restarts and
work while the provider is unavailable, until they expire.

Disabling a provider account prevents new logins, but does not revoke existing
Atuin sessions. Choose a shorter `session_ttl_seconds` if needed. To revoke all
devices for one account immediately, execute this against the Atuin database:

```sql
DELETE FROM sessions
WHERE user_id = (SELECT id FROM users WHERE username = 'oidc-REPLACE_WITH_USERNAME');
```

CLI logout removes local credentials. Session rows are retained until operator
cleanup or account deletion; expired tokens cannot authenticate. Account deletion
through the CLI deletes the local Atuin account and records, not the provider
account. As in the upstream server, possession of an Atuin session authorizes
account deletion; the Hub client's password prompt is not checked against the IdP.

Use **one server process**. Pending login state is bounded and in memory; a restart
cancels pending logins. Horizontal replicas or rolling restarts during login need
shared handshake storage, deliberately outside this patch. Discovery/JWKS are
loaded at startup; restart after provider key rotation to load new signing keys.
The provider must be reachable at startup. Back up the normal Atuin database and
configuration; no extra auth database or server signing key exists.

## Maintain the fork

The implementation is in `crates/atuin-server/src/oidc.rs`, with its focused tests
in `src/oidc/tests.rs`. Existing code changes are limited to server dependencies,
optional settings, startup/router wiring, the non-password identity marker, and
`oidc: None` in existing test fixtures. Client code, sync handlers, database queries,
existing migrations, and upstream's Dockerfile are unchanged.

The maintained branch is `oidc`; `upstream/main` tracks the original repository.
To move the patch onto a new upstream revision:

```sh
git fetch upstream --tags
git switch oidc
git rebase --onto <new-upstream-tag-or-commit> b138f6c75c9f5d3d34566c518109b23844240e64
```

Alternatively export just the fork commit with `git format-patch` and apply it to
a fresh upstream checkout using `git am -3`. Reconcile the router/startup/settings
integration if upstream changes those interfaces, and update the base revision
recorded here. Do not squash upstream database migrations into the patch.

Verify an update with:

```sh
cargo test --locked -p atuin-server --lib
cargo test --locked -p atuin-server --test sync
cargo clippy --locked -p atuin-server --all-targets -- -D warnings
cargo +nightly fmt -p atuin-server --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked -p atuin-server --no-deps --document-private-items
docker build -f Dockerfile.oidc -t atuin-oidc:local .
```

The OIDC tests use a local discovery/JWKS/token provider with signed ID tokens,
check PKCE at token exchange, and exercise the unmodified Hub login and bearer sync
clients. They cover account isolation, repeated login, URL prefixes, invalid
issuer/audience/signature/nonce/expiry/access-token hashes, consent and CSRF,
single-use polling, capacity/timeout, and collisions with existing accounts.
The existing SQLite sync suite checks the normal server mode. Provider-specific
policy and a real deployment's TLS/reverse proxy should also be checked when
connecting your identity provider.
