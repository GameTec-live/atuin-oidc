# Atuin with self-hosted OIDC

This fork adds OpenID Connect browser login to the upstream sync server using the
unmodified client's Hub protocol. GitHub Actions publishes server images for
**Linux amd64 and arm64** to `ghcr.io/gametec-live/atuin-oidc:latest` after tests pass.
You do not need Rust or a local image build to run the server.

## Quickstart with Docker Compose

1. Create an OIDC application in your provider. Enable **Authorization Code** and
   **PKCE S256**, allow the `openid` scope, and use `client_secret_basic` for client
   authentication. Register this exact callback:
   `https://atuin.example.com/auth/cli/callback`. Restrict who can access the
   application using your provider's users/groups policy.
2. Create a directory containing `compose.yaml`, `server.toml`, and
   `oidc-client-secret` using the examples below. The secret file contains your
   provider's client secret alone. Replace the example URLs and client ID.
3. Put the server behind your HTTPS reverse proxy, forwarding
   `https://atuin.example.com` to `http://127.0.0.1:8888`. Preserve all paths and query
   strings, and omit `/auth/cli*` query strings from access logs.

`compose.yaml`:

```yaml
services:
  atuin:
    image: ghcr.io/gametec-live/atuin-oidc:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8888:8888"
    volumes:
      - data:/config
      - ./server.toml:/config/server.toml:ro
    secrets:
      - oidc-client-secret
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

secrets:
  oidc-client-secret:
    file: ./oidc-client-secret

volumes:
  data:
```

`server.toml`:

```toml
host = "0.0.0.0"
port = 8888
db_uri = "sqlite:///config/atuin.db"
open_registration = false

[oidc]
# Exact issuer from your provider's discovery document, including any trailing slash.
issuer_url = "https://auth.example.com/realms/home"
client_id = "atuin"
client_secret_file = "/run/secrets/oidc-client-secret"
public_url = "https://atuin.example.com"
session_ttl_seconds = 0 # no expiration (default)
```

If your reverse proxy runs in Docker, connect it to the same Docker network and
route to `http://atuin:8888` instead of
the host's loopback address. The Compose service supports the usual additional
`networks` configuration for your proxy.

Run the server:

```sh
docker compose pull
docker compose up -d
```

The `data` volume persists the SQLite database. Keep it when updating:
`docker compose pull && docker compose up -d`. The same Compose and server settings
are available in [`deploy/`](deploy/) if you prefer cloning this repository.

On each client, set this in `~/.config/atuin/config.toml`:

```toml
sync_address = "https://atuin.example.com"
sync_protocol = "hub"
```

Run `atuin login`, sign in with your provider, approve the terminal, then run
`atuin sync`. Use the same Atuin encryption key on every device. Existing clients
with credentials for another server should run `atuin logout` before logging in.

OIDC mode disables password login and registration. Provider-authorized users are
created automatically, even with `open_registration = false`. Sessions do not
expire by default; set a positive `session_ttl_seconds` to require periodic login.
Run one server process, since pending browser logins are kept in memory.

The `latest` and `oidc` image tags follow successful builds of the `oidc` branch.
Use `sha-<full-commit-sha>` to select a specific fork revision, or pin an image
digest to keep the exact same image. Pull requests build and test images without
publishing. The **OIDC server** workflow can also be run manually to rebuild images.

See [OIDC.md](OIDC.md) for provider options, session revocation, source builds,
deployment details, and the small patch's upstream upgrade procedure.

<p align="center">
 <picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/atuinsh/atuin/assets/53315310/13216a1d-1ac0-4c99-b0eb-d88290fe0efd">
  <img alt="Text changing depending on mode. Light: 'So light!' Dark: 'So dark!'" src="https://github.com/atuinsh/atuin/assets/53315310/08bc86d4-a781-4aaa-8d7e-478ae6bcd129">
</picture>
</p>

<p align="center">
<em>magical shell history</em>
</p>

<hr/>

<p align="center">
  <a href="https://buildkite.com/atuin/atuin"><img src="https://badge.buildkite.com/6213f2ad159947780451bdc7fca76c8a8a0be3d3bca66b8a6d.svg?branch=main" /></a>
  <a href="https://crates.io/crates/atuin"><img src="https://img.shields.io/crates/v/atuin.svg?style=flat-square" /></a>
  <a href="https://crates.io/crates/atuin"><img src="https://img.shields.io/crates/d/atuin.svg?style=flat-square" /></a>
  <a href="https://github.com/atuinsh/atuin/blob/main/LICENSE"><img src="https://img.shields.io/crates/l/atuin.svg?style=flat-square" /></a>
  <a href="https://discord.gg/Fq8bJSKPHh"><img src="https://img.shields.io/discord/954121165239115808" /></a>
  <a rel="me" href="https://hachyderm.io/@atuin"><img src="https://img.shields.io/mastodon/follow/109944632283122560?domain=https%3A%2F%2Fhachyderm.io&style=social"/></a>
  <a href="https://twitter.com/atuinsh"><img src="https://img.shields.io/twitter/follow/atuinsh?style=social" /></a>
</p>

Atuin replaces your existing shell history with a SQLite database, and records
additional context for your commands. Additionally, it provides optional and
_fully encrypted_ synchronisation of your history between machines, via an Atuin
server.

<p align="center">
  <img src="demo.gif" alt="animated" width="80%" />
</p>

<p align="center">
<em>exit code, duration, time and command shown</em>
</p>

As well as the search UI, it can do things like this:

```
# search for all successful `make` commands, recorded after 3pm yesterday
atuin search --exit 0 --after "yesterday 3pm" make
```

You may use either the server I host, or host your own! Or just don't use sync
at all. As all history sync is encrypted, I couldn't access your data even if
I wanted to. And I **really** don't want to.

## Features

- rebind `ctrl-r` and `up` (configurable) to a full screen history search UI
- store shell history in a sqlite database
- back up and sync **encrypted** shell history
- the same history across terminals, across sessions, and across machines
- log exit code, cwd, hostname, session, command duration, etc
- calculate statistics such as "most used command"
- old history file is not replaced
- quick-jump to previous items with <kbd>Alt-\<num\></kbd>
- switch filter modes via ctrl-r; search history just from the current session, directory, or globally
- enter to execute a command, tab to edit

## Documentation

- [Quickstart](#quickstart)
- [Install](https://docs.atuin.sh/latest/guide/installation/)
- [Setting up sync](https://docs.atuin.sh/latest/guide/sync/)
- [Import history](https://docs.atuin.sh/latest/guide/import/)
- [Basic usage](https://docs.atuin.sh/latest/guide/basic-usage/)

## Supported platforms

Atuin supports zsh, bash, fish, nushell, xonsh, and PowerShell. See
[Supported platforms](https://docs.atuin.sh/latest/support/) for the full matrix
and what each tier means.

## Community

### Forum

Atuin has a community forum, please ask here for help and support: <https://forum.atuin.sh/>

### IRC

We're also available via #atuin on libera.chat

### Discord

Atuin also has a community Discord, available [here](https://discord.gg/jR3tfchVvW)

# Quickstart

This will sign you up for the Atuin Cloud sync server. Everything is end-to-end encrypted, so your secrets are safe!

Read the [docs](https://docs.atuin.sh) for an offline setup, self-hosted server, and more.

```
curl --proto '=https' --tlsv1.2 -LsSf https://setup.atuin.sh | sh

atuin register -u <USERNAME> -e <EMAIL>
atuin import auto
atuin sync
```

Then restart your shell!

> [!NOTE]
>
> **For Bash users**: The above sets up `bash-preexec` for necessary hooks, but
> `bash-preexec` has limitations. For details, please see the
> [Bash](https://docs.atuin.sh/latest/guide/installation/#installing-the-shell-plugin)
> section of the shell plugin documentation.


# Related projects
- [Catpuccin for Atuin](https://github.com/catppuccin/atuin)
- [eshell-atuin](https://github.com/SqrtMinusOne/eshell-atuin)
- [mob (tiny creatures in your terminal)](https://github.com/bboynton97/mob)

Please open a PR for any others!

# Contributors

<a href="https://github.com/atuinsh/atuin/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=atuinsh/atuin&max=300" />
</a>

Made with [contrib.rocks](https://contrib.rocks).
