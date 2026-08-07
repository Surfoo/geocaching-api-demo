# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal PHP demo app showing how to use the `surfoo/geocaching-php-sdk` (v4) with OAuth2 v3 against the Geocaching API. It's not a framework app — no routing, no DI container, just two plain PHP entry points under `public/` bootstrapped by `app/app.php`.

## Setup and running

```bash
composer install                    # also copies app/config.dist.php -> app/config.php and vendors bootstrap CSS/JS assets
php -S 0.0.0.0:8000 -t public        # dev server, then open http://localhost:8000
```

`app/config.php` (gitignored, copied from `config.dist.php` on install) holds OAuth `oauth_key`/`oauth_secret`/`callback_url` per environment (`staging`/`production`) and the active `environment`. The callback URL must be allow-listed by Groundspeak.

## Checks

```bash
composer phpstan       # vendor/bin/phpstan analyse (level 5, scans app/ and public/)
composer php-cs-fixer  # php-cs-fixer fix (PSR2 + project rules, scans app/ and public/)
```

There is no test suite.

## Architecture

- `app/app.php` — shared bootstrap: requires `config.php`, sets up Twig (loader from `templates/`, debug mode auto-enabled when `SERVER_NAME == 'localhost'`), registers a `print_r` Twig filter. Included by both entry points via `require dirname(__DIR__) . '/app/app.php'`.
- `public/index.php` — the actual OAuth2 + SDK demo, in one linear script:
  1. Handles `POST reset` (destroys session).
  2. Handles `POST oauth` (builds the League `Geocaching` provider, redirects to the authorization URL, stashes `oauth2state`/`oauth2pkceCode` in `$_SESSION`).
  3. Handles the OAuth callback (validates `state`, exchanges the code for a token via PKCE, fetches the resource owner to capture `referenceCode`, stores everything in `$_SESSION`).
  4. If a session token exists, builds a `GeocachingSdk` client (via `ClientBuilder`) with two plugins — `TokenRefreshPlugin` (auto-refresh using `SessionTokenStorage`) and `GeocachingHttpLoggerPlugin` (in-memory HTTP request/response logging, token-masked, toggled by the `HTTP_DEBUG` constant) — then calls `getUser('me', ...)` as the example API call.
  5. Renders `templates/index.html.twig` with the response/exception/http-debug data.
- `public/monitoring.php` — a drift-detection page: downloads (and file-caches for `SWAGGER_TTL` seconds) the Geocaching API's Swagger spec, extracts `METHOD /path` pairs from it, reflects over `Geocaching\GeocachingSdk`'s public methods to extract the same pairs from their docblocks (`GET /v1/...` etc.), normalizes away version prefixes (`/v1`, `/v{api-version}`), and renders `templates/monitoring.html.twig` with the two-way diff — i.e. which API endpoints the SDK is missing, and which SDK methods no longer exist in the API.
- `src/SessionTokenStorage.php` — implements the SDK's `TokenStorageInterface` using `$_SESSION['token']` as the backing store, with an in-memory (non-persistent, single-request) lock map. Explicitly a demo-only stand-in; the class docblock notes production should use a durable store with real locking.

Both entry points are self-contained scripts, not part of a class hierarchy — when modifying request handling, edit the relevant `public/*.php` file directly rather than looking for a router or controller layer.
