# Geocaching SDK PHP Demo

A minimal PHP demo showing how to use the [Geocaching PHP SDK](https://github.com/Surfoo/geocaching-php-sdk) with the OAuth2 authorization code flow (PKCE), inspired by [thephpleague](https://github.com/thephpleague/oauth2-client)'s example.

Requires PHP ^8.5.

## Try the demo

    composer install

This also copies `app/config.dist.php` to `app/config.php` (if it doesn't already exist) and installs the Bootstrap CSS/JS assets used by the templates.

Edit `app/config.php` with your OAuth `oauth_key`, `oauth_secret`, `callback_url`, and the active `environment` (`staging` or `production`).

Your callback URL must be authorized by Groundspeak — contact their support to allow-list it (`http://localhost:8000` is a good example for local development).

### Run the server

    php -S 0.0.0.0:8000 -t public

Then open your browser on http://localhost:8000.

## What's in the demo

- `public/index.php` — walks through the OAuth2 + PKCE flow, then uses the SDK's `GeocachingSdk` client (with token-refresh and HTTP-logging plugins) to call `getUser('me', ...)` as an example API request. Feel free to modify it for your own needs.
- `public/monitoring.php` — compares the SDK's methods against the live Geocaching API Swagger spec, showing any endpoints the SDK doesn't cover yet or SDK methods that no longer exist in the API.

## Checks

    composer phpstan       # static analysis (level 5)
    composer php-cs-fixer   # code style (PSR2 + project rules)

There is no test suite.
