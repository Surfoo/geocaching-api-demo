# Geocaching SDK PHP Demo

## Try the demo

    composer install

Edit the file `app/config.php` with your OAuth keys, callback URL and environment (`staging` or `production`)

Your callback URL must be authorized by Groundspeak, you need to contact the support (`http://localhot:8000` is a good example for your development).

### Run the server

    php -S 0.0.0.0:8000 -t public

Run the command above and open your browser on http://localhost:8000

The code written `index.php` is an example of implementation of the OAuth process (inspired by the example of [thephpleague](https://github.com/thephpleague/oauth2-client)) and the SDK for the [Geocaching API](https://github.com/Surfoo/geocaching-php-sdk), feel free to modify it for your needs.