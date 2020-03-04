<?php

$app['staging'] = [
    'oauth_key'    => '',
    'oauth_secret' => '',
    'callback_url' => 'http://localhost:8000',
];

// 'staging' or 'production'
$app['environment'] = 'staging';

define('ROOT', dirname(__DIR__));

define('WEB_DIRECTORY', '/');

define('SWAGGER_PATH', 'cache/swagger.json');
define('URI_SWAGGER_FILE', 'https://staging.api.groundspeak.com/api-docs/v1/swagger');
define('SWAGGER_TTL', 3600 * 24);
