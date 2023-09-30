<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\ClientBuilder;
use Geocaching\Enum\Environment;
use Geocaching\GeocachingSdk;
use Geocaching\Options;
use League\OAuth2\Client\Provider\Exception\GeocachingIdentityProviderException;
use League\OAuth2\Client\Provider\Geocaching as GeocachingProvider;

// Display HTTP logs from Guzzle
define('HTTP_DEBUG', false);

session_start();

$twig_vars = [];

// OAuth reset
if (isset($_POST['reset'])) {
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', 0);
    }
    session_destroy();
    header('Location: ' . WEB_DIRECTORY);
    exit(0);
}

// Create Provider
$provider = new GeocachingProvider([
    'clientId'      => $app[$app['environment']]['oauth_key'],
    'clientSecret'  => $app[$app['environment']]['oauth_secret'],
    'redirectUri'   => $app[$app['environment']]['callback_url'],
    'environment'   => $app['environment'],
]);

// Refresh the OAuth Token
if (isset($_GET['refresh'])) {
    try {
        $_SESSION['token'] = $provider->getAccessToken('refresh_token', [
            'refresh_token' => $_SESSION['token']->getRefreshToken(),
        ]);
    } catch (GeocachingIdentityProviderException $e) {
        $twig_vars['exception'] = [
            'type'    => 'GeocachingIdentityProviderException',
            'message' => $e->getMessage(),
            'code'    => $e->getCode(),
            'trace'   => print_r($e->getTrace(), true),
        ];
    }

    header('Location: ' . WEB_DIRECTORY);
    exit(0);
}

// Run the OAuth process
if (isset($_POST['oauth'])) {
    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();
    $_SESSION['oauth2pkceCode'] = $provider->getPkceCode();
    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit(0);
}

// Return to the callback URL after the user gave the permission
if (isset($_SESSION['oauth2state'])) {
    // Check given state against previously stored one to mitigate CSRF attack
    if (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
        $twig_vars['exception'] = [
            'type'    => 'Invalid State',
            'message' => $_GET['state'] . ' != ' . $_SESSION['oauth2state'],
        ];
    } else {
        // state is OK, retrive the access token
        try {
            if (!isset($_GET['code'])) {
                throw new GeocachingIdentityProviderException(sprintf(
                    'error: %s, error_error_description: %s',
                    $_GET['error'],
                    $_GET['error_description']
                ), 0, $_GET);
            }

            $provider->setPkceCode($_SESSION['oauth2pkceCode']);

            // Try to get an access token using the authorization code grant.
            $accessToken = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

            // We have an access token, which we may use in authenticated
            // requests against the service provider's API.
            $_SESSION['token'] = $accessToken;
        } catch (\Throwable $e) {
            // Failed to get the access token or user details.
            $class = explode('\\', get_class($e));

            $twig_vars['exception'] = [
                'type'    => array_pop($class),
                'message' => $e->getMessage(),
                'code'    => $e->getCode(),
                'trace'   => print_r($e->getTrace(), true),
            ];
        }
    }
    unset($_SESSION['oauth2state']);

    header('Location: ' . WEB_DIRECTORY);
    exit(0);
}

if (!empty($_SESSION['token'])) {
    try {
        $_SESSION['resourceOwner'] = $provider->getResourceOwner($_SESSION['token']);

        // Check expiration token, and renew if needed
        if ($_SESSION['token']->hasExpired()) {
            try {
                $_SESSION['token'] = $provider->getAccessToken('refresh_token', [
                    'refresh_token' => $_SESSION['token']->getRefreshToken(),
                ]);
            } catch (GeocachingIdentityProviderException $e) {
                $twig_vars['exception'] = [
                    'type'    => "GeocachingIdentityProviderException",
                    'message' => $e->getMessage(),
                    'code'    => $e->getCode(),
                    'trace'   => print_r($e->getTrace(), true),
                ];
            }
        }

        $clientBuilder = new ClientBuilder();
        $options = new Options([
            'access_token'   => $_SESSION['token']->getToken(),
            'environment'    => Environment::from($app['environment']),
            'client_builder' => $clientBuilder,
        ]);

        $geocachingApi = new GeocachingSdk($options);

        // request the API with getUser method
        $httpResponse = $geocachingApi->getUser(
            'me',
            ['fields' => 'username,referenceCode,joinedDateUtc,favoritePoints,' .
                         'membershipLevelId,avatarUrl,bannerUrl,url,homeCoordinates,' .
                         'hideCount,findCount,geocacheLimits',
            ]
        );

        $response['body']       = json_decode(json:(string) $httpResponse->getBody(), associative:true, flags:JSON_PRETTY_PRINT);
        $response['headers']    = $httpResponse->getHeaders();
        $response['statusCode'] = sprintf('%d %s', $httpResponse->getStatusCode(), $httpResponse->getReasonPhrase());

        $twig_vars['response'] = $response;
    } catch (\Throwable $e) {
        $class       = explode('\\', get_class($e));
        $jsonContent = json_decode($e->getResponseBody());

        $twig_vars['exception'] = [
            'type'         => array_pop($class),
            'message'      => $e->getMessage(),
            'errorMessage' => $jsonContent->errorMessage,
            'code'         => $e->getCode(),
            'trace'        => print_r($e->getTrace(), true),
        ];
    }

    $httpDebugLog = ob_get_clean();
    if (HTTP_DEBUG) {
        $twig_vars['http_debug'] = print_r($httpDebugLog, true);
    }
}

$twig_vars['environment'] = $app['environment'];
$twig_vars['session']     = $_SESSION;

echo $twig->render('index.html.twig', $twig_vars);
