<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\GeocachingFactory;
use Geocaching\Exception\GeocachingSdkException;
use League\OAuth2\Client\Provider\Geocaching as GeocachingProvider;
use League\OAuth2\Client\Provider\Exception\GeocachingIdentityProviderException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;

$twig_vars = [];

// OAuth reset
if (isset($_POST['reset'])) {
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', 0);
    }
    session_destroy();
    header('Location: /');
    exit(0);
}

// Create Provider
$provider = new GeocachingProvider([
    'clientId'       => $app[$app['environment']]['oauth_key'],
    'clientSecret'   => $app[$app['environment']]['oauth_secret'],
    'redirectUri'    => $app[$app['environment']]['callback_url'],
    'response_type'  => 'code',
    'scope'          => '*',
    'environment'    => $app['environment'],
]);

// Refresh the OAuth Token
if (isset($_GET['refresh'])) {
    try {
        $accessToken = refreshToken($provider, unserialize($_SESSION['object']));
        $_SESSION['object'] = serialize($accessToken);
    } catch(GeocachingIdentityProviderException $e) {
        $twig_vars['exception'] = [
            'type'    => 'GeocachingIdentityProviderException',
            'message' => $e->getMessage(),
            'code'    => $e->getCode(),
            'trace'   => print_r($e->getTrace(), true),
        ];
    }
}

// Run the OAuth process
if (isset($_POST['oauth'])) {
    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

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
            'message' => $_GET['state'] . ' != ' . $_SESSION['oauth2state']
        ];

        if (isset($_SESSION['oauth2state'])) {
            unset($_SESSION['oauth2state']);
        }
    } else {
        // state is OK, retrive the access token
        try {
            // Try to get an access token using the authorization code grant.
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
            // We have an access token, which we may use in authenticated
            // requests against the service provider's API.
            $_SESSION['accessToken']      = $accessToken->getToken();
            $_SESSION['refreshToken']     = $accessToken->getRefreshToken();
            $_SESSION['expiredTimestamp'] = $accessToken->getExpires();
            $_SESSION['hasExpired']       = $accessToken->hasExpired();
            $_SESSION['object']           = serialize($accessToken);
        } catch (IdentityProviderException $e) {
            // Failed to get the access token or user details.
            $twig_vars['exception'] = [
                'type'    => 'IdentityProviderException',
                'message' => $e->getMessage(),
                'code'    => $e->getCode(),
                'trace'   => print_r($e->getTrace(), true),
            ];
        }
    }

}

if (!empty($_SESSION['accessToken'])) {
    try {
        $accessToken = unserialize($_SESSION['object']);

        $_SESSION['resourceOwner'] = $provider->getResourceOwner($accessToken);

        //Check expiration token, and renew
        if ($accessToken->hasExpired()) {
            try {
                $accessToken = refreshToken($provider, $accessToken);
                $_SESSION['object'] = serialize($accessToken);
            } catch(GeocachingIdentityProviderException $e) {
                echo $e->getMessage();
            }
        }

        $httpDebug = false;
        $geocachingApi = GeocachingFactory::createSdk($_SESSION['accessToken'], $app['environment'],
                                                    [
                                                        'debug'   => $httpDebug,
                                                        'timeout' => 10,
                                                    ]);
        // request the API
        $httpResponse = $geocachingApi->getUser('me', ['fields' => 'referenceCode,username,hideCount,findCount,favoritePoints,membershipLevelId,avatarUrl,bannerUrl,url,homeCoordinates,geocacheLimits']);

        $response['body']    = $httpResponse->getBody();
        $response['headers'] = $httpResponse->getHeaders();
        $response['statusCode'] = sprintf('%d %s', $httpResponse->getStatusCode(), $httpResponse->getReasonPhrase());

        $twig_vars['response'] = $response;
    } catch (\Exception $e) {
        $class = explode('\\', get_class($e));

        $twig_vars['exception'] = [
            'type'    => array_pop($class),
            'message' => $e->getMessage(),
            'code'    => $e->getCode(),
            'trace'   => print_r($e->getTrace(), true),
        ];
    }

    $httpDebugLog = ob_get_clean();
    if ($httpDebug) {
        $twig_vars['http_debug'] = print_r($httpDebugLog, true);
    }
}

$twig_vars['environment'] = $app['environment'];
$twig_vars['session']     = $_SESSION;

echo $twig->render('index.html.twig', $twig_vars);

/**
 * @param League\OAuth2\Client\Provider\Geocaching $provider
 * @param League\OAuth2\Client\Token\AccessToken $existingAccessToken
 */
function refreshToken(GeocachingProvider $provider, AccessToken $existingAccessToken) {

    $accessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $existingAccessToken->getRefreshToken()
    ]);

    $_SESSION['accessToken']      = $accessToken->getToken();
    $_SESSION['refreshToken']     = $accessToken->getRefreshToken();
    $_SESSION['expiredTimestamp'] = $accessToken->getExpires();
    $_SESSION['hasExpired']       = $accessToken->hasExpired();

    return $accessToken;
}