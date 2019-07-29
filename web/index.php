<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\Exception\GeocachingSdkException;
use Geocaching\GeocachingFactory;
use Geocaching\Lib\Utils\Utils;
use League\OAuth2\Client\Provider\Exception\GeocachingIdentityProviderException;
use League\OAuth2\Client\Provider\Geocaching as GeocachingProvider;
use League\OAuth2\Client\Token\AccessToken;

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
        $_SESSION['token'] = $provider->getAccessToken('refresh_token', [
            'refresh_token' => $_SESSION['token']->getRefreshToken()
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
    $pkce = [];
    $_SESSION['codeVerifier'] = $_SESSION['codeChallenge'] = $_SESSION['pkce'] = '';

    if (isset($_POST['pkce'])) {
        switch ($_POST['pkce']) {
            case "plain":
                $_SESSION['codeVerifier'] = $_SESSION['codeChallenge'] = Utils::createCodeVerifier();
                $_SESSION['pkce']         = "plain";
                $pkce = ['code_challenge'        => $_SESSION['codeChallenge'],
                         'code_challenge_method' => "plain",
                    ];
                break;
            case "S256":
                $_SESSION['codeVerifier']  = Utils::createCodeVerifier();
                $_SESSION['codeChallenge'] = Utils::createCodeChallenge($_SESSION['codeVerifier']);
                $_SESSION['pkce']          = "S256";
                $pkce = ['code_challenge'        => $_SESSION['codeChallenge'],
                         'code_challenge_method' => 'S256',
                    ];
                break;
        }
    }


    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl($pkce);

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
            // Try to get an access token using the authorization code grant.
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code'           => $_GET['code'],
                'code_verifier'  => $_SESSION['codeVerifier'],
            ]);

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
                    'refresh_token' => $_SESSION['token']->getRefreshToken()
                ]);
            } catch (GeocachingIdentityProviderException $e) {
                $twig_vars['exception'] = [
                    'type'    => array_pop($class),
                    'message' => $e->getMessage(),
                    'code'    => $e->getCode(),
                    'trace'   => print_r($e->getTrace(), true),
                ];
            }
        }

        // Create GeocachingSDK from a factory
        $geocachingApi = GeocachingFactory::createSdk(
            $_SESSION['token']->getToken(),
            $app['environment'],
            [
                'debug'   => HTTP_DEBUG,
                'timeout' => 10,
                'connect_timeout' => 10,
            ]
        );
        // request the API with getUser method
        $httpResponse = $geocachingApi->getUser('me', ['fields' => 'username,referenceCode,joinedDateUtc,favoritePoints,membershipLevelId,avatarUrl,bannerUrl,url,homeCoordinates,hideCount,findCount,geocacheLimits,optedInFriendSharing']);

        $response['body']    = $httpResponse->getBody(true);
        $response['headers'] = $httpResponse->getHeaders();
        $response['statusCode'] = sprintf('%d %s', $httpResponse->getStatusCode(), $httpResponse->getReasonPhrase());

        $twig_vars['response'] = $response;
    } catch (\Throwable $e) {
        $class = explode('\\', get_class($e));

        $twig_vars['exception'] = [
            'type'    => array_pop($class),
            'message' => $e->getMessage(),
            'code'    => $e->getCode(),
            'trace'   => print_r($e->getTrace(), true),
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

/**
 * @param string $plainText
 *
 * @return string
 */
function base64url_encode(string $plainText): string
{
    return trim(strtr(base64_encode($plainText), '+/', '-_'), "=");
}
