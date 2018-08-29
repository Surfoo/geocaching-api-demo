<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\GeocachingFactory;
use Geocaching\Exception\GeocachingSdkException;
use League\OAuth2\Client\Provider\Geocaching as GeocachingProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

$twig_vars = [];

// OAuth reset
if (isset($_POST['reset'])) {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', 0);
    }
    session_destroy();
    header('Location: /');
    exit(0);
}

if (isset($_POST['environment'])) {
    $_SESSION['environment']  = $_POST['environment'] == GeocachingFactory::ENVIRONMENT_PRODUCTION ?
                                                            GeocachingFactory::ENVIRONMENT_PRODUCTION :
                                                            GeocachingFactory::ENVIRONMENT_STAGING;
    $_SESSION['oauth_key']    = $app[$_SESSION['environment']]['oauth_key'];
    $_SESSION['oauth_secret'] = $app[$_SESSION['environment']]['oauth_secret'];
    $_SESSION['callback_url'] = $app[$_SESSION['environment']]['callback_url'];
}

if (isset($_SESSION['environment'])) {
    $provider = new GeocachingProvider([
        'clientId'       => $_SESSION['oauth_key'],
        'clientSecret'   => $_SESSION['oauth_secret'],
        'redirectUri'    => $_SESSION['callback_url'],
        'response_type'  => 'code',
        'scope'          => '*',
        'environment'    => $_SESSION['environment'],
    ]);
}

if (isset($_SESSION['environment']) && !isset($_SESSION['accessToken'])) {

    if (!isset($_GET['code'])) {
        // Fetch the authorization URL from the provider; this returns the
        // urlAuthorize option and generates and applies any necessary parameters
        // (e.g. state).
        $authorizationUrl = $provider->getAuthorizationUrl();

        // Get the state generated for you and store it to the session.
        $_SESSION['oauth2state'] = $provider->getState();
    
        // Redirect the user to the authorization URL.
        header('Location: ' . $authorizationUrl);
        exit(0);
    
    // Check given state against previously stored one to mitigate CSRF attack
    } elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    
        $twig_vars['exception'] = [
            'type'    => 'Invalid State',
            'message' => $_GET['state'] . ' != ' . $_SESSION['oauth2state']
        ];

        if (isset($_SESSION['oauth2state'])) {
            unset($_SESSION['oauth2state']);
        }
    } else {
        try {
            // Try to get an access token using the authorization code grant.
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
            // We have an access token, which we may use in authenticated
            // requests against the service provider's API.
            $_SESSION['accessToken']  = $accessToken->getToken();
            $_SESSION['refreshToken'] = $accessToken->getRefreshToken();
            $_SESSION['expired_in']   = $accessToken->getRefreshToken();
            $_SESSION['hasExpired']   = $accessToken->hasExpired();
            $_SESSION['code']         = $_GET['code'];
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
        $httpDebug = true;
        $geocachingApi = GeocachingFactory::createSdk($_SESSION['accessToken'], 
                                                      $_SESSION['environment'], 
                                                    [
                                                        'debug'   => $httpDebug,
                                                        'timeout' => 10,
                                                    ]);

        $httpResponse = $geocachingApi->getUserLists('me', ['types' => 'pq', 'fields' => 'referenceCode,name,url']);

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

$twig_vars['session'] = $_SESSION;

echo $twig->render('index.html.twig', $twig_vars);
