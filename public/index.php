<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\ClientBuilder;
use Geocaching\Enum\Environment;
use Geocaching\GeocachingSdk;
use Geocaching\Options;
use Geocaching\Plugin\GeocachingHttpLoggerPlugin;
use GeoDemo\SessionTokenStorage;
use League\OAuth2\Client\Plugin\TokenRefreshPlugin;
use League\OAuth2\Client\Provider\Exception\GeocachingIdentityProviderException;
use League\OAuth2\Client\Provider\Geocaching as GeocachingProvider;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Psr\Log\LogLevel;

// Display HTTP logs
define('HTTP_DEBUG', true);

session_start();

$twig_vars = [];

$logger = new Logger('demo');
$logger->pushHandler(new StreamHandler(__DIR__ . '/../logs/demo.log', \Monolog\Level::Debug));

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
        // state is OK, retrieve the access token
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

            // Capture reference code for later refresh storage key
            try {
                $requester = $provider->setResourceOwnerFields(
                    [
                        'referenceCode',
                        'findCount',
                        'hideCount',
                        'favoritePoints',
                        'username',
                        'membershipLevelId',
                        'url',
                    ])->getResourceOwner($accessToken);
                $_SESSION['resourceReference'] = $requester->getReferenceCode();
                $_SESSION['requester'] = $requester;
            } catch (\Throwable $e) {
                $logger->warning('Unable to fetch resource owner after auth', ['error' => $e->getMessage()]);
                $_SESSION['resourceReference'] = 'session-user';
            }
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
        // Use stored reference code from initial auth (fallback to generic key)
        $referenceCode = $_SESSION['resourceReference'] ?? 'session-user';

        // Build client builder
        $clientBuilder = new ClientBuilder();

        //Optional refresh plugin
        $storage       = new SessionTokenStorage();
        $refreshPlugin = new TokenRefreshPlugin(
            $referenceCode,
            $storage,
            $provider,
            $logger
        );
        $clientBuilder->addPlugin($refreshPlugin);

        // Optional HTTP logging captured in-memory
        $httpLogHandler = null;
        if (HTTP_DEBUG) {
            $httpLogHandler = new TestHandler();
            $httpLogger     = new Logger('http');
            $httpLogger->pushHandler($httpLogHandler);

            $clientBuilder->addPlugin(new GeocachingHttpLoggerPlugin(
                $httpLogger,
                LogLevel::DEBUG,
                logBodies: true,
                maskTokens: true
            ));
        }

        $options = new Options([
            'access_token'   => $_SESSION['token']->getToken(),
            'environment'    => Environment::from($app['environment']),
            'client_builder' => $clientBuilder,
            'token_storage'  => $storage,
            'reference_code' => $referenceCode,
        ]);
        $geocachingApi = new GeocachingSdk($options);

        /**
         * Example: request the API with getUser method
         */
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
            'errorMessage' => $jsonContent->errorMessage ?? null,
            'code'         => $e->getCode(),
            'trace'        => print_r($e->getTrace(), true),
        ];
    }

    if (HTTP_DEBUG && isset($httpLogHandler)) {
        $twig_vars['http_debug'] = implode("\n", array_map(
            static fn ($record) => sprintf(
                '[%s] %s: %s %s',
                $record['datetime']->format('c'),
                $record['level_name'],
                $record['message'],
                $record['context'] ? json_encode($record['context']) : ''
            ),
            $httpLogHandler->getRecords()
        ));
    }
}

$twig_vars['environment'] = $app['environment'] ?? null;
$twig_vars['requester']   = $_SESSION['requester'] ?? null;
$twig_vars['token']       = $_SESSION['token'] ?? null;

echo $twig->render('index.html.twig', $twig_vars);
