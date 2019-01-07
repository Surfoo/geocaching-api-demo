<?php

require dirname(__DIR__) . '/app/app.php';

use Geocaching\GeocachingFactory;
use Geocaching\Exception\GeocachingSdkException;

$accessToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1bmlxdWVfbmFtZSI6IlN1cmZvbyIsInN1YiI6Ijg0ZDliMGY0LTI2YzYtNDlhOS05YzE0LTg1ZmNhMGI1NjI0YiIsImFpZCI6IjEyMjA0MzIiLCJsZ2QiOiJjZTYwYWJkMi0xNzdkLTQzYjItOGU5MS1jMzUxNDMxZWMxNWYiLCJpc3MiOiJodHRwczovL29hdXRoLXN0YWdpbmcuZ2VvY2FjaGluZy5jb20vdG9rZW4iLCJhdWQiOiJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3VzZXJkYXRhOiBhMmQ1MTE0YS0wYjEzLTQ4OTEtOTczNi1hM2Q0ZDkzMDMwZTUiLCJleHAiOjE1MzkwNjk2ODUsIm5iZiI6MTUzOTA2NjA4NX0.yuqZ7eYwaeqmVKoEWS88RQ0DdB2KIfyk4AIZLwiF33Q';

try {
    $geocachingApi = GeocachingFactory::createSdk($accessToken, $app['environment'],
                                                [
                                                    'debug'   => false,
                                                    'timeout' => 10,
                                                ]);
    // request the API
    $httpResponse = $geocachingApi->getUser('me', ['fields' => 'geocacheLimits']);
    $response['body'] = $httpResponse->getBody()->geocacheLimits;

    $count = $response['body']->liteCallsRemaining;
    echo $response['body']->liteCallsRemaining . "\n";

    $take = 100;
    // if ($take > $response['body']->liteCallsRemaining) {
    //     $take = $response['body']->liteCallsRemaining;
    // }
    // while($count > 0) {
        $httpResponse = $geocachingApi->searchGeocaches(
            [ 'lite' => true, 
              'q' => 'co:france',
              'take' => $take
            ]);
        $count -= $take;

        echo $count . "\n";
        sleep(2);
    // }

    $httpResponse = $geocachingApi->getUser('me', ['fields' => 'geocacheLimits']);
    $response = $httpResponse->getBody()->geocacheLimits;

} catch (\Exception $e) {
    echo $e->getMessage() . ' Code:' . $e->getCode();
    die;
}

var_dump($response);