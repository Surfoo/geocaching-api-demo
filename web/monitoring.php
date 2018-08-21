 <?php

require dirname(__DIR__) . '/app/app.php';

$swaggerAbsolutePath = dirname(__DIR__) . '/' . SWAGGER_PATH;

if (file_exists($swaggerAbsolutePath) &&
    is_readable($swaggerAbsolutePath) &&
    (time() - filemtime($swaggerAbsolutePath) < SWAGGER_TTL)) {
    $jsonContent = file_get_contents($swaggerAbsolutePath);
} else {
    try {
        $jsonContent = (new GuzzleHttp\Client())->get(URI_SWAGGER_FILE)->getBody();
    } catch(\Exception $e) {
        $twig_vars['exception'] = $e->getMessage();
        echo $twig->render('monitoring.html.twig', $twig_vars);
        exit();
    }
    file_put_contents($swaggerAbsolutePath, $jsonContent);
}

$swaggerJson = json_decode($jsonContent, true);

$swaggerMethods = [];
foreach($swaggerJson['paths'] as $path => $methods) {
    foreach(array_keys($methods) as $method) {
        $swaggerMethods[] = sprintf('%s %s', strtoupper($method), $path);
    }
}

// GeocachingSdk Methods
$methods = (new ReflectionClass('Geocaching\Sdk\GeocachingSdk'))->getMethods();
$sdkMethods = [];
foreach ($methods as $method) {
    if ($method->getName() == '__construct') {
        continue;
    }

    preg_match('/swagger:\s([^\s]+)\s([^\s]+)/', $method->getDocComment(), $matches);

    if (count($matches) == 3) {
        list($full, $methodMatch, $pathMatch) = $matches;
        $sdkMethods[] = sprintf('%s %s', $methodMatch, $pathMatch);
    }
}

$twig_vars['swaggerCreatedOn']      = date('r', filemtime($swaggerAbsolutePath));
$twig_vars['uri_swagger_file']      = URI_SWAGGER_FILE;
$twig_vars['positive_diff_methods'] = array_diff($swaggerMethods, $sdkMethods);
$twig_vars['negative_diff_methods'] = array_diff($sdkMethods, $swaggerMethods);

echo $twig->render('monitoring.html.twig', $twig_vars);
