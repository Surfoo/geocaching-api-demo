<?php

require __DIR__ . '/config.php';

header('Content-Type: text/html; charset=UTF-8');

require ROOT . '/vendor/autoload.php';

$debug = false;

if ($_SERVER['SERVER_NAME'] == 'localhost') {
    ini_set('display_errors', '1');
    error_reporting(-1);
    $debug = true;
}

$twig_options = ['debug' => $debug, 'cache' => false];

$loader = new Twig\Loader\FilesystemLoader(ROOT . '/templates');
$twig   = new Twig\Environment($loader, $twig_options);

$twig->addExtension(new \Twig\Extension\DebugExtension());

$twig->addFilter(new Twig\TwigFilter('print_r', function (array $array) {
    return print_r($array, true);
}));
