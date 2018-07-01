<?php

require __DIR__ . '/config.php';

session_start();
header('Content-Type: text/html; charset=UTF-8');

require ROOT . '/vendor/autoload.php';

$twig_options = ['debug' => false, 'cache' => false];

$loader = new Twig_Loader_Filesystem(ROOT . '/templates');
$twig   = new Twig_Environment($loader, $twig_options);

// $twig->addExtension(new Twig_Extension_Debug());

$twig->addFilter(new Twig_Filter('print_r', function(array $array) {
    return print_r($array, true);
}));