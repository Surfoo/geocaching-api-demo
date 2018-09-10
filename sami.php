<?php

/**
 * @see https://github.com/FriendsOfPHP/Sami
 */

use Sami\Sami;
use Symfony\Component\Finder\Finder;

$iterator = Finder::create()
    ->files()
    ->name('*.php')
    ->exclude('Resources')
    ->exclude('Tests')
    ->in('vendor/surfoo/geocaching-php-sdk/src')
;

return new Sami($iterator, [
    'title'                => 'Geocaching PHP SDK',
    'build_dir'            => __DIR__ . '/web/docs/',
]);
