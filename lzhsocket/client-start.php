<?php

require __DIR__ . '/../vendor/autoload.php';

define('IS_LOCAL', true);
define('PASSWORD', 'diaomao');

$loop = React\EventLoop\Factory::create();

$connector = new React\Socket\Connector($loop);
$client = new Clue\React\Socks\Client('socks://127.0.0.1:1081', $connector);

$server = new Clue\React\Socks\Server($loop, $client);

$socket = new React\Socket\Server('127.0.0.1:1080', $loop);
$server->listen($socket);

echo 'SOCKS server listening on 127.0.0.1:1080'  . PHP_EOL;
echo 'Forwarding via: 35.229.174.18:80' . PHP_EOL;

$loop->run();