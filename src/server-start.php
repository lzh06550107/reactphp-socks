<?php

// A more advanced example which runs a secure SOCKS over TLS proxy server.
// The listen address can be given as first argument and defaults to localhost:1080 otherwise.
//
// See also example #32 for the client side.

use Clue\React\Socks\Server;
use React\Socket\Server as Socket;

require __DIR__ . '/../vendor/autoload.php';

$loop = React\EventLoop\Factory::create();

// start a new SOCKS proxy server
$server = new Server($loop);

// listen on tls://127.0.0.1:1080 or first argument
$listen = isset($argv[1]) ? $argv[1] : '127.0.0.1:80';
$socket = new Socket('tls://' . $listen, $loop, array('tls' => array(
    'local_cert' => __DIR__ . '/localhost.pem',
)));

echo 'SOCKS over TLS server listening on ' . str_replace('tls:', 'sockss:', $socket->getAddress()) . PHP_EOL;

$server->listen($socket);

$loop->run();
