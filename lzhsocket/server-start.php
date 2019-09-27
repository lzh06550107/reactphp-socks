<?php

// A more advanced example which runs a secure SOCKS over TLS proxy server.
// The listen address can be given as first argument and defaults to localhost:1080 otherwise.
//
// See also example #32 for the client side.

use Clue\React\Socks\Server;
use React\Socket\Server as Socket;

require __DIR__ . '/../vendor/autoload.php';

define('PASSWORD', 'diaomao');

$loop = React\EventLoop\Factory::create();

// start a new SOCKS proxy server
$server = new Server($loop);

// listen on 127.0.0.1:1080 or first argument
$socket = new Socket(isset($argv[1]) ? $argv[1] : '127.0.0.1:1081', $loop);
$server->listen($socket);

echo 'SOCKS server listening on ' . $socket->getAddress() . PHP_EOL;

$loop->run();
