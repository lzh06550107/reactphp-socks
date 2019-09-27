<?php

/**
 * 远程代理，负责解密ss_local发送过来的数据并转发给远程资源
 */

use lzhsocket\Socks\Server;

require __DIR__ . '/../vendor/autoload.php';

define('PASSWORD', 'diaomao');

$loop = React\EventLoop\Factory::create();

// start a new SOCKS proxy server
$server = new Server($loop);

// listen on 127.0.0.1:1080 or first argument
$socket = new \React\Socket\Server(isset($argv[1]) ? $argv[1] : '0.0.0.0:2333', $loop);
$server->listen($socket);

echo 'SOCKS server listening on ' . $socket->getAddress() . PHP_EOL;

$loop->run();

