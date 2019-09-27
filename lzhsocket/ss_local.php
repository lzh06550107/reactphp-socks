<?php

/**
 * 本地代理，主要负责接收浏览器sock请求，并把连接请求加密转发给ss_server端
 */

use React\Socket\Server;

require __DIR__ . '/../vendor/autoload.php';

define('IS_LOCAL', true);
define('PASSWORD', 'diaomao');

$loop = React\EventLoop\Factory::create();

new \lzhsocket\Socks\Client('127.0.0.1:1081',$loop);

echo 'SOCKS server listening on 127.0.0.1:1080'  . PHP_EOL;
echo 'Forwarding via: 35.229.174.18:80' . PHP_EOL;

$loop->run();