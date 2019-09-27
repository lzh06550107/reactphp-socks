<?php

require __DIR__ . '/../vendor/autoload.php';

$loop = React\EventLoop\Factory::create(); // 创建一个循环实例

$server = stream_socket_server('tcp://127.0.0.1:8080'); // 创建一个服务器socket，返回创建的流
stream_set_blocking($server, false); // 设置该流为非阻塞

// 注册流的读事件到事件循环中
$loop->addReadStream($server, function ($server) use ($loop) {
    $conn = stream_socket_accept($server); // 接收一个连接，返回一个连接流
    $data = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHi\n"; // 响应数据
    // 注册流的写事件到事件循环中
    $loop->addWriteStream($conn, function ($conn) use (&$data, $loop) {
        $written = fwrite($conn, $data); // 写入数据到流中，因为非阻塞，所以不能保证一次能够写入所有的数据
        if ($written === strlen($data)) { // 如果数据已经完全写入，则关闭连接流
            fclose($conn);
            $loop->removeWriteStream($conn); // 从事件循环中删除连接流写事件
        } else { // 清除已经写入的数据
            $data = substr($data, $written);
        }
    });
});
// 添加周期定时器来统计当前脚本使用的内存
$loop->addPeriodicTimer(5, function () {
    $memory = memory_get_usage() / 1024; // 统计分配给脚本的内存
    $formatted = number_format($memory, 3).'K';
    echo "Current memory usage: {$formatted}\n";
});

$loop->run(); //开始事件循环