<?php

namespace lzhsocket\Socks;

use React\Socket\ServerInterface;
use React\Socket\ConnectorInterface;
use React\Socket\Connector;
use React\Socket\ConnectionInterface;
use React\EventLoop\LoopInterface;
use \UnexpectedValueException;
use \InvalidArgumentException;
use \Exception;

final class Server
{
    // 以下错误代码仅用于SOCKS5
    /** @internal */
    const ERROR_GENERAL = 0x01;
    /** @internal */
    const ERROR_NOT_ALLOWED_BY_RULESET = 0x02;
    /** @internal */
    const ERROR_NETWORK_UNREACHABLE = 0x03;
    /** @internal */
    const ERROR_HOST_UNREACHABLE = 0x04;
    /** @internal */
    const ERROR_CONNECTION_REFUSED = 0x05;
    /** @internal */
    const ERROR_TTL = 0x06;
    /** @internal */
    const ERROR_COMMAND_UNSUPPORTED = 0x07;
    /** @internal */
    const ERROR_ADDRESS_UNSUPPORTED = 0x08;

    private $loop;

    private $connector;

    /**
     * @param LoopInterface           $loop
     * @param null|ConnectorInterface $connector
     */
    public function __construct(LoopInterface $loop, ConnectorInterface $connector = null)
    {
        if ($connector === null) {
            $connector = new Connector($loop);
        }

        $this->loop = $loop;
        $this->connector = $connector;
    }

    /**
     * @param ServerInterface $socket
     * @return void
     */
    public function listen(ServerInterface $socket) // 监听客户端连接
    {
        $that = $this;
        $socket->on('connection', function (ConnectionInterface $connection) use ($that) {
            // 使用加密和解密连接包装连接
            $that->onConnection(new EncryptDecryptConnection($connection));
            //$that->onConnection($connection);
        });
    }

    /** @internal */
    public function onConnection(ConnectionInterface $connection)
    {
        $that = $this;
        $handling = $this->handleSocks($connection)->then(null, function () use ($connection, $that) {
            // SOCKS失败=>关闭连接
            $that->endConnection($connection);
        });

        $connection->on('close', function () use ($handling) {
            $handling->cancel();
        });
    }

    /**
     * [internal] 通过刷新所有剩余数据和关闭流来正常关闭连接
     *
     * @internal
     */
    public function endConnection(ConnectionInterface $stream)
    {
        $tid = true;
        $loop = $this->loop;

        // 如果连接及时关闭，请取消定时器
        $stream->once('close', function () use (&$tid, $loop) {
            if ($tid === true) {
                // 确保不要启动无用的计时器
                $tid = false;
            } else {
                $loop->cancelTimer($tid);
            }
        });

        // 通过暂停输入数据，刷新输出缓冲区然后退出来关闭连接
        $stream->pause();
        $stream->end();

        // 检查连接是否尚未关闭
        if ($tid === true) {
            // 如果缓冲区无法刷新，则在3秒内强制关闭连接
            $tid = $loop->addTimer(3.0, array($stream,'close'));
        }
    }

    private function handleSocks(ConnectionInterface $stream)
    {
        $reader = new StreamReader();
        // 监听data事件，把接收数据写入缓冲区中

        $stream->on('data', array($reader, 'write'));

        $that = $this;

        return $that->handleSocks5($stream, $reader);
    }

    /** @internal */
    public function handleSocks5(ConnectionInterface $stream, StreamReader $reader)
    {
        $remote = $stream->getRemoteAddress();

        $that = $this;
        return $reader->readBinary(array(
                'version' => 'C',
                'command' => 'C',
                'null'    => 'C',
                'type'    => 'C'
            ))->then(function ($data) use ($reader) {
            if ($data['version'] !== 0x05) {
                throw new UnexpectedValueException('SOCKS版本无效');
            }
            if ($data['command'] !== 0x01) {
                throw new UnexpectedValueException('仅支持CONNECT请求', Server::ERROR_COMMAND_UNSUPPORTED);
            }

            if ($data['type'] === 0x03) { // 域名访问
                return $reader->readByte()->then(function ($len) use ($reader) {
                    return $reader->readLength($len); // 读取域名数据
                });
            } else if ($data['type'] === 0x01) { // 如果是ip4
                return $reader->readLength(4)->then(function ($addr) {
                    return inet_ntop($addr); // 读取ip4地址
                });
            } else if ($data['type'] === 0x04) { // 如果是ip6
                return $reader->readLength(16)->then(function ($addr) {
                    return inet_ntop($addr); // 读取ip6地址
                });
            } else {
                throw new UnexpectedValueException('地址类型无效', Server::ERROR_ADDRESS_UNSUPPORTED);
            }
        })->then(function ($host) use ($reader, &$remote) { // 组装目标地址
            return $reader->readBinary(array('port'=>'n'))->then(function ($data) use ($host, &$remote) {
                return array($host, $data['port'], $remote); // $remote表示目标源
            });
        })->then(function ($target) use ($that, $stream) { //
            return $that->connectTarget($stream, $target); // 连接目标地址
        }, function($error) use ($stream) {
            throw new UnexpectedValueException('SOCKS5协议错误', $error->getCode(), $error);
        })->then(function (ConnectionInterface $remote) use ($stream) {
            // 服务器建立远程连接成功后回应客户端，表示整个代理链路建立完成，可以发送请求数据
            $stream->write(pack('C4Nn', 0x05, 0x00, 0x00, 0x01, 0, 0));

            return $remote; // 返回远程连接对象
        }, function(Exception $error) use ($stream){
            //  服务器建立远程连接失败后回应客户端，表示整个代理链路建立失败
            $stream->write(pack('C4Nn', 0x05, $error->getCode() === 0 ? Server::ERROR_GENERAL : $error->getCode(), 0x00, 0x01, 0, 0));

            throw $error;
        });
    }

    /** @internal */
    public function connectTarget(ConnectionInterface $stream, array $target)
    {
        $uri = $target[0];
        if (strpos($uri, ':') !== false) {
            $uri = '[' . $uri . ']';
        }
        $uri .= ':' . $target[1];

        // 验证URI，因此字符串主机名不能传递过多的URI部分
        $parts = parse_url('tcp://' . $uri);
        if (!$parts || !isset($parts['scheme'], $parts['host'], $parts['port']) || count($parts) !== 3) {
            return \React\Promise\reject(new InvalidArgumentException('给定的目标URI无效'));
        }

        if (isset($target[2])) {
            $uri .= '?source=' . rawurlencode($target[2]); // 带上目标源
        }

        $that = $this;

        echo PHP_EOL.'diaomao build link with '.$uri;

        $connecting = $this->connector->connect($uri);

        // 如果当前连接关闭，则没有必要执行远程连接
        $stream->on('close', function () use ($connecting) {
            $connecting->cancel();
        });
        // socks连接成功后就是数据转发
        return $connecting->then(function (ConnectionInterface $remote) use ($stream, $that, $uri) {
            // 清空本地连接data监听
            $stream->removeAllListeners('data');

            // 类似于管道传输数据，直接数据转发
            $stream->on('data', function($data) use($remote){
                $remote->write($data);
            });

            $remote->on('data', function($data) use  ($stream) {
                $stream->write($data);
            });

            // 远程端关闭连接=>从本端停止读取，尝试将缓冲区刷新到本地并断开本地连接
            $remote->on('end', function() use ($stream, $that) {
                $that->endConnection($stream);
            });

            // 本地端关闭连接=>停止从远程端读取，尝试将缓冲区刷新到远程并断开远程连接
            $stream->on('end', function() use ($remote, $that) {
                $that->endConnection($remote);
            });

            return $remote;
        }, function(Exception $error) {
            // 默认为一般/未知错误
            $code = Server::ERROR_GENERAL;
            throw new UnexpectedValueException('无法连接到远程目标', $code, $error);
        });
    }
}
