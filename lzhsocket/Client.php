<?php

namespace lzhsocket\Socks;

use Exception;
use React\EventLoop\LoopInterface;
use React\Socket\ConnectorInterface;
use React\Socket\Server;
use React\Socket\ConnectionInterface;
use  React\Socket\Connector;
use RuntimeException;
use UnexpectedValueException;

final class Client
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

    private $connector;
    private $socksUri;
    private $loop;
    private $server;

    public function __construct($socksUri, LoopInterface $loop, ConnectorInterface $connector = null)
    {

        $this->socksUri = $socksUri; // 远程服务器uri

        $this->loop = $loop;

        $that = $this;

        $this->connector = $connector?? new Connector($loop);

        $this->server = new Server('127.0.0.1:1080', $loop); // 建立本地服务代理

        $this->server->on('connection', function(ConnectionInterface $local) use($that) {

            // 对sock5进行回复都在本地客户端进行，最后发送建立连接转发给远程服务端
            $this->onConnection($local);

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

        // 注册监听关闭事件
        $stream->once('close', function () use (&$tid, $loop) {
            if ($tid === true) {
                // 确保不要启动无用的计时器
                $tid = false;
            } else { // 如果连接通过定时器强制关闭，则取消定时器
                $loop->cancelTimer($tid);
            }
        });

        // 1、通过暂停输入数据，刷新输出缓冲区然后退出来关闭连接
        $stream->pause();
        $stream->end(); // 会触发close事件

        // 检查连接是否尚未关闭，就是还没有触发close事件
        if ($tid === true) {
            // 如果缓冲区无法刷新，则在3秒内强制关闭连接
            $tid = $loop->addTimer(3.0, array($stream,'close'));
        }
    }

    /** @internal */
    public function onConnection(ConnectionInterface $connection)
    {
        $that = $this;
        $handling = $this->handleSocks($connection)->then(null, function () use ($connection, $that) {
            // SOCKS失败=>关闭连接
            $that->endConnection($connection); // 如果远程连接失败，则关闭当前连接
        });

        $connection->on('close', function () use ($handling) {
            $handling->cancel(); // 当前连接关闭，则取消未执行的promise
        });
    }

    private function handleSocks(ConnectionInterface $stream)
    {
        $reader = new StreamReader();
        // 监听data事件，把接收数据写入缓冲区中
        $stream->on('data', array($reader, 'write'));

        $that = $this;

        // 读取一个字节数据
        return $reader->readByte()->then(function ($version) use ($stream, $that, $reader){
            if ($version === 0x05) {
                return $that->handleSocks5($stream, $reader);
            }
            // 如果不是socks5版本协议，则抛出异常，生成一个拒绝promise
            throw new UnexpectedValueException('意外/未知版本号');
        });
    }

    /** @internal */
    public function handleSocks5(ConnectionInterface $stream, StreamReader $reader)
    {
        $remote = $stream->getRemoteAddress();

        $that = $this;
        return $reader->readByte()->then(function ($num) use ($reader) {
            return $reader->readLength($num); // 字段是 METHODS 字段占用的字节数，八位的范围为(0~255)
        })->then(function ($methods) use ($reader, $stream, &$remote) {
            // 如果为0表示不需要认证
            if (strpos($methods,"\x00") !== false) {
                // 接收 "no authentication" 服务器返回，不需要认证
                $stream->write(pack('C2', 0x05, 0x00));

                return 0x00;
            } else {
                // 拒绝所有提供的认证方法
                $stream->write(pack('C2', 0x05, 0xFF));
                throw new UnexpectedValueException('找不到可接受的认证机制');
            }
        })->then(function ($method) use ($reader) { // 读取建立连接数据
            return $reader->readBinary(array(
                'version' => 'C',
                'command' => 'C',
                'null'    => 'C',
                'type'    => 'C'
            ));
        })->then(function ($data) use ($reader) {
            if ($data['version'] !== 0x05) {
                throw new UnexpectedValueException('SOCKS版本无效');
            }
            if ($data['command'] !== 0x01) {
                throw new UnexpectedValueException('仅支持CONNECT请求', Client::ERROR_COMMAND_UNSUPPORTED);
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
                throw new UnexpectedValueException('地址类型无效', Client::ERROR_ADDRESS_UNSUPPORTED);
            }
        })->then(function ($host) use ($reader, &$remote) { // 组装目标地址
            return $reader->readBinary(array('port'=>'n'))->then(function ($data) use ($host, &$remote) {
                return array($host, $data['port'], $remote); // $remote表示目标源
            });
        })->then(function ($target) use ($that, $stream) { //
            return $that->connectServer($stream, $target); // 连接远程服务器
        }, function($error) use ($stream) {
            throw new UnexpectedValueException('SOCKS5协议错误', $error->getCode(), $error);
        });
    }

    public function connectServer($local, $target) {

        $that = $this;

        return $this->connector->connect($this->socksUri)->then(function (ConnectionInterface $remote) use ($local, $that, $target) {

            echo PHP_EOL.'diaomao request '.$target[0].':'.$target[1] ;

            $remote = new EncryptDecryptConnection($remote);

            // 不解析主机名。 只尝试转换为（二进制/包）IP
            $ip = @inet_pton($target[0]);

            $uri = $target[0];

            $data = pack('C3', 0x05, 0x01, 0x00);
            if ($ip === false) {

                // 不是IP，作为主机名发送
                $data .= pack('C2', 0x03, strlen($target[0])) . $target[0];
            } else {
                // 发送 IPv4 / IPv6
                $data .= pack('C', (strpos($target[0], ':') === false) ? 0x01 : 0x04) . $ip;
            }
            $data .= pack('n', $target[1]);

            $remote->write($data); //TODO  发起连接请求，但需要加密

            $reader = new StreamReader();
            $remote->on('data', array($reader, 'write')); // TODO 需要解密

            $reader->readBinary(array(
                'version' => 'C',
                'status' => 'C',
                'null' => 'C',
                'type' => 'C'
            ))->then(function ($data) use ($reader, $uri) {
                if ($data['version'] !== 0x05 || $data['null'] !== 0x00) {
                    throw new Exception('SOCKS响应无效');
                }
                if ($data['status'] !== 0x00) {
                    // 将有限的SOCKS错误代码列表映射到常见的套接字错误条件
                    // @link https://tools.ietf.org/html/rfc1928#section-6
                    if ($data['status'] === Client::ERROR_GENERAL) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为一般服务器故障，代理拒绝连接 (ECONNREFUSED)',
                            defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                        );
                    } elseif ($data['status'] === Client::ERROR_NOT_ALLOWED_BY_RULESET) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理因规则集而拒绝访问 (EACCES)',
                            defined('SOCKET_EACCES') ? SOCKET_EACCES : 13
                        );
                    } elseif ($data['status'] === Client::ERROR_NETWORK_UNREACHABLE) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理报告网络无法访问 (ENETUNREACH)',
                            defined('SOCKET_ENETUNREACH') ? SOCKET_ENETUNREACH : 101
                        );
                    } elseif ($data['status'] === Client::ERROR_HOST_UNREACHABLE) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理报告主机无法访问 (EHOSTUNREACH)',
                            defined('SOCKET_EHOSTUNREACH') ? SOCKET_EHOSTUNREACH : 113
                        );
                    } elseif ($data['status'] === Client::ERROR_CONNECTION_REFUSED) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' failed because proxy reported connection refused (ECONNREFUSED)',
                            defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                        );
                    } elseif ($data['status'] === Client::ERROR_TTL) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理报告TTL /超时已过期 (ETIMEDOUT)',
                            defined('SOCKET_ETIMEDOUT') ? SOCKET_ETIMEDOUT : 110
                        );
                    } elseif ($data['status'] === Client::ERROR_COMMAND_UNSUPPORTED) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理不支持CONNECT命令 (EPROTO)',
                            defined('SOCKET_EPROTO') ? SOCKET_EPROTO : 71
                        );
                    } elseif ($data['status'] === Client::ERROR_ADDRESS_UNSUPPORTED) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为代理不支持此地址类型 (EPROTO)',
                            defined('SOCKET_EPROTO') ? SOCKET_EPROTO : 71
                        );
                    }

                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为未知错误代码，代理服务器拒绝连接 ' . sprintf('0x%02X', $data['status']) . ' (ECONNREFUSED)',
                        defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                    );
                }
                if ($data['type'] === 0x01) {
                    // IPv4 address => skip IP 和端口
                    return $reader->readLength(6);
                } elseif ($data['type'] === 0x03) {
                    // domain name => 读域名长度
                    return $reader->readBinary(array(
                        'length' => 'C'
                    ))->then(function ($data) use ($reader) {
                        // 跳过域名和端口
                        return $reader->readLength($data['length'] + 2);
                    });
                } elseif ($data['type'] === 0x04) {
                    // IPv6 address => 跳过域名和端口
                    return $reader->readLength(18);
                } else {
                    throw new Exception('SOCKS响应无效：地址类型无效');
                }
            },function (Exception $error) {
                throw new Exception('无法读取数据', 0, $error);
            })->then(function () use ($local, $remote, $that) {
                $local->write(pack('C4Nn', 0x05, 0x00, 0x00, 0x01, 0, 0));

                $remote->removeAllListeners('data');

                $local->on('data', function($data) use($remote){
                    $remote->write($data);
                });

                $remote->on('data', function($data) use  ($local) {
                    $local->write($data);
                });

                // 远程端关闭连接=>从本端停止读取，尝试将缓冲区刷新到本地并断开本地连接
                $remote->on('end', function () use ($local, $that) {
                    $that->endConnection($local);
                });

                // 本地端关闭连接=>停止从远程端读取，尝试将缓冲区刷新到远程并断开远程连接
                $local->on('end', function () use ($remote, $that) {
                    $that->endConnection($remote);
                });

                return $remote;
            });
        });
    }
}
