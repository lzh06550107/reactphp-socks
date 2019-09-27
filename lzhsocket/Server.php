<?php

namespace Clue\React\Socks;

use function foo\func;
use phpDocumentor\Reflection\DocBlock\Description;
use React\Socket\ServerInterface;
use React\Promise\PromiseInterface;
use React\Socket\ConnectorInterface;
use React\Socket\Connector;
use React\Socket\ConnectionInterface;
use React\EventLoop\LoopInterface;
use React\Stream\ThroughStream;
use \UnexpectedValueException;
use \InvalidArgumentException;
use \Exception;
use React\Promise\Timer\TimeoutException;

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
     * @var null|callable
     */
    private $auth;

    /**
     * @param LoopInterface           $loop
     * @param null|ConnectorInterface $connector
     * @param null|array|callable     $auth
     */
    public function __construct(LoopInterface $loop, ConnectorInterface $connector = null, $auth = null)
    {
        if ($connector === null) {
            $connector = new Connector($loop);
        }

        if (\is_array($auth)) {
            // 在身份验证回调中包装身份验证数组
            $this->auth = function ($username, $password) use ($auth) {
                return \React\Promise\resolve(
                    isset($auth[$username]) && (string)$auth[$username] === $password
                );
            };
        } elseif (\is_callable($auth)) {
            // 包装身份验证回调以将其返回值强制转换为promise
            $this->auth = function($username, $password, $remote) use ($auth) {
                return  \React\Promise\resolve(
                    \call_user_func($auth, $username, $password, $remote)
                );
            };
        } elseif ($auth !== null) {
            throw new \InvalidArgumentException('给出了无效的身份验证器');
        }

        $this->loop = $loop;
        $this->connector = $connector;
    }

    /**
     * @param ServerInterface $socket
     * @return void
     */
    public function listen(ServerInterface $socket)
    {
        $that = $this;
        $socket->on('connection', function ($connection) use ($that) {
            $that->onConnection($connection);
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
        $auth = $this->auth;

        // 读取一个字节数据
        return $reader->readByte()->then(function ($version) use ($stream, $that, $auth, $reader){
            if ($version === 0x04) {
                if ($auth !== null) {
                    throw new UnexpectedValueException('因为需要身份验证，不允许SOCKS4');
                }
                return $that->handleSocks4($stream, $reader);
            } else if ($version === 0x05) {
                return $that->handleSocks5($stream, $auth, $reader);
            }
            throw new UnexpectedValueException('意外/未知版本号');
        });
    }

    /** @internal */
    public function handleSocks4(ConnectionInterface $stream, StreamReader $reader)
    {
        $remote = $stream->getRemoteAddress();
        if ($remote !== null) {
            // 删除传输协议并使用socks4://替换
            $secure = strpos($remote, 'tls://') === 0;
            if (($pos = strpos($remote, '://')) !== false) {
                $remote = substr($remote, $pos + 3);
            }
            $remote = 'socks4' . ($secure ? 's' : '') . '://' . $remote;
        }

        $that = $this;
        return $reader->readByteAssert(0x01)->then(function () use ($reader) {
            return $reader->readBinary(array(
                'port'   => 'n',
                'ipLong' => 'N',
                'null'   => 'C'
            ));
        })->then(function ($data) use ($reader, $remote) {
            if ($data['null'] !== 0x00) {
                throw new Exception('不是空字节');
            }
            if ($data['ipLong'] === 0) {
                throw new Exception('无效的IP');
            }
            if ($data['port'] === 0) {
                throw new Exception('无效的端口');
            }
            if ($data['ipLong'] < 256) {
                // 无效的IP =>可能是附加主机名的SOCKS4a请求
                return $reader->readStringNull()->then(function ($string) use ($data, $remote){
                    return array($string, $data['port'], $remote);
                });
            } else {
                $ip = long2ip($data['ipLong']);
                return array($ip, $data['port'], $remote);
            }
        })->then(function ($target) use ($stream, $that) {
            return $that->connectTarget($stream, $target)->then(function (ConnectionInterface $remote) use ($stream){
                $stream->write(pack('C8', 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

                return $remote;
            }, function($error) use ($stream){
                $stream->end(pack('C8', 0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

                throw $error;
            });
        }, function($error) {
            throw new UnexpectedValueException('SOCKS4 protocol error',0,$error);
        });
    }

    /** @internal */
    public function handleSocks5(ConnectionInterface $stream, $auth, StreamReader $reader)
    {
        $remote = $stream->getRemoteAddress();
        if ($remote !== null) {
            // 删除传输协议并用socks5://前缀替换
            $secure = strpos($remote, 'tls://') === 0;
            if (($pos = strpos($remote, '://')) !== false) {
                $remote = substr($remote, $pos + 3);
            }
            $remote = 'socks' . ($secure ? 's' : '') . '://' . $remote;
        }

        $that = $this;
        return $reader->readByte()->then(function ($num) use ($reader) {
            return $reader->readLength($num); // 字段是 METHODS 字段占用的字节数，八位的范围为(0~255)
        })->then(function ($methods) use ($reader, $stream, $auth, &$remote) {
            // 如果为0表示不需要认证
            if ($auth === null && strpos($methods,"\x00") !== false) {
                // 接收 "no authentication" 服务器返回，不需要认证
                $stream->write(pack('C2', 0x05, 0x00));

                return 0x00;
            } else if ($auth !== null && strpos($methods,"\x02") !== false) {
                // 用户名/密码验证（RFC 1929）子协商
                $stream->write(pack('C2', 0x05, 0x02));
                return $reader->readByteAssert(0x01)->then(function () use ($reader) {
                    return $reader->readByte();
                })->then(function ($length) use ($reader) {
                    return $reader->readLength($length);
                })->then(function ($username) use ($reader, $auth, $stream, &$remote) {
                    return $reader->readByte()->then(function ($length) use ($reader) {
                        return $reader->readLength($length);
                    })->then(function ($password) use ($username, $auth, $stream, &$remote) {
                        // 用户名和密码=>验证

                        // 远程URI中前缀用户名/密码
                        if ($remote !== null) {
                            $remote = str_replace('://', '://' . rawurlencode($username) . ':' . rawurlencode($password) . '@', $remote);
                        }

                        return $auth($username, $password, $remote)->then(function ($authenticated) use ($stream) {
                            if ($authenticated) {
                                // 接受认证
                                $stream->write(pack('C2', 0x01, 0x00));
                            } else {
                                // 拒绝auth =>发送任何代码除了0x00
                                $stream->end(pack('C2', 0x01, 0xFF));
                                throw new UnexpectedValueException('身份认证被拒绝');
                            }
                        }, function ($e) use ($stream) {
                            // 拒绝验证失败=>发送除0x00之外的任何代码
                            $stream->end(pack('C2', 0x01, 0xFF));
                            throw new UnexpectedValueException('身份认证错误', 0, $e);
                        });
                    });
                });
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
        })->then(function ($target) use ($that, $stream) {
            return $that->connectTarget($stream, $target); // 连接目标地址
        }, function($error) use ($stream) {
            throw new UnexpectedValueException('SOCKS5协议错误', $error->getCode(), $error);
        })->then(function (ConnectionInterface $remote) use ($stream) {
            // 服务器获取远程响应后回应客户端连接
            $stream->write(pack('C4Nn', 0x05, 0x00, 0x00, 0x01, 0, 0));

            return $remote; // 返回
        }, function(Exception $error) use ($stream){
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

        echo PHP_EOL.'diaomao send request '.$uri;

        $connecting = $this->connector->connect($uri);

        $stream->on('close', function () use ($connecting) {
            $connecting->cancel();
        });
        // socks连接成功后就是数据转发
        return $connecting->then(function (ConnectionInterface $remote) use ($stream, $that, $uri) {

            // 监听管道是否返回数据
            $stream->on('pipe', function() use ($uri){
                echo PHP_EOL.' diaomao accept '.$uri. ' response.....';
            });

            // $stream连接为客户端与服务端连接；$remote连接为服务端与远程请求资源连接，它们之间建立管道
            // 如果是本地服务端，则$remote发送数据需要加密，如果是远程服务端，则$remote发送数据需要解密
            $des = new DES('diaomao');
            $encrypt = new ThroughStream(function($data) use($des){
                //return $des->encrypt($data);
                return $data;
            });
            $decrypt = new ThroughStream(function($data) use($des) {
                //return $des->decrypt($data);
                return $data;
            });

            $encrypt->on('data', function($data) {

            });

            $decrypt->on('data', function($data) {

            });

            if(defined('IS_LOCAL') && IS_LOCAL) { // 本地服务端

                $stream->pipe($encrypt, array('end'=>false))->pipe($remote, array('end'=>false));
                $remote->pipe($decrypt, array('end'=>false))->pipe($stream, array('end'=>false));

            } else { // 远程服务端

                $stream->pipe($decrypt, array('end'=>false))->pipe($remote, array('end'=>false));
                $remote->pipe($encrypt, array('end'=>false))->pipe($stream, array('end'=>false));

            }

            //$stream->pipe($remote, array('end'=>false));
            // 如果是本地服务端，则$stream获取数据需要解密，如果是远程服务端，则$stream获取数据需要加密
            //$remote->pipe($stream, array('end'=>false));

            // 远程端关闭连接=>从本端停止读取，尝试将缓冲区刷新到本地并断开本地连接
            $remote->on('end', function() use ($stream, $that) {
                $that->endConnection($stream);
            });

            // 本地端关闭连接=>停止从远程端读取，尝试将缓冲区刷新到远程并断开远程连接
            $stream->on('end', function() use ($remote, $that) {
                $that->endConnection($remote);
            });

            // 设置更大的缓冲区大小为100k以提高性能
            $stream->bufferSize = $remote->bufferSize = 100 * 1024 * 1024;

            return $remote;
        }, function(Exception $error) {

            // 默认为一般/未知错误
            $code = Server::ERROR_GENERAL;

            // 将常见套接字错误条件映射到SOCKS错误代码的有限列表
            if ((defined('SOCKET_EACCES') && $error->getCode() === SOCKET_EACCES) || $error->getCode() === 13) {
                $code = Server::ERROR_NOT_ALLOWED_BY_RULESET;
            } elseif ((defined('SOCKET_EHOSTUNREACH') && $error->getCode() === SOCKET_EHOSTUNREACH) || $error->getCode() === 113) {
                $code = Server::ERROR_HOST_UNREACHABLE;
            } elseif ((defined('SOCKET_ENETUNREACH') && $error->getCode() === SOCKET_ENETUNREACH) || $error->getCode() === 101) {
                $code = Server::ERROR_NETWORK_UNREACHABLE;
            } elseif ((defined('SOCKET_ECONNREFUSED') && $error->getCode() === SOCKET_ECONNREFUSED) || $error->getCode() === 111 || $error->getMessage() === 'Connection refused') {
                //套接字组件当前没有为此分配错误代码，因此我们不得不求助于检查异常消息
                $code = Server::ERROR_CONNECTION_REFUSED;
            } elseif ((defined('SOCKET_ETIMEDOUT') && $error->getCode() === SOCKET_ETIMEDOUT) || $error->getCode() === 110 || $error instanceof TimeoutException) {
                // 套接字组件当前没有为此分配错误代码，但我们可以依赖于TimeoutException
                $code = Server::ERROR_TTL;
            }

            throw new UnexpectedValueException('无法连接到远程目标', $code, $error);
        });
    }
}
