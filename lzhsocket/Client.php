<?php

namespace Clue\React\Socks;

use React\Promise;
use React\Promise\PromiseInterface;
use React\Promise\Deferred;
use React\Socket\ConnectionInterface;
use React\Socket\ConnectorInterface;
use React\Socket\FixedUriConnector;
use \Exception;
use \InvalidArgumentException;
use RuntimeException;

final class Client implements ConnectorInterface
{
    /**
     *
     * @var ConnectorInterface
     */
    private $connector;

    private $socksUri;

    private $protocolVersion = 5;

    private $auth = null; // 认证用户名称和密码

    public function __construct($socksUri, ConnectorInterface $connector)
    {
        // 支持 `sockss://` SOCKS over TLS
        // 支持 `socks+unix://`  Unix domain socket (UDS) 路径
        if (preg_match('/^(socks(?:5|4)?)(s|\+unix):\/\/(.*?@)?(.+?)$/', $socksUri, $match)) {
            // rewrite URI to parse SOCKS scheme, authentication and dummy host
            $socksUri = $match[1] . '://' . $match[3] . 'localhost';

            // connector uses appropriate transport scheme and explicit host given
            $connector = new FixedUriConnector(
                ($match[2] === 's' ? 'tls://' : 'unix://') . $match[4],
                $connector
            );
        }

        // 默认协议
        if (strpos($socksUri, '://') === false) {
            $socksUri = 'socks://' . $socksUri;
        }

        // 解析 URI
        $parts = parse_url($socksUri);
        if (!$parts || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('无效的 SOCKS 服务 URI "' . $socksUri . '"');
        }

        // 默认端口
        if (!isset($parts['port'])) {
            $parts['port'] = 1080;
        }

        // URI => SOCKS5 身份认证中的用户和密码
        if (isset($parts['user']) || isset($parts['pass'])) {
            if ($parts['scheme'] !== 'socks' && $parts['scheme'] !== 'socks5') {
                // 如果明确给出任何其他协议版本则失败
                throw new InvalidArgumentException('身份验证需要SOCKS5。 考虑使用协议版本5或放弃身份验证。');
            }
            $parts += array('user' => '', 'pass' => '');
            $this->setAuth(rawurldecode($parts['user']), rawurldecode($parts['pass']));
        }

        // 从URI检查有效的协议版本
        $this->setProtocolVersionFromScheme($parts['scheme']);

        $this->socksUri = $parts['host'] . ':' . $parts['port'];
        $this->connector = $connector;
    }

    private function setProtocolVersionFromScheme($scheme)
    {
        if ($scheme === 'socks' || $scheme === 'socks5') {
            $this->protocolVersion = 5;
        } elseif ($scheme === 'socks4') {
            $this->protocolVersion = 4;
        } else {
            throw new InvalidArgumentException('无效的协议 "' . $scheme . '://"');
        }
    }

    /**
     * 设置用户名/密码验证方法的登录数据(RFC1929)
     *
     * @param string $username
     * @param string $password
     * @link http://tools.ietf.org/html/rfc1929
     */
    private function setAuth($username, $password)
    {
        if (strlen($username) > 255 || strlen($password) > 255) {
            throw new InvalidArgumentException('用户名和密码不得超过每个255字节的长度');
        }
        $this->auth = pack('C2', 0x01, strlen($username)) . $username . pack('C', strlen($password)) . $password;
    }

    /**
     * 通过SOCKS服务器建立与给定目标URI的TCP / IP连接
     *
     * 许多更高级别的网络协议都建立在TCP之上。 你正在处理一个这样的客户端实现，它可能使用/接受实现ReactPHP的`ConnectorInterface`的实例（通常是它的默认`Connector`实例）。 在这种情况下，您也可以传递此“Connector”实例而不是实现SOCKS相关接口。
     *
     * @param string $uri
     * @return PromiseInterface Promise<ConnectionInterface,Exception>
     */
    public function connect($uri)
    {
        if (strpos($uri, '://') === false) {
            $uri = 'tcp://' . $uri;
        }

        $parts = parse_url($uri);
        if (!$parts || !isset($parts['scheme'], $parts['host'], $parts['port']) || $parts['scheme'] !== 'tcp') {
            return Promise\reject(new InvalidArgumentException('指定的目标URI无效'));
        }

        $host = trim($parts['host'], '[]');
        $port = $parts['port'];

        if (strlen($host) > 255 || $port > 65535 || $port < 0 || (string)$port !== (string)(int)$port) {
            return Promise\reject(new InvalidArgumentException('指定的目标无效'));
        }

        // 构造要连接的SOCKS服务器的URI
        $socksUri = $this->socksUri;

        // 如果给出，则从URI追加路径
        if (isset($parts['path'])) {
            $socksUri .= $parts['path'];
        }

        // 解析查询参数
        $args = array();
        if (isset($parts['query'])) {
            parse_str($parts['query'], $args);
        }

        // 除非明确给出，否则将URI中的主机名附加到查询字符串
        if (!isset($args['hostname'])) {
            $args['hostname'] = $host;
        }

        // 追加查询字符串
        $socksUri .= '?' . http_build_query($args, '', '&');

        // 如果给出，则从URI追加片段
        if (isset($parts['fragment'])) {
            $socksUri .= '#' . $parts['fragment'];
        }

        // 启动到SOCKS服务器的TCP / IP连接
        $connecting = $this->connector->connect($socksUri);

        $deferred = new Deferred(function ($_, $reject) use ($uri, $connecting) {
            $reject(new RuntimeException(
                '在等待代理（ECONNABORTED）时连接到 ' . $uri . ' 被取消',
                defined('SOCKET_ECONNABORTED') ? SOCKET_ECONNABORTED : 103
            ));

            // 关闭活动连接或取消挂起连接尝试
            $connecting->then(function (ConnectionInterface $stream) {
                $stream->close();
            });
            $connecting->cancel();
        });

        // 连接准备就绪后处理SOCKS协议
        // SOCKS协议完成后解析普通连接
        $that = $this;
        $connecting->then(
            function (ConnectionInterface $stream) use ($that, $host, $port, $deferred, $uri) {
                $that->handleConnectedSocks($stream, $host, $port, $deferred, $uri);
            },
            function (Exception $e) use ($uri, $deferred) {
                $deferred->reject($e = new RuntimeException(
                    '连接到 ' . $uri . ' 失败，因为连接到代理失败 (ECONNREFUSED)',
                    defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111,
                    $e
                ));

                // 通过替换调用堆栈中的所有闭包来避免垃圾引用。
                $r = new \ReflectionProperty('Exception', 'trace');
                $r->setAccessible(true);
                $trace = $r->getValue($e);
                foreach ($trace as &$one) {
                    foreach ($one['args'] as &$arg) {
                        if ($arg instanceof \Closure) {
                            $arg = 'Object(' . get_class($arg) . ')';
                        }
                    }
                }
                $r->setValue($e, $trace);
            }
        );

        return $deferred->promise();
    }

    /**
     * 用于处理与SOCKS服务器通信的内部帮助程序
     *
     * @param ConnectionInterface $stream
     * @param string              $host
     * @param int                 $port
     * @param Deferred            $deferred
     * @param string              $uri
     * @return void
     * @internal
     */
    public function handleConnectedSocks(ConnectionInterface $stream, $host, $port, Deferred $deferred, $uri)
    {
        $reader = new StreamReader();
        $stream->on('data', array($reader, 'write')); // 如果流存在可读数据，则写入到StreamReader中

        // 如果流存在错误，则发出拒绝
        $stream->on('error', $onError = function (Exception $e) use ($deferred, $uri) {
            $deferred->reject(new RuntimeException(
                '连接到 ' . $uri . ' 失败，因为连接到代理引起一个流错误(EIO)',
                defined('SOCKET_EIO') ? SOCKET_EIO : 5, $e)
            );
        });

        // 如果流关闭，则发出拒绝
        $stream->on('close', $onClose = function () use ($deferred, $uri) {
            $deferred->reject(new RuntimeException(
                '连接到 ' . $uri . ' 失败，因为当等待代理响应时连接丢失(ECONNRESET)',
                defined('SOCKET_ECONNRESET') ? SOCKET_ECONNRESET : 104)
            );
        });

        if ($this->protocolVersion === 5) { // 处理sockes5协议
            $promise = $this->handleSocks5($stream, $host, $port, $reader, $uri);
        } else {
            $promise = $this->handleSocks4($stream, $host, $port, $reader, $uri);
        }

        $promise->then(function () use ($deferred, $stream, $reader, $onError, $onClose) {
            $stream->removeListener('data', array($reader, 'write')); // 清楚socks协议交互帮助工具
            $stream->removeListener('error', $onError);
            $stream->removeListener('close', $onClose);

            $deferred->resolve($stream);
        }, function (Exception $error) use ($deferred, $stream, $uri) {
            // 通过原样传递自定义RuntimeException
            if (!$error instanceof RuntimeException) {
                $error = new RuntimeException(
                    '连接到 ' . $uri . ' 失败，因为代理返回无效响应 (EBADMSG)',
                    defined('SOCKET_EBADMSG') ? SOCKET_EBADMSG: 71,
                    $error
                );
            }

            $deferred->reject($error);
            $stream->close();
        });
    }

    private function handleSocks4(ConnectionInterface $stream, $host, $port, StreamReader $reader, $uri)
    {
        // 不解析主机名。 只尝试转换为IP
        $ip = ip2long($host);

        // 发送IP或如果无效（0.0.0.1）
        $data = pack('C2nNC', 0x04, 0x01, $port, $ip === false ? 1 : $ip, 0x00);

        if ($ip === false) {
            // 主机不是有效的IP =>沿主机名发送（SOCKS4a）
            $data .= $host . pack('C', 0x00);
        }

        $stream->write($data);

        return $reader->readBinary(array(
            'null'   => 'C',
            'status' => 'C',
            'port'   => 'n',
            'ip'     => 'N'
        ))->then(function ($data) use ($uri) {
            if ($data['null'] !== 0x00) {
                throw new Exception('SOCKS响应无效');
            }
            if ($data['status'] !== 0x5a) {
                throw new RuntimeException(
                    '连接到 ' . $uri . ' 失败，因为代理拒绝连接 ' . sprintf('0x%02X', $data['status']) . ' (ECONNREFUSED)',
                    defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                );
            }
        });
    }

    private function handleSocks5(ConnectionInterface $stream, $host, $port, StreamReader $reader, $uri)
    {
        // 协议版本5
        $data = pack('C', 0x05);

        $auth = $this->auth; // 连接授权
        if ($auth === null) {
            // 一种方法，即没有认证
            $data .= pack('C2', 0x01, 0x00);
        } else {
            // 两种方法，用户名/密码和没有认证
            $data .= pack('C3', 0x02, 0x02, 0x00);
        }
        $stream->write($data); // 发送协商请求

        $that = $this;

        return $reader->readBinary(array(
            'version' => 'C',
            'method'  => 'C'
        ))->then(function ($data) use ($auth, $stream, $reader, $uri) { // 读取协商响应并传入
            if ($data['version'] !== 0x05) {
                throw new Exception('版本/协议不匹配');
            }

            if ($data['method'] === 0x02 && $auth !== null) {
                // 请求并提供用户名/密码验证
                $stream->write($auth);

                return $reader->readBinary(array(
                    'version' => 'C',
                    'status'  => 'C'
                ))->then(function ($data) use ($uri) {
                    if ($data['version'] !== 0x01 || $data['status'] !== 0x00) {
                        throw new RuntimeException(
                            '连接到 ' . $uri . ' 失败，因为给定的身份认证信息而拒绝访问 (EACCES)',
                            defined('SOCKET_EACCES') ? SOCKET_EACCES : 13
                        );
                    }
                });
            } else if ($data['method'] !== 0x00) {
                // 除“无认证”之外的任何其他方法
                throw new RuntimeException(
                    '连接到 ' . $uri . ' 失败，因为不支持的身份验证方法代理拒绝访问 (EACCES)',
                    defined('SOCKET_EACCES') ? SOCKET_EACCES : 13
                );
            }
        })->then(function () use ($stream, $reader, $host, $port) {
            // 不解析主机名。 只尝试转换为（二进制/包）IP
            $ip = @inet_pton($host);

            $data = pack('C3', 0x05, 0x01, 0x00);
            if ($ip === false) {
                // 不是IP，作为主机名发送
                $data .= pack('C2', 0x03, strlen($host)) . $host;
            } else {
                // 发送 IPv4 / IPv6
                $data .= pack('C', (strpos($host, ':') === false) ? 0x01 : 0x04) . $ip;
            }
            $data .= pack('n', $port);

            $stream->write($data); // 发起连接请求

            return $reader->readBinary(array(
                'version' => 'C',
                'status'  => 'C',
                'null'    => 'C',
                'type'    => 'C'
            ));
        })->then(function ($data) use ($reader, $uri) {
            if ($data['version'] !== 0x05 || $data['null'] !== 0x00) {
                throw new Exception('SOCKS响应无效');
            }
            if ($data['status'] !== 0x00) {
                // 将有限的SOCKS错误代码列表映射到常见的套接字错误条件
                // @link https://tools.ietf.org/html/rfc1928#section-6
                if ($data['status'] === Server::ERROR_GENERAL) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为一般服务器故障，代理拒绝连接 (ECONNREFUSED)',
                        defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                    );
                } elseif ($data['status'] === Server::ERROR_NOT_ALLOWED_BY_RULESET) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为代理因规则集而拒绝访问 (EACCES)',
                        defined('SOCKET_EACCES') ? SOCKET_EACCES : 13
                    );
                } elseif ($data['status'] === Server::ERROR_NETWORK_UNREACHABLE) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为代理报告网络无法访问 (ENETUNREACH)',
                        defined('SOCKET_ENETUNREACH') ? SOCKET_ENETUNREACH : 101
                    );
                } elseif ($data['status'] === Server::ERROR_HOST_UNREACHABLE) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为代理报告主机无法访问 (EHOSTUNREACH)',
                        defined('SOCKET_EHOSTUNREACH') ? SOCKET_EHOSTUNREACH : 113
                    );
                } elseif ($data['status'] === Server::ERROR_CONNECTION_REFUSED) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' failed because proxy reported connection refused (ECONNREFUSED)',
                        defined('SOCKET_ECONNREFUSED') ? SOCKET_ECONNREFUSED : 111
                    );
                } elseif ($data['status'] === Server::ERROR_TTL) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为代理报告TTL /超时已过期 (ETIMEDOUT)',
                        defined('SOCKET_ETIMEDOUT') ? SOCKET_ETIMEDOUT : 110
                    );
                } elseif ($data['status'] === Server::ERROR_COMMAND_UNSUPPORTED) {
                    throw new RuntimeException(
                        '连接到 ' . $uri . ' 失败，因为代理不支持CONNECT命令 (EPROTO)',
                        defined('SOCKET_EPROTO') ? SOCKET_EPROTO : 71
                    );
                } elseif ($data['status'] === Server::ERROR_ADDRESS_UNSUPPORTED) {
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
        });
    }
}
