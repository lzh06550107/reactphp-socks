<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/9
 * Time: 17:27
 */

namespace lzhsocket\Socks;


use Clue\React\Socks\RC4;
use React\Socket\ConnectionInterface;
use React\Stream\WritableStreamInterface;

class EncryptDecryptConnection implements ConnectionInterface
{
    private $connection;
    private $encrypt;

    public function __construct(ConnectionInterface $connection, $encrypt = null)
    {
        $this->connection = $connection;
        $this->encrypt = $encrypt??new RC4('diaomao');
    }

    public function getRemoteAddress()
    {
        return $this->connection->getRemoteAddress();
    }

    public function getLocalAddress()
    {
        return $this->connection->getLocalAddress();
    }

    public function on($event, callable $listener)
    {
        // 对于读取事件，回调函数需要解密
        if($event == 'data') {
            $listener = function($data)  use($listener){
                // 调用解密函数进行解密
                $result = $this->encrypt->decrypt($data);
                return $listener($result);
            };
        }

        $this->connection->on($event, $listener);
    }

    public function once($event, callable $listener)
    {
        $this->connection->once($event, $listener);
    }

    public function removeListener($event, callable $listener)
    {
        $this->connection->removeListener($event, $listener);
    }

    public function removeAllListeners($event = null)
    {
        $this->connection->removeAllListeners($event);
    }

    public function listeners($event = null)
    {
        $this->connection->listeners($event);
    }

    public function emit($event, array $arguments = [])
    {
        $this->connection->emit($event, $arguments);
    }

    public function isReadable()
    {
        return $this->connection->isReadable();
    }

    public function pause()
    {
        $this->connection->pause();
    }

    public function resume()
    {
        $this->connection->resume();
    }

    public function pipe(WritableStreamInterface $dest, array $options = array())
    {
        return $this->connection->pipe($dest, $options);
    }

    public function close()
    {
        $this->connection->close();
    }

    public function isWritable()
    {
        return $this->connection->isWritable();
    }

    public function write($data)
    {
        // 写入数据需要加密
        $result = $this->encrypt->encrypt($data);
        return $this->connection->write($result);
    }

    public function end($data = null)
    {
        $this->connection->end($data);
    }
}