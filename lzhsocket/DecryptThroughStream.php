<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/9
 * Time: 19:30
 */

namespace lzhsocket\Socks;


use Clue\React\Socks\RC4;
use Evenement\EventEmitter;
use InvalidArgumentException;
use React\Stream\DuplexStreamInterface;
use React\Stream\Util;
use React\Stream\WritableStreamInterface;

/**
 * 对流进行解密
 * Class DecryptThroughStream
 * @package lzhsocket\Socks
 */
class DecryptThroughStream extends EventEmitter implements DuplexStreamInterface
{
    private $readable = true;
    private $writable = true;
    private $closed = false;
    private $paused = false;
    private $drain = false;
    private $callback;

    private $tool;

    public function __construct($callback = null)
    {
        if ($callback !== null && !\is_callable($callback)) {
            throw new InvalidArgumentException('Invalid transformation callback given');
        }

        $this->callback = $callback;

        $this->tool = new RC4('diaomao');
    }

    public function pause()
    {
        $this->paused = true;
    }

    public function resume()
    {
        if ($this->drain) {
            $this->drain = false;
            $this->emit('drain');
        }
        $this->paused = false;
    }

    public function pipe(WritableStreamInterface $dest, array $options = array())
    {
        return Util::pipe($this, $dest, $options);
    }

    public function isReadable()
    {
        return $this->readable;
    }

    public function isWritable()
    {
        return $this->writable;
    }

    public function write($data)
    {
        if (!$this->writable) {
            return false;
        }

        if ($this->tool !== null) {
            try {
                $data = $this->tool->decrypt($data);
            } catch (\Exception $e) {
                $this->emit('error', array($e));
                $this->close();

                return false;
            }
        }

        $this->emit('data', array($data));

        if ($this->paused) {
            $this->drain = true;
            return false;
        }

        return true;
    }

    public function end($data = null)
    {
        if (!$this->writable) {
            return;
        }

        if (null !== $data) {
            $this->write($data);

            // return if write() already caused the stream to close
            if (!$this->writable) {
                return;
            }
        }

        $this->readable = false;
        $this->writable = false;
        $this->paused = true;
        $this->drain = false;

        $this->emit('end');
        $this->close();
    }

    public function close()
    {
        if ($this->closed) {
            return;
        }

        $this->readable = false;
        $this->writable = false;
        $this->closed = true;
        $this->paused = true;
        $this->drain = false;
        $this->callback = null;

        $this->emit('close');
        $this->removeAllListeners();
    }
}