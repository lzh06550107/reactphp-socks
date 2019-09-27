<?php

namespace lzhsocket\Socks;

use React\Promise\Deferred;
use \InvalidArgumentException;
use \UnexpectedValueException;

/**
 * @internal
 */
final class StreamReader
{
    const RET_DONE = true;
    const RET_INCOMPLETE = null;

    private $buffer = '';
    private $queue = array();

    public function write($data)
    {

        $this->buffer .= $data;

        do {
            $current = reset($this->queue);

            if ($current === false) {
                break;
            }

            /* @var $current Closure */

            $ret = $current($this->buffer); // 回调

            if ($ret === self::RET_INCOMPLETE) {
                // 当前数据不完整，所以等待进一步的数据到达
                break;
            } else {
                // 当前已完成，从列表中删除并继续下一步
                array_shift($this->queue);
            }
        } while (true);
    }

    public function readBinary($structure)
    {
        $length = 0;
        $unpack = '';
        foreach ($structure as $name=>$format) {
            if ($length !== 0) {
                $unpack .= '/';
            }
            $unpack .= $format . $name;

            if ($format === 'C') {
                ++$length;
            } else if ($format === 'n') {
                $length += 2;
            } else if ($format === 'N') {
                $length += 4;
            } else {
                throw new InvalidArgumentException('给出的格式无效');
            }
        }

        return $this->readLength($length)->then(function ($response) use ($unpack) {
            return unpack($unpack, $response);
        });
    }

    public function readLength($bytes)
    {
        $deferred = new Deferred();
        // 读取METHODS 字段长度并返回该字段的值
        $this->readBufferCallback(function (&$buffer) use ($bytes, $deferred) { // 这里加入了回调队列
            if (strlen($buffer) >= $bytes) {
                $deferred->resolve((string)substr($buffer, 0, $bytes));
                $buffer = (string)substr($buffer, $bytes);

                return StreamReader::RET_DONE; // 读取到指定的长度
            }
        });

        return $deferred->promise();
    }

    public function readByte()
    {
        return $this->readBinary(array(
            'byte' => 'C'
        ))->then(function ($data) {
            return $data['byte'];
        });
    }

    public function readByteAssert($expect)
    {
        return $this->readByte()->then(function ($byte) use ($expect) {
            if ($byte !== $expect) {
                throw new UnexpectedValueException('遇到意外的字节');
            }
            return $byte;
        });
    }

    public function readStringNull()
    {
        $deferred = new Deferred();
        $string = '';

        $that = $this;
        $readOne = function () use (&$readOne, $that, $deferred, &$string) {
            $that->readByte()->then(function ($byte) use ($deferred, &$string, $readOne) {
                if ($byte === 0x00) {
                    $deferred->resolve($string);
                } else {
                    $string .= chr($byte);
                    $readOne();
                }
            });
        };
        $readOne();

        return $deferred->promise();
    }

    public function readBufferCallback(/* callable */ $callable)
    {
        if (!is_callable($callable)) {
            throw new InvalidArgumentException('给定函数必须是可调用的');
        }

        if ($this->queue) {
            $this->queue []= $callable;
        } else {
            $this->queue = array($callable);

            if ($this->buffer !== '') {
                // 这是队列中的第一个元素，缓冲区被填充=>触发写入过程
                $this->write('');
            }
        }
    }

    public function getBuffer()
    {
        return $this->buffer;
    }
}
