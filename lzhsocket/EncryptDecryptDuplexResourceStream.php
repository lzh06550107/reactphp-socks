<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/11
 * Time: 12:50
 */

namespace lzhsocket\Socks;


use Evenement\EventEmitter;
use InvalidArgumentException;
use React\EventLoop\LoopInterface;
use React\Stream\DuplexStreamInterface;
use React\Stream\Util;
use React\Stream\WritableResourceStream;
use React\Stream\WritableStreamInterface;

class EncryptDecryptDuplexResourceStream  extends EventEmitter implements DuplexStreamInterface
{
    private $stream;
    private $loop;

    /**
     * Controls the maximum buffer size in bytes to read at once from the stream.
     *
     * This can be a positive number which means that up to X bytes will be read
     * at once from the underlying stream resource. Note that the actual number
     * of bytes read may be lower if the stream resource has less than X bytes
     * currently available.
     *
     * This can be `-1` which means read everything available from the
     * underlying stream resource.
     * This should read until the stream resource is not readable anymore
     * (i.e. underlying buffer drained), note that this does not neccessarily
     * mean it reached EOF.
     *
     * @var int
     */
    private $bufferSize;
    private $buffer;

    private $readable = true;
    private $writable = true;
    private $closing = false;
    private $listening = false;

    public function __construct($stream, LoopInterface $loop, $readChunkSize = null, WritableStreamInterface $buffer = null)
    {
        if (!\is_resource($stream) || \get_resource_type($stream) !== "stream") {
            throw new InvalidArgumentException('First parameter must be a valid stream resource');
        }

        $meta = \stream_get_meta_data($stream);
        if (isset($meta['mode']) && $meta['mode'] !== '' && \strpos($meta['mode'], '+') === false) {
            throw new InvalidArgumentException('Given stream resource is not opened in read and write mode');
        }

        if ($buffer === null) {
            $buffer = new WritableResourceStream($stream, $loop);
        }

        $this->stream = $stream;
        $this->loop = $loop;
        $this->bufferSize = ($readChunkSize === null) ? 65536 : (int)$readChunkSize;
        $this->buffer = $buffer;

        $that = $this;

        // 写入流发生错误，则传递错误事件给全双工流
        $this->buffer->on('error', function ($error) use ($that) {
            $that->emit('error', array($error));
        });

        $this->buffer->on('close', array($this, 'close'));

        $this->buffer->on('drain', function () use ($that) { // 写入流空事件
            $that->emit('drain');
        });

        $this->resume();
    }

    public function isReadable()
    {
        return $this->readable;
    }

    public function isWritable()
    {
        return $this->writable;
    }

    public function pause()
    {
        if ($this->listening) {
            $this->loop->removeReadStream($this->stream);
            $this->listening = false;
        }
    }

    public function resume()
    {
        if (!$this->listening && $this->readable) { // 还未监听且可读，则加入事件循环中
            $this->loop->addReadStream($this->stream, array($this, 'handleData'));
            $this->listening = true;
        }
    }

    public function write($data)
    {
        if (!$this->writable) {
            return false;
        }

        // TODO 对写入的数据进行加密


        return $this->buffer->write($data);
    }

    public function close()
    {
        if (!$this->writable && !$this->closing) {
            return;
        }

        $this->closing = false;

        $this->readable = false;
        $this->writable = false;

        $this->emit('close'); // 发出关闭时间
        $this->pause(); // 暂停读取数据
        $this->buffer->close(); // 关闭写入流
        $this->removeAllListeners(); // 移除所有监听器

        if (\is_resource($this->stream)) {
            \fclose($this->stream); // 关闭底层流
        }
    }

    public function end($data = null)
    {
        if (!$this->writable) {
            return;
        }

        $this->closing = true;

        $this->readable = false;
        $this->writable = false;
        $this->pause();

        $this->buffer->end($data);
    }

    public function pipe(WritableStreamInterface $dest, array $options = array())
    {
        return Util::pipe($this, $dest, $options);
    }

    /** @internal */
    public function handleData($stream)
    {
        $error = null;
        \set_error_handler(function ($errno, $errstr, $errfile, $errline) use (&$error) {
            $error = new \ErrorException(
                $errstr,
                0,
                $errno,
                $errfile,
                $errline
            );
        });

        $data = \stream_get_contents($stream, $this->bufferSize); // 读取指定长度的内容

        \restore_error_handler();

        if ($error !== null) { // 如果读取出错，则关闭当前流
            $this->emit('error', array(new \RuntimeException('Unable to read from stream: ' . $error->getMessage(), 0, $error)));
            $this->close();
            return;
        }

        // TODO 对读取的数据进行解密

        if ($data !== '') { // 如果获取数据，则触发数据事件
            $this->emit('data', array($data));
        } elseif (\feof($this->stream)) { // 如果读完数据，则触发end事件并关闭流
            // no data read => we reached the end and close the stream
            $this->emit('end');
            $this->close();
        }
    }

    /**
     * Returns whether this is a pipe resource in a legacy environment
     *
     * This works around a legacy PHP bug (#61019) that was fixed in PHP 5.4.28+
     * and PHP 5.5.12+ and newer.
     *
     * @param resource $resource
     * @return bool
     * @link https://github.com/reactphp/child-process/issues/40
     *
     * @codeCoverageIgnore
     */
    private function isLegacyPipe($resource)
    {
        if (\PHP_VERSION_ID < 50428 || (\PHP_VERSION_ID >= 50500 && \PHP_VERSION_ID < 50512)) {
            $meta = \stream_get_meta_data($resource);

            if (isset($meta['stream_type']) && $meta['stream_type'] === 'STDIO') {
                return true;
            }
        }
        return false;
    }
}