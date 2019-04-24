<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/11
 * Time: 13:48
 */

namespace lzhsocket\Socks;

class AesEncryptingStream
{

    const BLOCK_SIZE = 16; // 128 bits

    /**
     * @var string
     */
    private $buffer = '';
    /**
     * @var CipherMethod
     */
    private $cipherMethod;

    /**
     * @var string
     */
    private $key;

    private $stream;


    public function __construct(
        $stream,
        string $key,
         $cipherMethod
    ) {
        $this->stream = $stream;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    private function isPad($plainText)
    {
        $length = strlen($plainText);
        if ($this->cipherMethod->requiresPadding() && $length < self::BLOCK_SIZE) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks.
            $padding = self::BLOCK_SIZE - $length % self::BLOCK_SIZE;
            return $padding;
        }

        return false;
    }

    // 这里的加密特点是对整个一段数据流，需要在循环中读取流中所有数据
    public function encrypt($plainText) {
        $this->buffer .= $plainText; // $plainText是随时到来的数据块

        // 如果传入数据不够且到达流末尾，则填充
        if(strlen($this->buffer)  < self::BLOCK_SIZE && feof($this->stream)) { // feof表示底层数据流块读取结束，但流没有关闭
            if($len = $this->isPad($plainText)) { // 判断是否需要填充
                $chr = chr($len);
                $plainText = $this->buffer.str_repeat($chr, $len);
                $this->buffer = ''; // 清空临时缓冲区
            }
        } else if(strlen($this->buffer) < self::BLOCK_SIZE ){
          return; // 如果不是流末尾且长度不够，则只记录，不处理
        } else { // 长度足够，则截取指定长度加密传输
            $index = strlen($this->buffer)%self::BLOCK_SIZE;
            $plainText = substr($this->buffer, 0, -$index);
            $this->buffer = substr($this->buffer, -$index);
        }

        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;

        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv()
        );

        $this->cipherMethod->update($cipherText); // 链式加密方式

        return $cipherText;
    }
    
}