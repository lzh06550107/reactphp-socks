<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/11
 * Time: 15:06
 */

namespace lzhsocket\Socks;


class AesDecryptingStream
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
        CipherMethod $cipherMethod
    ) {
        $this->stream = $stream;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    private function unpadding($ciphertext)
    {
        $chr = substr($ciphertext, -1);
        $padding = ord($chr);

        if($padding > strlen($ciphertext))
        {
            return false;
        }
        if(strspn($ciphertext, $chr, -1 * $padding, $padding) !== $padding)
        {
            return false;
        }

        return substr($ciphertext, 0, -1 * $padding);
    }
    
    public function decrypt($cipherText) {
        $this->buffer .= $cipherText;

        if(strlen($this->buffer) < self::BLOCK_SIZE ){
            return; // 如果不是流末尾且长度不够，则只记录，不处理
        } else { // 长度足够，则截取指定长度传输
            $index = strlen($this->buffer)%self::BLOCK_SIZE;
            $cipherText = substr($this->buffer, 0, -$index);
            $this->buffer = substr($this->buffer, -$index);
        }

        $options = OPENSSL_RAW_DATA | OPENSSL_NO_PADDING;

        $plaintext = openssl_decrypt(
            $cipherText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv()
        );

        $plaintext = $plaintext ? $this->unpadding($plaintext) : false; // 清除填充

        $this->cipherMethod->update($cipherText);

        return $plaintext;

    }
}