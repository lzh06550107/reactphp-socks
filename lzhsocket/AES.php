<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/11
 * Time: 15:18
 */

namespace lzhsocket\Socks;

/**
 * AES,高级加密标准（英语：Advanced Encryption Standard，缩写：AES），在密码学中又称Rijndael加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。严格地说，AES的区块长度固定为128 比特，密钥长度则可以是128，192或256比特，包括AES-ECB,AES-CBC,AES-CTR,AES-OFB,AES-CFB
 *
 * 这个流加密方法有个缺点，只能进行固定长度的分段加密，加密效率低
 * @package lzhsocket\Socks
 */

class AES
{
    const BLOCK_SIZE = 16; // 128 bits
    
    private $key;
    private $method = 'aes-256-cbc';
    private $length = 128;
    private $decrypt_buffer = '';
    private $encrypt_buffer = '';

    public function __construct($key)
    {
        // 是否启用了openssl扩展
        extension_loaded('openssl') or die('未启用 OPENSSL 扩展');
        $this->key = $key;
    }

    public function encrypt($plaintext)
    {

        if (!in_array($this->method, openssl_get_cipher_methods())) {
            die('不支持该加密算法!');
        }

        $this->encrypt_buffer .= $plaintext;

        $result = '';

        do {
            $plaintext = substr($this->encrypt_buffer, 0, self::BLOCK_SIZE-1);

            // 获取加密算法要求的初始化向量的长度
            $ivlen = openssl_cipher_iv_length($this->method);
            // 生成对应长度的初始化向量
            $iv = openssl_random_pseudo_bytes($ivlen);
            $iv_len = strlen($iv);
            // 加密数据
            $ciphertext = openssl_encrypt($plaintext, $this->method, $this->key, OPENSSL_RAW_DATA, $iv);
            $ciphertext_len = strlen($ciphertext);
            $hmac = hash_hmac('sha256', $ciphertext, $this->key, false);
            $hmac_len = strlen($hmac);
            $temp = base64_encode($iv . $hmac . $ciphertext);
            $result_len = strlen($temp);

            $result .= $temp;

            $this->encrypt_buffer = substr($this->encrypt_buffer, self::BLOCK_SIZE-1); // 减1是为了让分组长度非整数倍，从而不引起分组填充
            $len = strlen($this->encrypt_buffer);
        } while($len > 0);

        return $result;
    }

    public function decrypt($ciphertext)
    {
        $this->decrypt_buffer.= $ciphertext;

        $len = strlen($this->decrypt_buffer);
        if( $len < $this->length)  {
            return '';
        }

        $result = '';

        do {
            $ciphertext = substr($this->decrypt_buffer, 0, $this->length);

            $ciphertext = base64_decode($ciphertext);
            $ivlen = openssl_cipher_iv_length($this->method);
            $iv = substr($ciphertext, 0, $ivlen);
            $hmac = substr($ciphertext, $ivlen, 64);
            $ciphertext = substr($ciphertext, $ivlen + 64);
            $verifyHmac = hash_hmac('sha256', $ciphertext, $this->key, false);
            $this->decrypt_buffer = substr($this->decrypt_buffer, $this->length);
            $len = strlen($this->decrypt_buffer);
            if(hash_equals($hmac, $verifyHmac)) {
                $plaintext = openssl_decrypt($ciphertext, $this->method, $this->key, OPENSSL_RAW_DATA, $iv)??false;
                if($plaintext) {
                    $result .= $plaintext;
                }
            } else {
                echo('数据被修改!');
            }

        } while($len >= $this->length);

        return $result;
    }

}

//$plaintext = '0123456789ABCDE';
//$des = new AES('diaomao');
//$result = $des->encrypt($plaintext);
//print $result.PHP_EOL;
//print $des->decrypt($result);