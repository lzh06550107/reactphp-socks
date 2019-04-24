<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/7
 * Time: 15:33
 */

namespace Clue\React\Socks;


class DES
{
    private $method = 'DES-CBC';
    private $key;

    public function __construct($password)
    {
        // 密钥长度不能超过64bit(UTF-8下为8个字符长度),超过64bit不会影响程序运行,但有效使用的部分只有64bit,多余部分无效,可通过openssl_error_string()查看错误提示
        $this->key = hash('sha256', $password, true);
    }

    public function encrypt($plaintext)
    {
        // 生成加密所需的初始化向量, 加密时缺失iv会抛出一个警告
        $ivlen = openssl_cipher_iv_length($this->method);
        $iv = openssl_random_pseudo_bytes($ivlen);

        // 按64bit一组填充明文
        $plaintext = $this->padding($plaintext);
        // 加密数据
        $ciphertext = openssl_encrypt($plaintext, $this->method, $this->key, 1, $iv);
        // 生成hash
        $hash = hash_hmac('sha256', $ciphertext, $this->key, false);

        return base64_encode($iv . $hash . $ciphertext);

    }

    public function decrypt($ciphertext)
    {
        $ciphertext = base64_decode($ciphertext);
        // 从密文中获取iv
        $ivlen = openssl_cipher_iv_length($this->method);
        $iv = substr($ciphertext, 0, $ivlen);
        // 从密文中获取hash
        $hash = substr($ciphertext, $ivlen, 64);
        // 获取原始密文
        $ciphertext = substr($ciphertext, $ivlen + 64);
        // hash校验
        if(hash_equals($hash, hash_hmac('sha256', $ciphertext, $this->key, false)))
        {
            // 解密数据
            $ciphertext = openssl_decrypt($ciphertext, $this->method, $this->key, 1, $iv) ?? false;
            // 去除填充数据
            $plaintext = $ciphertext ? $this->unpadding($ciphertext) : false;

            return $plaintext;
        }

        return '解密失败';
    }

    // 按64bit一组填充数据
    private function padding($plaintext)
    {
        $padding = 8 - (strlen($plaintext)%8);
        $chr = chr($padding);

        return $plaintext . str_repeat($chr, $padding);
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
}

//$plaintext = '叼毛测试';
//$des = new DES('diaomao');
//$result = $des->encrypt($plaintext);
//print $result;
//print $des->decrypt($result);