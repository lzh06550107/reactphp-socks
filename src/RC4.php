<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/9
 * Time: 15:43
 */

namespace Clue\React\Socks;


class RC4
{
    private $method = 'rc4';
    private $key;

    public function __construct($password)
    {
        $this->key = hash('sha256', $password, true);
    }

    public function encrypt($plaintext)
    {
        if($ciphertext = openssl_encrypt($plaintext, $this->method, $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING)) {
            return $ciphertext;
        }else {
            return 'encrypt fail';
        }
        // 生成hash
        //$hash = hash_hmac('sha256', $ciphertext, $this->key, false);

    }

    public function decrypt($ciphertext)
    {
        // 从密文中获取hash
        //$hash = substr($ciphertext, 0, 64);
        // 获取原始密文
       // $ciphertext = substr($ciphertext, 64);
            // 解密数据
            if($ciphertext = openssl_decrypt($ciphertext, $this->method, $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING)) {
                return $ciphertext;
            } else {
                return 'decrypt fail';
            }


    }

}

//$plaintext = '叼毛测试';
//$des = new RC4('diaomao');
//$result = $des->encrypt($plaintext);
//print $result.PHP_EOL;
//print $des->decrypt($result);