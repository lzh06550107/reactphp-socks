<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/5
 * Time: 12:11
 */

namespace Clue\React\Socks;


/**
 * 常用对称加密算法类
 * 支持密钥：64/128/256 bit（字节长度8/16/32）
 * 支持算法：DES/AES（根据密钥长度自动匹配使用：DES:64bit AES:128/256bit）
 * 支持模式：CBC/ECB/OFB/CFB
 * 密文编码：base64字符串/十六进制字符串/二进制字符串流
 * 填充方式: PKCS5Padding（DES）
 *
 * @author: linvo
 * @version: 1.0.0
 * @date: 2013/1/10
 */
class Xcrypt{


    // curve25519xsalsa20poly1305
    static function crypt25519($msg, $pwd)
    {
        try {
            $nonce=random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
        $key=sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_KEYPAIRBYTES,  $pwd, substr($nonce, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES), SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
        $crypt=sodium_crypto_box($msg, $nonce, $key);
        return base64_encode($nonce).':'.base64_encode($crypt);
    }
    static function decrypt25519($msg, $pwd)
    {
        list($nonce, $crypt)=explode(':', $msg);
        $nonce=base64_decode($nonce);
        $key=sodium_crypto_pwhash(SODIUM_CRYPTO_BOX_KEYPAIRBYTES,  $pwd, substr($nonce, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES), SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
        $crypt=base64_decode($crypt);
        $msg=sodium_crypto_box_open($crypt, $nonce, $key);
        return $msg;
    }

    static function encrypt($plaintext, $password) {
        $method = "AES-256-CBC";
        $key = hash('sha256', $password, true);
        $iv = openssl_random_pseudo_bytes(16);

        $ciphertext = openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv);
        $hash = hash_hmac('sha256', $ciphertext, $key, true);

        return $iv . $hash . $ciphertext;
    }

   static function decrypt($ivHashCiphertext, $password) {
        $method = "AES-256-CBC";
        $iv = substr($ivHashCiphertext, 0, 16);
        $hash = substr($ivHashCiphertext, 16, 32);
        $ciphertext = substr($ivHashCiphertext, 48);
        $key = hash('sha256', $password, true);

        if (hash_hmac('sha256', $ciphertext, $key, true) !== $hash) return null;

        return openssl_decrypt($ciphertext, $method, $key, OPENSSL_RAW_DATA, $iv);
    }


}

//$str = '叼毛';
//$password = 'test';
//$encode = Xcrypt::crypt25519($str, $password);
//echo $encode.PHP_EOL;
//$decode = Xcrypt::decrypt25519($encode, $password);
//echo $decode;