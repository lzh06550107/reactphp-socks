<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/12
 * Time: 17:58
 */

namespace lzhsocket\Socks;


class XCHACHA20POLY1305
{


    const CHUNK_SIZE = 4096;
    const ALG = SODIUM_CRYPTO_PWHASH_ALG_DEFAULT;
    const OPSLIMIT = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    const MEMLIMIT = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
    private $password;
    private $salt;
    private $secret_key;

    public function __construct($password)
    {
        $this->password = $password;
        $this->salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $this->secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
            $password, $this->salt, OPSLIMIT, MEMLIMIT, ALG);
    }

    public function encrypt() {

    }


    public function decrypt() {

    }

}