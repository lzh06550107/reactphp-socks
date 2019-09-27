<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2019/4/7
 * Time: 15:30
 */

namespace Clue\React\Socks;


use React\Stream\ThroughStream;

class Utils
{

    public static function pipe( $source) {
        $middle = new ThroughStream(function($data) use($source){

            if(strlen($data))

            if(!$source->isReadable()) { // 如果源已经读取数据，则发送剩余的数据

            }
        });
    }
}