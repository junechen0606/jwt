<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-14 14:35:05
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-14 14:53:17
 * 
 */
declare(strict_types=1);

namespace June\JWT\Hmac;

use June\JWT\Hmac;

final class Sha512 extends Hmac
{

    public function algorithm(): string
    {
        return 'sha512';
    }

    public function minimumBitsLengthForKey(): int
    {
        return 512;
    }
}
