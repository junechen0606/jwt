<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-14 14:35:05
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-14 14:52:37
 * 
 */

declare(strict_types=1);

namespace June\JWT;

use function hash_equals;
use function hash_hmac;
use function strlen;

abstract class Hmac
{
    final public function sign(string $payload, string $key): string
    {
        $actualKeyLength   = 8 * strlen($key);
        $expectedKeyLength = $this->minimumBitsLengthForKey();
        if ($actualKeyLength < $expectedKeyLength) {
            throw new  JwtException('Key provided is shorter than ' . $expectedKeyLength . ' bits,'
                . ' only ' . $actualKeyLength . ' bits provided');
        }
        return hash_hmac($this->algorithm(), $payload, $key, true);
    }

    final public function verify(string $expected, string $payload, string $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }

    abstract public function algorithm(): string;

    /** @return positive-int */
    abstract public function minimumBitsLengthForKey(): int;
}
