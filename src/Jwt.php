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

class Jwt
{
    private static $instance;

    /**
     * @param mixed ...$args
     * @return static
     */
    static function getInstance(...$args)
    {
        if (!isset(static::$instance)) {
            static::$instance = new static(...$args);
        }
        return static::$instance;
    }

    public function token(Config $config): array
    {
        $headersString = $this->encodeHeaders($config);
        $claimsString = $this->encodeClaims($config);
        $signatureString = $this->encodeSignature($config, $headersString, $claimsString);
        return [
            $headersString,
            $claimsString,
            $signatureString,
        ];
    }

    private function encodeHeaders(Config $config): string
    {
        return base64_encode(json_encode($config->getHeaders()));
    }

    private function encodeClaims(Config $config): string
    {
        return base64_encode(json_encode($config->getClaims()));
    }

    private function encodeSignature(Config $config, string $headersString, string $claimsString): string
    {
        $hmac = $config->getHmac();
        $class = "\June\JWT\Hmac\\" . ucfirst($hmac);
        if (!class_exists($class)) {
            throw new JwtException('The encryption mode does not support');
        }
        return base64_encode((new $class())->sign($headersString . $claimsString, $config->getKey()));
    }
}
