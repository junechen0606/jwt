<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-14 14:35:05
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-14 14:53:25
 * 
 */
declare(strict_types=1);

namespace June\JWT;

class Config
{
    //时区
    private $signingKey = "";
    //支持的加密方式
    private $hmacs = [
        "HS256" => "sha256",
        "HS384" => "sha384",
        "HS512" => "sha512",
    ];
    private $headers = [
        "alg"  => "HS256"
    ];
    private $claims = [];

    public function getKey(): string
    {
        return $this->signingKey;
    }

    public function setKey(string $key)
    {
        $this->signingKey = $key;
    }

    public function getHmac(): string
    {
        return $this->hmacs[$this->headers['alg']];
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function setHeaders(array $headers)
    {
        if (isset($headers['alg'])  && empty($this->hmacs[$headers['alg']])) {
            throw new JwtException('The encryption mode does not support ' . $headers['alg']);
        }
        $this->headers = $headers;
    }

    public function setHeader(string $name, $value)
    {
        if ($name == "alg" && empty($this->hmacs[$value])) {
            throw new JwtException('The encryption mode does not support ' . $value);
        }
        $this->headers[$name] = $value;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function setClaims(array $headers)
    {
        $this->claims = $headers;
    }

    public function setClaim(string $name, $value)
    {
        $this->claims[$name] = $value;
    }
}
