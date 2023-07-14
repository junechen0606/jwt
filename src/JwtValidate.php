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

class JwtValidate
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

    public function claims(Config $config, string $token)
    {
        list($headersString, $claimsString, $signatureString) = $this->splitToken($token);
        $this->decodeHeaders($config, $headersString);
        $this->signatureValidate($config, $headersString . $claimsString, $signatureString);
        return $this->decodeClaims($config, $claimsString);
    }

    private function splitToken(string $token): ?array
    {
        $tokenArr = explode('.', $token);
        if (count($tokenArr) !== 3) {
            throw new JwtException('Token format error');
        }
        return $tokenArr;
    }

    private function decodeHeaders(Config $config, string $headers): ?array
    {
        $tokenArr = json_decode(base64_decode($headers), true);
        if (empty($tokenArr['alg'])) {
            throw new JwtException('Token uses an unknown algorithm');
        }
        $config->setHeader('alg', $tokenArr['alg']);
        return $tokenArr;
    }

    private function signatureValidate(Config $config, string $payload, string $signatureString): ?bool
    {
        $signature = base64_decode($signatureString);
        $hmac = $config->getHmac();
        $class = "\June\JWT\Hmac\\" . ucfirst($hmac);
        if (!class_exists($class)) {
            throw new JwtException('The encryption mode does not support');
        }
        $encryption = new $class();
        if ($encryption->verify($signature, $payload, $config->getKey())) {
            throw new JwtException('Token signature error');
        }
        return true;
    }

    private function decodeClaims(Config $config, string $claims): ?array
    {
        $claimsArr = json_decode(base64_decode($claims), true);
        $time = time();
        if (!empty($claimsArr['nbf']) && $claimsArr['nbf'] > $time) {
            throw new JwtException('The token has not yet taken effect');
        }
        if (!empty($claimsArr['exp']) && $claimsArr['exp'] <= $time) {
            throw new JwtException('The token has expired');
        }
        $configClaims = $config->getClaims();
        if (!empty($configClaims['iss']) && (empty($claimsArr['iss']) || $claimsArr['iss'] != $configClaims['iss'])) {
            throw new JwtException('Issuer mismatch');
        }
        if (!empty($configClaims['sub']) && (empty($claimsArr['sub']) || $claimsArr['sub'] != $configClaims['sub'])) {
            throw new JwtException('Subject mismatch');
        }
        if (!empty($configClaims['aud']) && (empty($claimsArr['aud']) || $claimsArr['aud'] != $configClaims['aud'])) {
            throw new JwtException('Audience mismatch');
        }
        return $claimsArr;
    }
}
