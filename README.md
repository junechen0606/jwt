# JWT Singleton

#### 介绍
JWT Singleton encapsulation

#### 安装
```
composer require june/jwt
```
#### 使用说明
1. Get token
```
use June\JWT\Jwt;
use June\JWT\Config;

$signingKey = "JuneSwoole";
$config = new Config();
$config->setKey($signingKey);
$config->setClaim("iss", "june");
$config->setClaim("aud", "JuneSwoole");
$config->setClaim("exp", time() + 7200);
$config->setClaim("jti", (string) getSoleId());
$token = Jwt::getInstance()->token($config);
```
2. Validate token
```
use June\JWT\JwtValidate;
use June\JWT\Config;
use June\JWT\JwtException;

try {
    $config = new Config();
    $signingKey = "JuneSwoole";
    $config->setKey($signingKey);
    $tokenClaim = JwtValidate::getInstance()->claims($config, $token);
} catch (JwtException $th) {
    echo $th->getMessage();
}

```