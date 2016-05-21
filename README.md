# Silex JWT Service Provider

It is designed to work with the older Silex Version 1.2.4.

## Installation

`composer require notsolucky/silex-jwt`

## Usage

Register the `JWTSecurityServiceProvider` with your Silex application.

```php
use TenTwentyFour\Security\JWT\Silex\Provider\JWTSecurityServiceProvider;
$app->register(new Silex\Provider\SecurityServiceProvider());
$app->register(new JWTSecurityServiceProvider());
```

When configuring the firewall, you can set the stateless authentication flag to disable the creation of a session cookie used to persist the security context.

```php
$app['security.firewalls'] = array(
    'api' => array(
        'pattern' => '^/api',
        'jwt' => true,
        'stateless' => true
    ),
);
```

To generate a token create a new JWToken instance with`$app['jwt.token']()`.

```php
$token = $app['jwt.token']()->generate([
    'iss' => 'Issuer',
    'aud' => 'Audience',
    'iat' => time(), // time the JWT was issued
    'nbf' => time(), // not valid before this time
    'exp' => time() + 2400, // expiration time
    'sub' => 'Example', // subject
]);
```

To access the current token used during authentication. This is only available after the Silex application has been booted.

```php
$app['security']->getToken();
```

### Options
```php
$app['jwt.options'] = [
    'key' => 'aRandomKeyToSignThePayload',
    'alg' => 'HS256', // supported algorithms (HS256, HS512, HS384, RS256)
    'crd' => [
        'claim' => 'credentialskey',
        'sub' => 'example'
    ],
    'att' => [
        'claim' => 'credentialskey'
    ],
    'usr' => 'claim'
];
```
- `key` : The secret encoded with the JWT header and payload to calculate and verify the signature. **Important**, set this to a random string value.
- `alg` : The algorithm used to calculate the JWS signature, default is `HS256`.
- `att` (optional): The claims that should be passed into the token attributes. Accessible through `JWTToken::getAttributes();`.
- `crd` (optional): The claims that should be passed into the user credentials of the token. `JWTToken::getCredentials();`.
- `usr` (optional): The name of the JWT claim that specifies the username that should be returned by `JWTToken::getUser();`.