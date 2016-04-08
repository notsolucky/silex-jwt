use TenTwentyFour\Service\Provider\JWTSecurityServiceProvider;

$app->register(
    new Silex\Provider\SecurityServiceProvider(),
    [
        'security.firewalls' => [
            'addresses' => [
                'pattern' => '^/addresses',
                'jwt' => true
            ]
        ]
    ]
);

$app->register(new JWTSecurityServiceProvider());


/// FROM config
,
"jwt.options": {
    "key": "wItfJjpx31Hk9D4Xt5Uk5AsS82n4bQQ8zAov2UZXNrbhn6CN35iQwnEORjgl2crx"
}

//// ADMIN/index.php

<?php
    require_once "../open.inc.php";
    use \Firebase\JWT\JWT;

    $key = $config->{'jwt.options'}->key;

    //["PHP_AUTH_USER"]=> string(3) "guy" ["PHP_AUTH_PW"]=

    $now = (new DateTime())->format('U');
    $token = array(
        "iss" => "http://cmd.flowey.com", // issueing entity
        "aud" => "http://cmd.flowey.com", // audience
        "iat" => $now, // issued at
        "nbf" => $now + 1,  // do not accept before this date
        "exp" => $now + 60, // expiration time
        "sub" => "authenticate",  // subject ?
        "user" => 'admin'
    );

    $jwt = JWT::encode($token, $key, 'HS256');
    // manipulate the jwt
    // $parts = explode('.', $jwt);
    // $entry = json_decode(base64_decode($parts[1]), true);
    // $entry['user'] = 'kevin';
    // $parts[1] = base64_encode(json_encode($entry));
    // $jwt = implode('.', $parts);

    // setting jwt in the header | use $.ajax request to set custom headers for a post/get request
    // header('jwt: '.$jwt);

?>

<input type="hidden" name="jwt" value="<?php echo $jwt;?>">


"firebase/php-jwt": "^3.0"
