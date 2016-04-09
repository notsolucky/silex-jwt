<?php

namespace TenTwentyFour\Security\JWT\Authentication\Token;

use Silex\Application;
use Firebase\JWT\JWT;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class JWToken extends AbstractToken implements TokenInterface
{
    protected $app;
    protected $payload;
    protected $encodedPayload;
    protected $hash;

    public function __construct(array $roles = array())
    {
        parent::__construct($roles);
    }

    /**
     *
     * @return [type] [description]
     */
    public function generate($params)
    {
        return JWT::encode(
            $params,
            $this->app['jwt.options']['key'],
            $this->app['jwt.options']['alg']
        );
    }

    public function decode()
    {
        $this->payload = (array) JWT::decode(
            $this->encodedPayload,
            $this->app['jwt.options']['key'],
            $this->app['jwt.options']['alg']
        );
    }

    public function setEncodedPayload(array $payload)
    {
        $this->encodedPayload = $payload;
    }

    public function getEncodedPayload()
    {
        return $this->encodedPayload;
    }

    public function getCredentials()
    {
        return [];
    }

}
