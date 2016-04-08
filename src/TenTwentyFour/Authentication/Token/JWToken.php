<?php

namespace TenTwentyFour\Authentication\Token;

use Silex\Application;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class JWToken extends AbstractToken implements TokenInterface
{
    protected $app;
    protected $payload;
    protected $hash;

    public function __construct(Application $app, array $roles = array()) {
        parent::__construct($roles);
        $this->app = $app;
    }

    public function setEncodedPayload(array $payload)
    {
        $this->payload = $payload;
    }

    public function getEncodedPayload()
    {
        return $this->payload;
    }

    public function getCredentials()
    {
        return [];
    }

}
