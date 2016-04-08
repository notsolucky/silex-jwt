<?php

namespace TenTwentyFour\Component\Security\Http\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

use Silex\Application;

class JWToken extends AbstractToken implements TokenInterface
{

    protected $app;
    protected $payload;
    protected $hash;

    public function __construct(Application $app, array $roles = array()) {
        parent::__construct($roles);
        $this->app = $app;
    }

    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setHash($hash) {
        $this->hash = $hash;
    }

    public function getHash() {
        return $this->hash;
    }

    public function getCredentials()
    {
        return [];
    }

}
