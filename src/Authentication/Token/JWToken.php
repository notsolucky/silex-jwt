<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 * @author David Raison <david@tentwentyfour.lu>
 */

namespace TenTwentyFour\Security\JWT\Authentication\Token;

use Firebase\JWT\JWT;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class JWToken extends AbstractToken implements TokenInterface
{
    protected $payload;
    protected $encodedPayload;
    protected $hash;

    public function __construct(array $roles = array(), $key, $alg)
    {
        parent::__construct($roles);
        $this->key = $key;
        $this->alg = $alg;
    }

    /**
     *
     * @return [type] [description]
     */
    public function generate($params)
    {
        return JWT::encode(
            $params,
            $this->key,
            $this->alg
        );
    }

    public function decode()
    {
        $this->payload = (array) JWT::decode(
            $this->encodedPayload,
            $this->key,
            $this->alg
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
