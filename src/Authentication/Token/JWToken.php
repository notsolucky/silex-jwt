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
    protected $options;
    protected $payload;
    protected $encodedPayload;
    protected $credentials;

    public function __construct(array $roles = array(), array $options)
    {
        parent::__construct($roles);
        $this->options = $options;
        $this->credentials = [];
    }

    /**
     * Generates an encoded JWT token based on the parameters passed in
     *
     * @return String Encoded JWT
     */
    public function generate($params)
    {
        return JWT::encode(
            $params,
            $this->options['key'],
            $this->options['alg']
        );
    }

    /**
     * Throws an exception if decoding fails.
     * Exceptions are could in JWTProvider
     * @return JWToken
     */
    public function decode()
    {
        $this->payload = (array) JWT::decode(
            $this->encodedPayload,
            $this->options['key'],
            [$this->options['alg']]
        );
        $this->loadAttributes();
        $this->loadUser();
        $this->loadCredentials();
        return $this;
    }

    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setEncodedPayload($payload)
    {
        $this->encodedPayload = $payload;
    }

    public function getEncodedPayload()
    {
        return $this->encodedPayload;
    }

    public function getCredentials()
    {
        return $this->credentials;
    }

    protected function loadAttributes()
    {
        if (isset($this->options['att'])
            && is_array($this->options['att'])) {

            $this->setAttributes($this->loadClaims($this->options['att']));
        }
    }

    protected function loadUser()
    {
        if (isset($this->options['usr'])
            && isset($this->payload[$this->options['usr']])) {

            $this->setUser($this->payload[$this->options['usr']]);
        }
    }

    protected function loadCredentials()
    {
        if (isset($this->options['crd'])
            && is_array($this->options['crd'])) {

            $this->credentials = $this->loadClaims($this->options['crd']);
        }
    }

    private function loadClaims(array $data)
    {
        $loaded = [];

        array_walk(
            $this->payload,
            function ($value, $key) use ($data, &$loaded) {
                if (isset($data[$key])) {
                    $loaded[$data[$key]] = $value;
                }
            }
        );

        return $loaded;
    }
}
