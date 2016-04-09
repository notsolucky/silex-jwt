<?php

namespace TenTwentyFour\Security\JWT\Authentication\Provider;

use Silex\Application;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

use TenTwentyFour\Authentication\Token\JWToken;

class JWTProvider implements AuthenticationProviderInterface
{
    protected $app;

    public function __construct(UserProviderInterface $userprovider, $key, $alg)
    {
        $this->userProvider = $userprovider;
        $this->key = $key;
        $this->alg = $alg;
    }

    /**
     * JWToken throws exceptions if unable to decode the token.
     * We catch these exceptions and turn them into AuthenticationExceptions
     *
     * @param  TokenInterface $token Token retrieved by the JWTListener
     *
     * @return JWToken  Returns a new instance of the JWToken if authentication succeeded.
     */
    public function authenticate(TokenInterface $token)
    {
        try {
            $token->decode();
            $authToken = new JWToken($this->app);   // I would rather pass in key and algorithm?
            $authToken->setAuthenticated(true);
            return $authToken;
        } catch (SignatureInvalidException $e) {
            throw new AuthenticationException(
                'Token signature is invalid.'
            );
        } catch (BeforeValidException $e) {
            throw new AuthenticationException(
                'Token validity period has not started yet.'
            );
        } catch (ExpiredException $e) {
            throw new AuthenticationException(
                'Token validity period has expired.'
            );
        }
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof JWToken;
    }

}
