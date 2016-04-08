<?php

namespace TenTwentyFour\Component\Security\Http\Authentication\Provider;

use Silex\Application;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

use TenTwentyFour\Authentication\Token\JWToken;

class JWTProvider implements AuthenticationProviderInterface
{
    protected $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function authenticate(TokenInterface $token)
    {
        try {
            $decoded = (array) JWT::decode(
                $token->getEncodedPayload(),
                $this->app['jwt.options']['key'],
                array('HS256')
            );
            $authToken = new JWToken();
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
