<?php

namespace TenTwentyFour\Component\Security\Http\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use Silex\Application;

use TenTwentyFour\Component\Security\Http\Authentication\Token\JWToken;

use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

/*

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
*/

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
                $token->getHash(),
                $this->app['jwt.options']['key'],
                array('HS256')
            );
            // maybe use new instance of JWToken to return
            $token->setPayload($decoded);
            $token->setAuthenticated(true);
            return $token;
        } catch (SignatureInvalidException $e) {
            throw new AuthenticationException('Token signature is invalid.');
        } catch (BeforeValidException $e) {
            throw new AuthenticationException('Token validity period has not started yet.');
        } catch (ExpiredException $e) {
            throw new AuthenticationException('Token validity period has expired.');
        }
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof JWToken;
    }

}
