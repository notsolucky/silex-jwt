<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 * @author David Raison <david@tentwentyfour.lu>
 */

namespace TenTwentyFour\Security\JWT\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;

use TenTwentyFour\Security\JWT\Authentication\Token\JWToken;

class JWTProvider implements AuthenticationProviderInterface
{

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
            $token->setAuthenticated(true);
            return $token;
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
