<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 * @author David Raison <david@tentwentyfour.lu>
 */

namespace TenTwentyFour\Security\JWT\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;

use TenTwentyFour\Security\JWT\Authentication\Token\JWToken;

class JWTListener implements ListenerInterface
{
    protected $tokenInstance;
    protected $securityContext;
    protected $authenticationManager;

    public function __construct(
        SecurityContextInterface $securityContext,
        AuthenticationManagerInterface $authenticationManager,
        JWToken $token
    ) {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->tokenInstance = $token;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $token = $this->findToken($request);
        $response = new Response();

        if ($token) {
            $this->tokenInstance->setEncodedPayload($token);
            try {
                $authenticatedToken = $this->authenticationManager->authenticate($this->tokenInstance);
                $this->securityContext->setToken($authenticatedToken);
                return;
            } catch (AuthenticationException $e) {
                $this->securityContext->setToken(null);
                $response->setContent('JWT Authentication Failed. '.$e->getMessage());
            }
        } else {
            $this->securityContext->setToken(null);
            $response->setContent('JWT Authentication Failed. JWT Hash could not be loaded from request.');
        }
        $response->setStatusCode(Response::HTTP_FORBIDDEN);
        $event->setResponse($response);
    }

    /**
     * Attempts to find a JWT token in either the request header
     * or the request parameters.

     * @param  Request $request Request
     * @return mixed    False if no token was found, String if it was
     */
    private function findToken(Request $request)
    {
        if ($request->headers->has('X-JWT-Assertion')) {
            return $request->headers->get('X-JWT-Assertion');
        } elseif ($request->request->has('jwt-token')) {
            return $request->request->get('jwt-token');
        } elseif ($request->query->has('jwt-token')) {
            return $request->query->get('jwt-token');
        }
        return false;
    }
}
