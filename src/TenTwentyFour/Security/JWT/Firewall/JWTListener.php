<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 */

namespace TenTwentyFour\Security\JWT\Firewall;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\Request;

use Firebase\JWT\JWT;
use TenTwentyFour\Authentication\Token\JWToken;

class JWTListener implements ListenerInterface
{
    protected $app;
    protected $tokenStorage;
    protected $authenticationManager;

    public function __construct($security, $authenticationManager)
    {
        $this->app = $app;
        $this->tokenStorage = $security;
        $this->authenticationManager = $authenticationManager;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $response = new Response();
        $token = new JWToken($this->app);

        if ($request->query->has('jwt')) {
            $token->setPayload($request->query->get('jwt'));
            try {
                $authenticatedToken = $this->authenticationManager->authenticate($token);
                $this->tokenStorage->setToken($authenticatedToken);
                return;
            } catch (AuthenticationException $e) {
                $this->tokenStorage->setToken(null);
                $response->setContent('JWT Authentication Failed. '.$e->getMessage());
            }
        } else {
            $this->tokenStorage->setToken(null);
            $response->setContent('JWT Authentication Failed. JWT Hash could not be loaded from request.');
        }
        $response->setStatusCode(Response::HTTP_FORBIDDEN);
        $event->setResponse($response);
    }

}
