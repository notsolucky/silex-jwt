<?php

namespace TenTwentyFour\Component\Security\Http\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\Request;

use Silex\Application;

use TenTwentyFour\Component\Security\Http\Authentication\Token\JWToken;

use Firebase\JWT\JWT;

class JWTListener implements ListenerInterface
{
    protected $app;
    protected $tokenStorage;
    protected $authenticationManager;

    public function __construct(Application $app)
    {
            $this->app = $app;
            // get security context instance (Symfony\Component\Security\Core\SecurityContext)
            // for Silex > 2.6, use 'security.token_storage'
            $this->tokenStorage = $app['security'];
            $this->authenticationManager = $app['security.authentication_manager'];
    }

    public function handle(GetResponseEvent $event) {
        $request = $event->getRequest();
        $response = new Response();
        // initialize token
        $token = new JWToken($this->app);
        if ($request->query->has('jwt')) {
            $token->setHash($request->query->get('jwt'));
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
