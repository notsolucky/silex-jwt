<?php

namespace TenTwentyFour\Service\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;

use TenTwentyFour\Component\Security\Http\Firewall\JWTListener;
use TenTwentyFour\Component\Security\Http\Authentication\Provider\JWTProvider;
use TenTwentyFour\Component\Security\Http\EntryPoint\JWTAuthenticationEntryPoint;

class JWTSecurityServiceProvider implements ServiceProviderInterface
{
    public function register(Application $app)
    {
        $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {

            // define the authentication provider object
            $app['security.authentication_provider.'.$name.'.jwt'] = $app->share(function () use ($app) {
                return new JWTProvider($app);
            });

            // define the authentication listener object
            $app['security.authentication_listener.'.$name.'.jwt'] = $app->share(function () use ($app) {
                // use 'security' instead of 'security.token_storage' on Symfony <2.6
                return new JWTListener($app);
            });

            $app['security.entry_point.'.$name.'.jwt'] = $app->share(function() use ($app) {
                return new JWTAuthenticationEntryPoint();
            });

            return array(
                // the authentication provider id
                'security.authentication_provider.'.$name.'.jwt',
                // the authentication listener id
                'security.authentication_listener.'.$name.'.jwt',
                // the entry point id
                'security.entry_point.'.$name.'.jwt',
                // the position of the listener in the stack
                'pre_auth'
            );
        });
    }

    public function boot(Application $app)
    {
    }
}
