<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 */

namespace TenTwentyFour\Security\JWT\Silex\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;

use TenTwentyFour\Security\JWT\Firewall\JWTListener;
use TenTwentyFour\Security\JWT\Authentication\Provider\JWTProvider;
use TenTwentyFour\Security\JWT\Authentication\Token\JWToken;
use TenTwentyFour\Security\JWT\EntryPoint\JWTAuthenticationEntryPoint;

class JWTSecurityServiceProvider implements ServiceProviderInterface
{
    public function register(Application $app)
    {
        //HMAC SHA256
        // var_dump($app['jwt.options']); exit;

        $app['jwt.token'] = $app->share(function () use ($app) {
            return new JWToken();
        });

        $app['jwt.options'] = [];   // does this override our options? If so how does this work in TwigServiceProvider?
        $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {

            $app['security.authentication_provider.'.$name.'.jwt'] = $app->share(function () use ($app) {
                return new JWTProvider(
                    $app['security.user_provider.default'], // Class expects instance of Silex Application
                    $app['jwt.options']['key'], // I think we should rather set something like 'security.authentication_provider.config.jwt' and use those from here on out? (cf. other Service Providers, for instance twig…?!)
                    $app['jwt.options']['alg']
                );
            });

            $app['security.authentication_listener.'.$name.'.jwt'] = $app->share(function () use ($app) {
                return new JWTListener(
                    $app['security'],
                    $app['security.authentication_manager']
                );
            });

            $app['security.entry_point.'.$name.'.jwt'] = $app->share(function() use ($app) {
                return new JWTAuthenticationEntryPoint();
            });

            return array(
                'security.authentication_provider.'.$name.'.jwt',
                'security.authentication_listener.'.$name.'.jwt',
                'security.entry_point.'.$name.'.jwt',
                'pre_auth'
            );
        });
    }

    public function boot(Application $app)
    {
    }
}
