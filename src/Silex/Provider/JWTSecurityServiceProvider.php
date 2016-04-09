<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 * @author David Raison <david@tentwentyfour.lu>
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
        $app['jwt.options'] = [];

        $app['jwt'] = $app->share(function ($app) {
            $app['jwt.options'] = array_replace(
                [
                    'key' => 'aRandomKeyThatShouldBeOverridenInTheConfigFile',
                    'alg' => 'HS256'    // HMAC SHA-256
                ],
                $app['jwt.options']
            );
        });

        $app['jwt.token'] = $app->share(function ($app) {
            return new JWToken(
                [],
                $app['jwt.options']['key'],
                $app['jwt.options']['alg']
            );
        });

        $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {

            $app['security.authentication_provider.'.$name.'.jwt'] = $app->share(function () use ($app) {
                return new JWTProvider(
                    $app['security.user_provider.default'],
                    $app['jwt.options']['key'],
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
