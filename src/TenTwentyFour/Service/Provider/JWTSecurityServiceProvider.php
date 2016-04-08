<?php
/**
 * @package 1024/silex-jwt
 * @author Paul Salentiny <paul@tentwentyfour.lu>
 */

namespace TenTwentyFour\Service\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;

use TenTwentyFour\Firewall\JWTListener;
use TenTwentyFour\Authentication\Provider\JWTProvider;
use TenTwentyFour\EntryPoint\JWTAuthenticationEntryPoint;

class JWTSecurityServiceProvider implements ServiceProviderInterface
{
    public function register(Application $app)
    {
        $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {

            $app['security.authentication_provider.'.$name.'.jwt'] = $app->share(function () use ($app) {
                return new JWTProvider(
                    $app['security.user_provider.default'],
                    __DIR__.'/security_cache'
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
