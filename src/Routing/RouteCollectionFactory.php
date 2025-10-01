<?php

declare(strict_types=1);

namespace App\Routing;

use App\Http\Controller\AuthorizeController;
use App\Http\Controller\MfaController;
use App\Http\Controller\PasswordController;
use App\Http\Controller\RegistrationController;
use App\Http\Controller\TokenController;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

final class RouteCollectionFactory
{
    public static function build(): RouteCollection
    {
        $routes = new RouteCollection();

        $authorizeController = new AuthorizeController();
        $mfaController = new MfaController();
        $tokenController = new TokenController();
        $registrationController = new RegistrationController();
        $passwordController = new PasswordController();

        $routes->add('authorize.get', new Route(
            '/oauth2/authorize',
            ['_controller' => [$authorizeController, 'show']],
            methods: ['GET']
        ));

        $routes->add('authorize.post', new Route(
            '/oauth2/authorize',
            ['_controller' => [$authorizeController, 'authenticate']],
            methods: ['POST']
        ));

        $routes->add('mfa.get', new Route(
            '/mfa',
            ['_controller' => [$mfaController, 'show']],
            methods: ['GET']
        ));

        $routes->add('mfa.post', new Route(
            '/mfa',
            ['_controller' => [$mfaController, 'verify']],
            methods: ['POST']
        ));

        $routes->add('register.get', new Route(
            '/register',
            ['_controller' => [$registrationController, 'show']],
            methods: ['GET']
        ));

        $routes->add('register.post', new Route(
            '/register',
            ['_controller' => [$registrationController, 'submit']],
            methods: ['POST']
        ));

        $routes->add('register.confirm.get', new Route(
            '/register/confirm',
            ['_controller' => [$registrationController, 'showConfirmation']],
            methods: ['GET']
        ));

        $routes->add('register.confirm.post', new Route(
            '/register/confirm',
            ['_controller' => [$registrationController, 'confirm']],
            methods: ['POST']
        ));

        $routes->add('register.resend.post', new Route(
            '/register/resend',
            ['_controller' => [$registrationController, 'resend']],
            methods: ['POST']
        ));

        $routes->add('password.forgot.get', new Route(
            '/forgot-password',
            ['_controller' => [$passwordController, 'showForgot']],
            methods: ['GET']
        ));

        $routes->add('password.forgot.post', new Route(
            '/forgot-password',
            ['_controller' => [$passwordController, 'sendForgot']],
            methods: ['POST']
        ));

        $routes->add('password.reset.get', new Route(
            '/reset-password',
            ['_controller' => [$passwordController, 'showReset']],
            methods: ['GET']
        ));

        $routes->add('password.reset.post', new Route(
            '/reset-password',
            ['_controller' => [$passwordController, 'confirmReset']],
            methods: ['POST']
        ));

        $routes->add('token.post', new Route(
            '/oauth2/token',
            ['_controller' => [$tokenController, 'exchange']],
            methods: ['POST']
        ));

        return $routes;
    }
}
