<?php

declare(strict_types=1);

namespace App;

use App\Config\Config;
use App\Routing\RouteCollectionFactory;
use App\Session\SessionManager;
use App\Support\Environment;
use Dotenv\Dotenv;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;

final class Kernel
{
    private Config $config;

    public function __construct()
    {
        $this->bootstrap();
    }

    private function bootstrap(): void
    {
        $rootPath = dirname(__DIR__);
        if (is_file($rootPath . '/.env')) {
            Dotenv::createImmutable($rootPath)->safeLoad();
        }

        Environment::syncToGetenv([
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'AWS_SESSION_TOKEN',
        ]);

        $this->config = Config::fromEnvironment();
        SessionManager::start($this->config);
    }

    public function handle(Request $request): Response
    {
        $routes = RouteCollectionFactory::build();
        $context = (new RequestContext())->fromRequest($request);
        $matcher = new UrlMatcher($routes, $context);

        try {
            $parameters = $matcher->match($request->getPathInfo());
            /** @var callable $controller */
            $controller = $parameters['_controller'];
            unset($parameters['_controller'], $parameters['_route']);

            return $controller($request, $this->config, $parameters);
        } catch (ResourceNotFoundException $e) {
            return new Response('Not Found', Response::HTTP_NOT_FOUND);
        } catch (\Throwable $e) {
            if ($this->config->isDebug()) {
                return new Response($e->getMessage(), Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            return new Response('Internal Server Error', Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
