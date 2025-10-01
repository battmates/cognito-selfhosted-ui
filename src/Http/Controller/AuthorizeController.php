<?php

declare(strict_types=1);

namespace App\Http\Controller;

use App\Auth\AuthorizationResponder;
use App\Auth\CognitoClient;
use App\Config\Config;
use App\Security\CsrfToken;
use App\View\View;
use Aws\Exception\AwsException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class AuthorizeController
{
    private const SESSION_NAMESPACE = '_oauth2';

    public function show(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        try {
            $authRequest = $this->buildAuthorizeRequest($request, $config);
        } catch (\InvalidArgumentException $e) {
            return new Response($e->getMessage(), Response::HTTP_BAD_REQUEST);
        }

        $_SESSION[self::SESSION_NAMESPACE]['request'] = $authRequest;

        $errors = $_SESSION[self::SESSION_NAMESPACE]['errors'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['errors']);

        $success = $_SESSION[self::SESSION_NAMESPACE]['success'] ?? null;
        unset($_SESSION[self::SESSION_NAMESPACE]['success']);

        $prefill = $_SESSION[self::SESSION_NAMESPACE]['prefill_username'] ?? '';

        $csrfToken = CsrfToken::generate('authorize_form');
        $content = View::render('authorize/login', [
            'query' => $authRequest,
            'errors' => $errors,
            'success' => $success,
            'csrf_token' => $csrfToken,
            'prefill_username' => $prefill,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Sign in',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    public function authenticate(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $authRequest = $_SESSION[self::SESSION_NAMESPACE]['request'] ?? null;
        if (!$authRequest) {
            return new Response('Authorization context missing. Please restart login.', Response::HTTP_BAD_REQUEST);
        }

        if (!CsrfToken::validate('authorize_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $username = trim((string) $request->request->get('username'));
        $password = (string) $request->request->get('password');

        if ($username === '' || $password === '') {
            $this->flashError('Please provide both username and password.');
            $_SESSION[self::SESSION_NAMESPACE]['prefill_username'] = $username;
            return $this->redirectBackToAuthorize($authRequest);
        }

        $client = new CognitoClient($config);

        try {
            $result = $client->initiateUserPasswordAuth($username, $password);
        } catch (AwsException $e) {
            $message = $this->mapAwsExceptionToMessage($e);
            $this->flashError($message);
            $_SESSION[self::SESSION_NAMESPACE]['prefill_username'] = $username;
            return $this->redirectBackToAuthorize($authRequest);
        }

        if (isset($result['ChallengeName'])) {
            $_SESSION[self::SESSION_NAMESPACE]['challenge'] = [
                'name' => $result['ChallengeName'],
                'session' => $result['Session'] ?? '',
                'username' => $username,
                'params' => $result['ChallengeParameters'] ?? [],
                'auth_request' => $authRequest,
            ];

            return new RedirectResponse('/mfa');
        }

        if (!isset($result['AuthenticationResult'])) {
            $this->flashError('Unexpected authentication response.');
            return $this->redirectBackToAuthorize($authRequest);
        }

        $responder = new AuthorizationResponder($config);
        $code = $responder->generateCode($authRequest, $result['AuthenticationResult'], $username);

        $_SESSION[self::SESSION_NAMESPACE]['user'] = [
            'username' => $username,
            'authenticated_at' => time(),
        ];
        unset($_SESSION[self::SESSION_NAMESPACE]['prefill_username']);

        return new RedirectResponse($responder->buildRedirectUrl($authRequest['redirect_uri'], [
            'code' => $code,
            'state' => $authRequest['state'] ?? null,
        ]));
    }

    /**
     * @return array<string, mixed>
     */
    private function buildAuthorizeRequest(Request $request, Config $config): array
    {
        $clientId = (string) $request->query->get('client_id');
        $redirectUri = (string) $request->query->get('redirect_uri');
        $responseType = (string) $request->query->get('response_type', 'code');

        if ($clientId === '' || $clientId !== $config->get('cognito_client_id')) {
            throw new \InvalidArgumentException('Invalid client_id');
        }

        if ($responseType !== 'code') {
            throw new \InvalidArgumentException('Unsupported response_type');
        }

        if (!$this->isRedirectAllowed($redirectUri, $config)) {
            throw new \InvalidArgumentException('redirect_uri is not allowed');
        }

        return [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => $responseType,
            'scope' => (string) $request->query->get('scope'),
            'state' => $request->query->get('state'),
            'code_challenge' => $request->query->get('code_challenge'),
            'code_challenge_method' => $request->query->get('code_challenge_method'),
            'prompt' => $request->query->get('prompt'),
        ];
    }

    private function isRedirectAllowed(string $redirectUri, Config $config): bool
    {
        if ($redirectUri === '') {
            return false;
        }

        $allowed = $config->allowedRedirects();
        if ($allowed === []) {
            return true;
        }

        foreach ($allowed as $allowedUri) {
            if ($allowedUri === '') {
                continue;
            }

            if (hash_equals($allowedUri, $redirectUri)) {
                return true;
            }
        }

        return false;
    }

    private function redirectBackToAuthorize(array $authRequest): Response
    {
        $query = http_build_query(array_filter([
            'client_id' => $authRequest['client_id'] ?? null,
            'redirect_uri' => $authRequest['redirect_uri'] ?? null,
            'response_type' => $authRequest['response_type'] ?? null,
            'scope' => $authRequest['scope'] ?? null,
            'state' => $authRequest['state'] ?? null,
            'code_challenge' => $authRequest['code_challenge'] ?? null,
            'code_challenge_method' => $authRequest['code_challenge_method'] ?? null,
        ]));

        return new RedirectResponse('/oauth2/authorize' . ($query ? '?' . $query : ''));
    }

    private function flashError(string $message): void
    {
        $this->ensureSessionNamespace();
        $_SESSION[self::SESSION_NAMESPACE]['errors'][] = $message;
    }

    private function mapAwsExceptionToMessage(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'NotAuthorizedException' => 'Incorrect username or password.',
            'UserNotConfirmedException' => 'Your account is not confirmed. Please check your email for the verification link.',
            'PasswordResetRequiredException' => 'You must reset your password before signing in.',
            default => 'Login failed. Please try again.',
        };
    }

    private function ensureSessionNamespace(): void
    {
        if (!isset($_SESSION[self::SESSION_NAMESPACE]) || !is_array($_SESSION[self::SESSION_NAMESPACE])) {
            $_SESSION[self::SESSION_NAMESPACE] = [];
        }
    }
}
