<?php

declare(strict_types=1);

namespace App\Http\Controller;

use App\Auth\CognitoClient;
use App\Config\Config;
use App\Security\CsrfToken;
use App\View\View;
use Aws\Exception\AwsException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class RegistrationController
{
    private const SESSION_NAMESPACE = '_registration';

    public function show(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $errors = $_SESSION[self::SESSION_NAMESPACE]['errors'] ?? [];
        $values = $_SESSION[self::SESSION_NAMESPACE]['values'] ?? [];
        $debug = $_SESSION[self::SESSION_NAMESPACE]['debug'] ?? [];
        unset(
            $_SESSION[self::SESSION_NAMESPACE]['errors'],
            $_SESSION[self::SESSION_NAMESPACE]['values'],
            $_SESSION[self::SESSION_NAMESPACE]['debug']
        );

        $client = new CognitoClient($config);
        $requiredAttributes = $client->requiredAttributes();

        $csrfToken = CsrfToken::generate('register_form');

        $content = View::render('register/form', [
            'errors' => $errors,
            'values' => $values,
            'csrf_token' => $csrfToken,
            'required_attributes' => $requiredAttributes,
            'debug' => $debug,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Create an account',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    public function submit(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        if (!CsrfToken::validate('register_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $email = trim((string) $request->request->get('email'));
        $password = (string) $request->request->get('password');
        $confirm = (string) $request->request->get('password_confirmation');
        $givenName = trim((string) $request->request->get('given_name'));
        $familyName = trim((string) $request->request->get('family_name'));

        $client = new CognitoClient($config);
        $requiredAttributes = $client->requiredAttributes();

        $errors = [];
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Enter a valid email address.';
        }
        if ($password === '') {
            $errors[] = 'Enter a password.';
        }
        if ($password !== $confirm) {
            $errors[] = 'Passwords do not match.';
        }

        if (in_array('given_name', $requiredAttributes, true) && $givenName === '') {
            $errors[] = 'Enter your first name.';
        }

        if (in_array('family_name', $requiredAttributes, true) && $familyName === '') {
            $errors[] = 'Enter your last name.';
        }

        if ($errors !== []) {
            $_SESSION[self::SESSION_NAMESPACE]['errors'] = $errors;
            $_SESSION[self::SESSION_NAMESPACE]['values'] = [
                'email' => $email,
                'given_name' => $givenName,
                'family_name' => $familyName,
            ];
            return new RedirectResponse('/register');
        }

        $attributes = array_filter([
            'given_name' => $givenName,
            'family_name' => $familyName,
        ], static fn($value) => $value !== null && $value !== '');

        $usernameBase = $this->generateUsernameFromEmail($email);
        $username = $usernameBase;
        $attempts = 0;
        $maxAttempts = 5;

        while ($attempts < $maxAttempts) {
            try {
                $client->signUp($username, $password, $email, $attributes);
                $createdUsername = $username;
                break;
            } catch (AwsException $e) {
                if ($e->getAwsErrorCode() === 'UsernameExistsException') {
                    $attempts++;
                    $suffix = $this->randomUsernameSuffix($attempts);
                    $base = substr($usernameBase, 0, max(1, 24 - strlen($suffix)));
                    $username = $base . $suffix;
                    continue;
                }

                $this->flashRegistrationFailure($email, $givenName, $familyName, $username, $e);
                return new RedirectResponse('/register');
            }
        }

        if (!isset($createdUsername)) {
            $this->flashRegistrationFailure(
                $email,
                $givenName,
                $familyName,
                $username,
                null,
                'We could not create your account right now. Please try again.'
            );
            return new RedirectResponse('/register');
        }

        $_SESSION[self::SESSION_NAMESPACE]['pending_username'] = $createdUsername;
        $_SESSION[self::SESSION_NAMESPACE]['pending_alias'] = $email;
        return new RedirectResponse('/register/confirm?username=' . urlencode($email));
    }

    public function showConfirmation(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $username = (string) ($request->query->get('username') ?: ($_SESSION[self::SESSION_NAMESPACE]['pending_alias'] ?? ''));
        $errors = $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] ?? [];
        $success = $_SESSION[self::SESSION_NAMESPACE]['confirm_success'] ?? null;
        unset($_SESSION[self::SESSION_NAMESPACE]['confirm_errors'], $_SESSION[self::SESSION_NAMESPACE]['confirm_success']);

        $csrfToken = CsrfToken::generate('register_confirm_form');

        $content = View::render('register/confirm', [
            'errors' => $errors,
            'success' => $success,
            'username' => $username,
            'csrf_token' => $csrfToken,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Verify your email',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    public function confirm(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        if (!CsrfToken::validate('register_confirm_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $username = trim((string) $request->request->get('username'));
        $code = trim((string) $request->request->get('code'));

        if ($username === '' || $code === '') {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = ['Enter your email address and the verification code.'];
            return new RedirectResponse('/register/confirm?username=' . urlencode($username));
        }

        $client = new CognitoClient($config);
        $actualUsername = $_SESSION[self::SESSION_NAMESPACE]['pending_username'] ?? $username;

        try {
            $client->confirmSignUp($actualUsername, $code);
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = [$this->mapConfirmationError($e)];
            return new RedirectResponse('/register/confirm?username=' . urlencode($username));
        }

        unset($_SESSION[self::SESSION_NAMESPACE]['pending_username'], $_SESSION[self::SESSION_NAMESPACE]['pending_alias']);
        $_SESSION['_oauth2']['success'] = 'Your account is confirmed. You can sign in now.';

        return new RedirectResponse($this->buildAuthorizeRedirect($config));
    }

    public function resend(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        if (!CsrfToken::validate('register_confirm_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $username = trim((string) $request->request->get('username'));
        if ($username === '') {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = ['Enter your email address to resend the code.'];
            return new RedirectResponse('/register/confirm');
        }

        $client = new CognitoClient($config);
        $actualUsername = $_SESSION[self::SESSION_NAMESPACE]['pending_username'] ?? $username;

        try {
            $client->resendConfirmationCode($actualUsername);
            $_SESSION[self::SESSION_NAMESPACE]['confirm_success'] = 'A new verification code has been sent.';
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = [$this->mapConfirmationError($e)];
        }

        return new RedirectResponse('/register/confirm?username=' . urlencode($username));
    }

    private function buildAuthorizeRedirect(Config $config): string
    {
        $authRequest = $_SESSION['_oauth2']['request'] ?? null;

        if (is_array($authRequest) && isset($authRequest['client_id'], $authRequest['redirect_uri'])) {
            $query = http_build_query(array_filter([
                'client_id' => $authRequest['client_id'] ?? null,
                'redirect_uri' => $authRequest['redirect_uri'] ?? null,
                'response_type' => $authRequest['response_type'] ?? 'code',
                'scope' => $authRequest['scope'] ?? null,
                'state' => $authRequest['state'] ?? null,
                'code_challenge' => $authRequest['code_challenge'] ?? null,
                'code_challenge_method' => $authRequest['code_challenge_method'] ?? null,
                'prompt' => $authRequest['prompt'] ?? null,
            ]));

            return '/oauth2/authorize' . ($query ? '?' . $query : '');
        }

        $fallbackRedirect = $this->defaultRedirectUri($config);

        $query = http_build_query(array_filter([
            'client_id' => $config->get('cognito_client_id'),
            'redirect_uri' => $fallbackRedirect,
            'response_type' => 'code',
            'scope' => 'openid',
        ]));

        return '/oauth2/authorize' . ($query ? '?' . $query : '');
    }

    private function defaultRedirectUri(Config $config): string
    {
        $allowed = $config->allowedRedirects();
        if ($allowed !== []) {
            return $allowed[0];
        }

        return (string) $config->get('app_url', '');
    }

    private function mapRegistrationError(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'UsernameExistsException' => 'An account with this email already exists. Try signing in.',
            'InvalidParameterException' => str_contains((string) $exception->getAwsErrorMessage(), 'alias')
                ? 'We had trouble creating your account. Please try again in a moment.'
                : 'Your account could not be created. Please try again with different details.',
            'InvalidPasswordException' => 'Your password does not meet the complexity requirements.',
            default => 'We could not create your account. Please try again.',
        };
    }

    private function generateUsernameFromEmail(string $email): string
    {
        $localPart = strtolower(strtok($email, '@') ?: $email);
        $sanitized = preg_replace('/[^a-z0-9]/', '', $localPart) ?: 'user';

        return substr($sanitized, 0, 24);
    }

    private function randomUsernameSuffix(int $attempt): string
    {
        try {
            return substr(bin2hex(random_bytes(3)), 0, 6);
        } catch (\Throwable) {
            return (string) ($attempt + random_int(0, 999));
        }
    }

    private function flashRegistrationFailure(
        string $email,
        string $givenName,
        string $familyName,
        string $username,
        ?AwsException $exception = null,
        ?string $customMessage = null
    ): void {
        $message = $customMessage ?? ($exception ? $this->mapRegistrationError($exception) : 'We could not create your account. Please try again.');

        $_SESSION[self::SESSION_NAMESPACE]['errors'] = [$message];
        $_SESSION[self::SESSION_NAMESPACE]['values'] = [
            'email' => $email,
            'given_name' => $givenName,
            'family_name' => $familyName,
        ];

        if (!isset($_SESSION[self::SESSION_NAMESPACE]['debug']) || !is_array($_SESSION[self::SESSION_NAMESPACE]['debug'])) {
            $_SESSION[self::SESSION_NAMESPACE]['debug'] = [];
        }

        $debug = [
            'attempted_username' => $username,
            'attributes' => array_filter([
                'email' => $email,
                'given_name' => $givenName,
                'family_name' => $familyName,
            ], static fn($value) => $value !== ''),
        ];

        if ($exception) {
            $debug['error'] = [
                'code' => $exception->getAwsErrorCode(),
                'message' => $exception->getAwsErrorMessage(),
            ];
        } elseif ($customMessage !== null) {
            $debug['error'] = [
                'code' => 'username_generation_failed',
                'message' => $customMessage,
            ];
        }

        $_SESSION[self::SESSION_NAMESPACE]['debug'][] = $debug;
    }

    private function mapConfirmationError(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'CodeMismatchException' => 'The code you entered is incorrect.',
            'ExpiredCodeException' => 'The code has expired. Request a new one.',
            default => 'We could not verify your account. Please try again.',
        };
    }

    private function ensureSessionNamespace(): void
    {
        if (!isset($_SESSION[self::SESSION_NAMESPACE]) || !is_array($_SESSION[self::SESSION_NAMESPACE])) {
            $_SESSION[self::SESSION_NAMESPACE] = [];
        }
    }
}
