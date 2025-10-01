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
        unset($_SESSION[self::SESSION_NAMESPACE]['errors'], $_SESSION[self::SESSION_NAMESPACE]['values']);

        $csrfToken = CsrfToken::generate('register_form');

        $content = View::render('register/form', [
            'errors' => $errors,
            'values' => $values,
            'csrf_token' => $csrfToken,
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

        if ($errors !== []) {
            $_SESSION[self::SESSION_NAMESPACE]['errors'] = $errors;
            $_SESSION[self::SESSION_NAMESPACE]['values'] = ['email' => $email];
            return new RedirectResponse('/register');
        }

        $client = new CognitoClient($config);

        try {
            $client->signUp($email, $password, $email);
        } catch (AwsException $e) {
            $message = $this->mapRegistrationError($e);
            $_SESSION[self::SESSION_NAMESPACE]['errors'] = [$message];
            $_SESSION[self::SESSION_NAMESPACE]['values'] = ['email' => $email];
            return new RedirectResponse('/register');
        }

        $_SESSION[self::SESSION_NAMESPACE]['pending_username'] = $email;
        return new RedirectResponse('/register/confirm?username=' . urlencode($email));
    }

    public function showConfirmation(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $username = (string) ($request->query->get('username') ?: ($_SESSION[self::SESSION_NAMESPACE]['pending_username'] ?? ''));
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

        try {
            $client->confirmSignUp($username, $code);
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = [$this->mapConfirmationError($e)];
            return new RedirectResponse('/register/confirm?username=' . urlencode($username));
        }

        unset($_SESSION[self::SESSION_NAMESPACE]['pending_username']);
        $_SESSION['_oauth2']['success'] = 'Your account is confirmed. You can sign in now.';

        return new RedirectResponse('/oauth2/authorize');
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

        try {
            $client->resendConfirmationCode($username);
            $_SESSION[self::SESSION_NAMESPACE]['confirm_success'] = 'A new verification code has been sent.';
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_NAMESPACE]['confirm_errors'] = [$this->mapConfirmationError($e)];
        }

        return new RedirectResponse('/register/confirm?username=' . urlencode($username));
    }

    private function mapRegistrationError(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'UsernameExistsException' => 'An account with this email already exists. Try signing in.',
            'InvalidPasswordException' => 'Your password does not meet the complexity requirements.',
            default => 'We could not create your account. Please try again.',
        };
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
