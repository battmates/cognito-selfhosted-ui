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

final class PasswordController
{
    private const SESSION_FORGOT = '_password_forgot';
    private const SESSION_RESET = '_password_reset';

    public function showForgot(Request $request, Config $config, array $parameters): Response
    {
        $errors = $_SESSION[self::SESSION_FORGOT]['errors'] ?? [];
        $success = $_SESSION[self::SESSION_FORGOT]['success'] ?? null;
        $values = $_SESSION[self::SESSION_FORGOT]['values'] ?? [];
        unset($_SESSION[self::SESSION_FORGOT]);

        $csrfToken = CsrfToken::generate('forgot_form');

        $content = View::render('password/forgot', [
            'errors' => $errors,
            'success' => $success,
            'values' => $values,
            'csrf_token' => $csrfToken,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Reset your password',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    public function sendForgot(Request $request, Config $config, array $parameters): Response
    {
        if (!CsrfToken::validate('forgot_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $email = trim((string) $request->request->get('email'));

        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION[self::SESSION_FORGOT]['errors'] = ['Enter a valid email address.'];
            $_SESSION[self::SESSION_FORGOT]['values'] = ['email' => $email];
            return new RedirectResponse('/forgot-password');
        }

        $client = new CognitoClient($config);

        try {
            $client->forgotPassword($email);
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_FORGOT]['errors'] = [$this->mapForgotError($e)];
            $_SESSION[self::SESSION_FORGOT]['values'] = ['email' => $email];
            return new RedirectResponse('/forgot-password');
        }

        $_SESSION[self::SESSION_FORGOT]['success'] = 'We have emailed you a password reset code.';
        $_SESSION[self::SESSION_RESET]['email'] = $email;

        return new RedirectResponse('/reset-password?email=' . urlencode($email));
    }

    public function showReset(Request $request, Config $config, array $parameters): Response
    {
        $email = (string) ($request->query->get('email') ?: ($_SESSION[self::SESSION_RESET]['email'] ?? ''));
        $errors = $_SESSION[self::SESSION_RESET]['errors'] ?? [];
        $success = $_SESSION[self::SESSION_RESET]['success'] ?? null;
        unset($_SESSION[self::SESSION_RESET]['errors'], $_SESSION[self::SESSION_RESET]['success']);

        $csrfToken = CsrfToken::generate('reset_form');

        $content = View::render('password/reset', [
            'errors' => $errors,
            'success' => $success,
            'email' => $email,
            'csrf_token' => $csrfToken,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Create a new password',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    public function confirmReset(Request $request, Config $config, array $parameters): Response
    {
        if (!CsrfToken::validate('reset_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        $email = trim((string) $request->request->get('email'));
        $code = trim((string) $request->request->get('code'));
        $password = (string) $request->request->get('password');
        $confirm = (string) $request->request->get('password_confirmation');

        $errors = [];
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Enter a valid email address.';
        }
        if ($code === '') {
            $errors[] = 'Enter the verification code.';
        }
        if ($password === '') {
            $errors[] = 'Enter a new password.';
        }
        if ($password !== $confirm) {
            $errors[] = 'Passwords do not match.';
        }

        if ($errors !== []) {
            $_SESSION[self::SESSION_RESET]['errors'] = $errors;
            return new RedirectResponse('/reset-password?email=' . urlencode($email));
        }

        $client = new CognitoClient($config);

        try {
            $client->confirmForgotPassword($email, $code, $password);
        } catch (AwsException $e) {
            $_SESSION[self::SESSION_RESET]['errors'] = [$this->mapResetError($e)];
            return new RedirectResponse('/reset-password?email=' . urlencode($email));
        }

        $_SESSION['_oauth2']['success'] = 'Your password has been updated. Sign in with your new password.';
        unset($_SESSION[self::SESSION_RESET]);

        return new RedirectResponse('/oauth2/authorize');
    }

    private function mapForgotError(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'UserNotFoundException' => 'We could not find an account with that email.',
            default => 'We could not start the reset process. Please try again.',
        };
    }

    private function mapResetError(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'CodeMismatchException' => 'The code you entered is incorrect.',
            'ExpiredCodeException' => 'The code has expired. Request a new one.',
            default => 'We could not reset your password. Please try again.',
        };
    }
}
