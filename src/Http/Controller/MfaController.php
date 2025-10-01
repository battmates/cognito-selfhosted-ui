<?php

declare(strict_types=1);

namespace App\Http\Controller;

use App\Auth\AuthorizationResponder;
use App\Auth\CognitoClient;
use App\Config\Config;
use App\Security\CsrfToken;
use App\View\View;
use Aws\Exception\AwsException;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class MfaController
{
    private const SESSION_NAMESPACE = '_oauth2';

    public function show(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $challenge = $_SESSION[self::SESSION_NAMESPACE]['challenge'] ?? null;
        if (!$challenge) {
            return new RedirectResponse('/oauth2/authorize');
        }

        return match ($challenge['name']) {
            'SELECT_MFA_TYPE' => $this->renderSelectChallenge($challenge),
            'MFA_SETUP' => $this->renderMfaSetup($challenge, $config),
            default => $this->renderCodeChallenge($challenge),
        };
    }

    public function verify(Request $request, Config $config, array $parameters): Response
    {
        $this->ensureSessionNamespace();

        $challenge = $_SESSION[self::SESSION_NAMESPACE]['challenge'] ?? null;
        if (!$challenge) {
            return new RedirectResponse('/oauth2/authorize');
        }

        if (!CsrfToken::validate('mfa_form', $request->request->get('_token'))) {
            return new Response('Invalid CSRF token', Response::HTTP_FORBIDDEN);
        }

        return match ($challenge['name']) {
            'SELECT_MFA_TYPE' => $this->handleSelectChallenge($challenge, $request, $config),
            'MFA_SETUP' => $this->handleMfaSetup($challenge, $request, $config),
            default => $this->handleCodeChallenge($challenge, $request, $config),
        };
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function renderCodeChallenge(array $challenge): Response
    {
        $errors = $_SESSION[self::SESSION_NAMESPACE]['challenge_errors'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['challenge_errors']);

        $debug = $_SESSION[self::SESSION_NAMESPACE]['debug'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['debug']);

        $csrfToken = CsrfToken::generate('mfa_form');

        $content = View::render('mfa/challenge', [
            'challenge' => $challenge,
            'errors' => $errors,
            'csrf_token' => $csrfToken,
            'instructions' => $this->instructionsForChallenge($challenge),
            'debug' => $debug,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Multi-factor authentication',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function renderSelectChallenge(array $challenge): Response
    {
        $errors = $_SESSION[self::SESSION_NAMESPACE]['challenge_errors'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['challenge_errors']);

        $debug = $_SESSION[self::SESSION_NAMESPACE]['debug'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['debug']);

        $options = $this->parseSelectableMfaOptions($challenge['params'] ?? []);
        $csrfToken = CsrfToken::generate('mfa_form');

        $content = View::render('mfa/select', [
            'options' => $options,
            'errors' => $errors,
            'csrf_token' => $csrfToken,
            'debug' => $debug,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Choose verification method',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function renderMfaSetup(array $challenge, Config $config): Response
    {
        $errors = $_SESSION[self::SESSION_NAMESPACE]['challenge_errors'] ?? [];
        unset($_SESSION[self::SESSION_NAMESPACE]['challenge_errors']);

        $challenge = $this->ensureSoftwareTokenSecret($challenge, $config);
        $_SESSION[self::SESSION_NAMESPACE]['challenge'] = $challenge;

        $csrfToken = CsrfToken::generate('mfa_form');
        $issuer = $this->issuerFromConfig($config);
        $otpauth = sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            rawurlencode($issuer),
            rawurlencode((string) $challenge['username']),
            $challenge['secret_code'],
            rawurlencode($issuer)
        );

        $qr = $this->generateQrCodeDataUri($otpauth);

        $content = View::render('mfa/setup', [
            'errors' => $errors,
            'csrf_token' => $csrfToken,
            'secret' => $challenge['secret_code'],
            'qr_code' => $qr,
            'debug' => $debug,
        ]);

        $html = View::render('layout/app', [
            'title' => 'Set up authenticator app',
            'content' => $content,
        ]);

        return new Response($html, Response::HTTP_OK);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function handleCodeChallenge(array $challenge, Request $request, Config $config): Response
    {
        $code = trim((string) $request->request->get('mfa_code'));
        if ($code === '') {
            $this->flashError('Please enter the verification code.');
            return new RedirectResponse('/mfa');
        }

        $client = new CognitoClient($config);
        $responses = $this->buildChallengeResponses($challenge, $code);

        try {
            $result = $client->respondToAuthChallenge($challenge['name'], $challenge['session'], $responses);
        } catch (AwsException $e) {
            $this->flashError($this->mapAwsExceptionToMessage($e));
            $this->flashDebug($challenge, $responses, $e);
            return new RedirectResponse('/mfa');
        }

        return $this->handleChallengeResult($challenge, $result, $config);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function handleSelectChallenge(array $challenge, Request $request, Config $config): Response
    {
        $choice = (string) $request->request->get('mfa_choice');
        if ($choice === '') {
            $this->flashError('Please choose a verification method.');
            return new RedirectResponse('/mfa');
        }

        $client = new CognitoClient($config);
        $payload = [
            'USERNAME' => $challenge['username'],
            'ANSWER' => $choice,
        ];

        try {
            $result = $client->respondToAuthChallenge('SELECT_MFA_TYPE', $challenge['session'], $payload);
        } catch (AwsException $e) {
            $this->flashError($this->mapAwsExceptionToMessage($e));
            $this->flashDebug($challenge, $payload, $e);
            return new RedirectResponse('/mfa');
        }

        return $this->handleChallengeResult($challenge, $result, $config);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function handleMfaSetup(array $challenge, Request $request, Config $config): Response
    {
        $code = trim((string) $request->request->get('mfa_code'));
        if ($code === '') {
            $this->flashError('Please enter the code from your authenticator app.');
            return new RedirectResponse('/mfa');
        }

        $client = new CognitoClient($config);

        try {
            $verification = $client->verifySoftwareToken($challenge['session'], $code);
        } catch (AwsException $e) {
            $this->flashError($this->mapAwsExceptionToMessage($e));
            $this->flashDebug($challenge, ['SOFTWARE_TOKEN_MFA_CODE' => $code], $e);
            return new RedirectResponse('/mfa');
        }

        $session = $verification['Session'] ?? $challenge['session'];

        try {
            $result = $client->respondToAuthChallenge('MFA_SETUP', $session, [
                'USERNAME' => $challenge['username'],
                'MFA_SETUP' => 'SOFTWARE_TOKEN_MFA',
            ]);
        } catch (AwsException $e) {
            $this->flashError($this->mapAwsExceptionToMessage($e));
            return new RedirectResponse('/mfa');
        }

        return $this->handleChallengeResult($challenge, $result, $config);
    }

    /**
     * @param array<string, mixed> $challenge
     * @param array<string, mixed> $result
     */
    private function handleChallengeResult(array $challenge, array $result, Config $config): Response
    {
        if (isset($result['ChallengeName'])) {
            $_SESSION[self::SESSION_NAMESPACE]['challenge'] = [
                'name' => $result['ChallengeName'],
                'session' => $result['Session'] ?? '',
                'username' => $challenge['username'],
                'params' => $result['ChallengeParameters'] ?? [],
                'auth_request' => $challenge['auth_request'],
            ];

            return new RedirectResponse('/mfa');
        }

        if (!isset($result['AuthenticationResult'])) {
            $this->flashError('Unexpected response from Cognito.');
            return new RedirectResponse('/mfa');
        }

        $responder = new AuthorizationResponder($config);
        $codeValue = $responder->generateCode($challenge['auth_request'], $result['AuthenticationResult'], $challenge['username']);

        unset($_SESSION[self::SESSION_NAMESPACE]['challenge']);
        $_SESSION[self::SESSION_NAMESPACE]['user'] = [
            'username' => $challenge['username'],
            'authenticated_at' => time(),
        ];

        return new RedirectResponse($responder->buildRedirectUrl($challenge['auth_request']['redirect_uri'], [
            'code' => $codeValue,
            'state' => $challenge['auth_request']['state'] ?? null,
        ]));
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function instructionsForChallenge(array $challenge): string
    {
        return match ($challenge['name']) {
            'SOFTWARE_TOKEN_MFA' => 'Enter the 6-digit code from your authenticator app.',
            'SMS_MFA' => sprintf('Enter the code sent to %s.', $challenge['params']['CODE_DELIVERY_DESTINATION'] ?? 'your phone'),
            'CUSTOM_CHALLENGE',
            'EMAIL_OTP' => sprintf('Enter the code sent to %s.', $challenge['params']['CODE_DELIVERY_DESTINATION'] ?? 'your email'),
            default => 'Enter the verification code to continue.',
        };
    }

    /**
     * @param array<string, mixed> $challenge
     * @return array<string, string>
     */
    private function buildChallengeResponses(array $challenge, string $code): array
    {
        $params = $challenge['params'] ?? [];
        $username = $params['USERNAME'] ?? $challenge['username'];

        $responses = [
            'USERNAME' => $username,
        ];

        if (isset($params['USER_ID_FOR_SRP'])) {
            $responses['USER_ID_FOR_SRP'] = $params['USER_ID_FOR_SRP'];
        }

        return match ($challenge['name']) {
            'SOFTWARE_TOKEN_MFA' => $responses + ['SOFTWARE_TOKEN_MFA_CODE' => $code],
            'SMS_MFA' => $responses + ['SMS_MFA_CODE' => $code],
            'EMAIL_OTP' => $responses + ['EMAIL_OTP_CODE' => $code],
            'CUSTOM_CHALLENGE' => $responses + ['ANSWER' => $code],
            default => throw new \RuntimeException('Unsupported challenge: ' . $challenge['name']),
        };
    }

    /**
     * @return array<int, array{value: string, label: string}>
     */
    private function parseSelectableMfaOptions(array $params): array
    {
        $raw = $params['MFAS_CAN_CHOOSE'] ?? $params['MFAS_CAN_SETUP'] ?? '';
        $parts = array_filter(array_map('trim', explode(',', (string) $raw)));

        $labels = [
            'SOFTWARE_TOKEN_MFA' => 'Authenticator app',
            'SMS_MFA' => 'Text message',
            'CUSTOM_CHALLENGE' => 'Email',
            'EMAIL_OTP' => 'Email',
        ];

        $options = [];
        foreach ($parts as $value) {
            $options[] = [
                'value' => $value,
                'label' => $labels[$value] ?? $value,
            ];
        }

        return $options;
    }

    /**
     * @param array<string, mixed> $challenge
     * @return array<string, mixed>
     */
    private function ensureSoftwareTokenSecret(array $challenge, Config $config): array
    {
        if (!empty($challenge['secret_code'])) {
            return $challenge;
        }

        $client = new CognitoClient($config);

        try {
            $response = $client->associateSoftwareToken($challenge['session']);
        } catch (AwsException $e) {
            $this->flashError($this->mapAwsExceptionToMessage($e));
            return $challenge;
        }

        $challenge['secret_code'] = $response['SecretCode'] ?? null;
        $challenge['session'] = $response['Session'] ?? $challenge['session'];

        return $challenge;
    }

    private function issuerFromConfig(Config $config): string
    {
        $url = (string) $config->get('app_url', 'Cognito Self-Hosted UI');
        $host = parse_url($url, PHP_URL_HOST);

        return $host ?: 'Cognito Self-Hosted UI';
    }

    private function generateQrCodeDataUri(string $otpauthUri): string
    {
        $renderer = new ImageRenderer(
            new RendererStyle(256),
            new SvgImageBackEnd()
        );
        $writer = new Writer($renderer);
        $svg = $writer->writeString($otpauthUri);

        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    private function flashError(string $message): void
    {
        $this->ensureSessionNamespace();
        $_SESSION[self::SESSION_NAMESPACE]['challenge_errors'][] = $message;
    }

    private function flashDebug(array $challenge, array $payload, AwsException $exception): void
    {
        if (!isset($_SESSION[self::SESSION_NAMESPACE]['debug'])) {
            $_SESSION[self::SESSION_NAMESPACE]['debug'] = [];
        }

        $_SESSION[self::SESSION_NAMESPACE]['debug'][] = [
            'challenge' => $challenge,
            'payload' => $payload,
            'error' => [
                'code' => $exception->getAwsErrorCode(),
                'message' => $exception->getAwsErrorMessage(),
            ],
        ];
    }

    private function mapAwsExceptionToMessage(AwsException $exception): string
    {
        return match ($exception->getAwsErrorCode()) {
            'CodeMismatchException' => 'The code you entered is incorrect. Please try again.',
            'ExpiredCodeException' => 'The verification code has expired. Request a new one and try again.',
            default => 'Verification failed. Please try again.',
        };
    }

    private function ensureSessionNamespace(): void
    {
        if (!isset($_SESSION[self::SESSION_NAMESPACE]) || !is_array($_SESSION[self::SESSION_NAMESPACE])) {
            $_SESSION[self::SESSION_NAMESPACE] = [];
        }
    }
}
