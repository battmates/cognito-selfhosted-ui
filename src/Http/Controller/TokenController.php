<?php

declare(strict_types=1);

namespace App\Http\Controller;

use App\Auth\AuthorizationCodeStore;
use App\Auth\CognitoClient;
use App\Auth\RefreshTokenStore;
use App\Config\Config;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class TokenController
{
    public function exchange(Request $request, Config $config, array $parameters): Response
    {
        $request->request->add($request->query->all());

        $grantType = (string) $request->request->get('grant_type');

        return match ($grantType) {
            'authorization_code' => $this->handleAuthorizationCode($request, $config),
            'refresh_token' => $this->handleRefreshToken($request, $config),
            default => $this->error('unsupported_grant_type', 'Grant type is not supported', Response::HTTP_BAD_REQUEST),
        };
    }

    private function handleAuthorizationCode(Request $request, Config $config): Response
    {
        [$clientId, $clientSecret] = $this->extractClientCredentials($request);

        if (!$this->validateClient($clientId, $clientSecret, $config)) {
            return $this->error('invalid_client', 'Client authentication failed', Response::HTTP_UNAUTHORIZED);
        }

        $code = (string) $request->request->get('code');
        $redirectUri = (string) $request->request->get('redirect_uri');

        if ($code === '' || $redirectUri === '') {
            return $this->error('invalid_request', 'code and redirect_uri are required', Response::HTTP_BAD_REQUEST);
        }

        $store = new AuthorizationCodeStore(dirname(__DIR__, 3) . '/storage/codes', $config->codeTtl());
        $record = $store->get($code);

        if ($record === null) {
            return $this->error('invalid_grant', 'Authorization code is invalid or expired', Response::HTTP_BAD_REQUEST);
        }

        if (!hash_equals($record['client_id'], (string) $clientId)) {
            return $this->error('invalid_grant', 'Authorization code was not issued to this client', Response::HTTP_BAD_REQUEST);
        }

        if (!hash_equals($record['redirect_uri'], $redirectUri)) {
            return $this->error('invalid_grant', 'redirect_uri does not match the original authorization request', Response::HTTP_BAD_REQUEST);
        }

        if (!$this->validatePkce($record, $request)) {
            return $this->error('invalid_grant', 'PKCE verification failed', Response::HTTP_BAD_REQUEST);
        }

        $record = $store->consume($code) ?? $record;

        $tokens = $record['tokens'] ?? [];

        if (!is_array($tokens) || empty($tokens['access_token'])) {
            return $this->error('invalid_grant', 'Authorization code payload is invalid', Response::HTTP_BAD_REQUEST);
        }

        $response = [
            'access_token' => $tokens['access_token'],
            'id_token' => $tokens['id_token'] ?? null,
            'token_type' => $tokens['token_type'] ?? 'Bearer',
            'expires_in' => (int) ($tokens['expires_in'] ?? 3600),
            'scope' => $record['scope'] ?? '',
        ];

        if (!empty($tokens['refresh_token'])) {
            $response['refresh_token'] = $tokens['refresh_token'];

            $refreshStore = new RefreshTokenStore(dirname(__DIR__, 3) . '/storage/refresh');
            $refreshStore->remember($tokens['refresh_token'], (string) $record['username'], (string) $record['client_id'], (string) ($record['scope'] ?? ''));
        }

        return new JsonResponse(array_filter($response, static fn($value) => $value !== null));
    }

    private function handleRefreshToken(Request $request, Config $config): Response
    {
        [$clientId, $clientSecret] = $this->extractClientCredentials($request);

        if (!$this->validateClient($clientId, $clientSecret, $config)) {
            return $this->error('invalid_client', 'Client authentication failed', Response::HTTP_UNAUTHORIZED);
        }

        $refreshToken = (string) $request->request->get('refresh_token');

        if ($refreshToken === '') {
            return $this->error('invalid_request', 'refresh_token is required', Response::HTTP_BAD_REQUEST);
        }

        $refreshStore = new RefreshTokenStore(dirname(__DIR__, 3) . '/storage/refresh');
        $record = $refreshStore->find($refreshToken);

        if ($record === null || !hash_equals($record['client_id'], (string) $clientId)) {
            return $this->error('invalid_grant', 'Refresh token is invalid or does not belong to this client', Response::HTTP_BAD_REQUEST);
        }

        $client = new CognitoClient($config);
        try {
            $result = $client->initiateRefreshTokenAuth($refreshToken, $record['username']);
        } catch (\Throwable) {
            $refreshStore->forget($refreshToken);
            return $this->error('invalid_grant', 'Refresh token could not be used', Response::HTTP_BAD_REQUEST);
        }

        $tokens = $result['AuthenticationResult'] ?? [];
        if (!is_array($tokens) || empty($tokens['AccessToken'])) {
            return $this->error('invalid_grant', 'Invalid response from Cognito during refresh', Response::HTTP_BAD_REQUEST);
        }

        $response = [
            'access_token' => $tokens['AccessToken'],
            'id_token' => $tokens['IdToken'] ?? null,
            'token_type' => $tokens['TokenType'] ?? 'Bearer',
            'expires_in' => (int) ($tokens['ExpiresIn'] ?? 3600),
            'scope' => $record['scope'] ?? '',
            'refresh_token' => $refreshToken,
        ];

        return new JsonResponse(array_filter($response, static fn($value) => $value !== null));
    }

    private function validatePkce(array $record, Request $request): bool
    {
        $codeChallenge = $record['code_challenge'] ?? null;
        if ($codeChallenge === null || $codeChallenge === '') {
            return true;
        }

        $codeVerifier = (string) $request->request->get('code_verifier');
        if ($codeVerifier === '') {
            return false;
        }

        $method = strtolower((string) ($record['code_challenge_method'] ?? 'plain'));

        return match ($method) {
            's256' => hash_equals($codeChallenge, $this->base64UrlEncode(hash('sha256', $codeVerifier, true))),
            'plain' => hash_equals($codeChallenge, $codeVerifier),
            default => false,
        };
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function extractClientCredentials(Request $request): array
    {
        $clientId = $request->request->get('client_id');
        $clientSecret = $request->request->get('client_secret');

        $authHeader = $request->headers->get('Authorization');
        if ($authHeader && str_starts_with($authHeader, 'Basic ')) {
            $decoded = base64_decode(substr($authHeader, 6), true);
            if ($decoded !== false) {
                [$id, $secret] = array_pad(explode(':', $decoded, 2), 2, null);
                $clientId = $id;
                $clientSecret = $secret;
            }
        }

        return [
            $clientId !== null ? (string) $clientId : null,
            $clientSecret !== null ? (string) $clientSecret : null,
        ];
    }

    private function validateClient(?string $clientId, ?string $clientSecret, Config $config): bool
    {
        if ($clientId === null || $clientId !== $config->get('cognito_client_id')) {
            return false;
        }

        $configuredSecret = (string) $config->get('cognito_client_secret');

        if ($configuredSecret === '') {
            return true;
        }

        return $clientSecret !== null && hash_equals($configuredSecret, $clientSecret);
    }

    private function error(string $type, string $description, int $status): Response
    {
        return new JsonResponse([
            'error' => $type,
            'error_description' => $description,
        ], $status);
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
