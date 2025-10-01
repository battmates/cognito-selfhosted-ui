<?php

declare(strict_types=1);

namespace App\Auth;

use App\Config\Config;

final class AuthorizationResponder
{
    private AuthorizationCodeStore $store;

    public function __construct(private Config $config)
    {
        $this->store = new AuthorizationCodeStore(dirname(__DIR__, 2) . '/storage/codes', $config->codeTtl());
    }

    /**
     * @param array<string, mixed> $authRequest
     * @param array<string, mixed> $authResult
     */
    public function generateCode(array $authRequest, array $authResult, string $username): string
    {
        $payload = [
            'client_id' => $authRequest['client_id'],
            'redirect_uri' => $authRequest['redirect_uri'],
            'username' => $username,
            'scope' => $authRequest['scope'] ?? '',
            'state' => $authRequest['state'] ?? null,
            'code_challenge' => $authRequest['code_challenge'] ?? null,
            'code_challenge_method' => $authRequest['code_challenge_method'] ?? null,
            'tokens' => [
                'access_token' => $authResult['AccessToken'] ?? null,
                'id_token' => $authResult['IdToken'] ?? null,
                'refresh_token' => $authResult['RefreshToken'] ?? null,
                'token_type' => $authResult['TokenType'] ?? 'Bearer',
                'expires_in' => $authResult['ExpiresIn'] ?? 3600,
            ],
        ];

        return $this->store->create($payload);
    }

    /**
     * @param array<string, mixed> $params
     */
    public function buildRedirectUrl(string $redirectUri, array $params): string
    {
        $filtered = array_filter($params, static fn($value) => $value !== null && $value !== '');
        if ($filtered === []) {
            return $redirectUri;
        }

        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        return $redirectUri . $separator . http_build_query($filtered);
    }
}
