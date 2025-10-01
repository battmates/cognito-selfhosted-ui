<?php

declare(strict_types=1);

namespace App\Config;

final class Config
{
    /** @var array<string, mixed> */
    private array $values;

    private function __construct(array $values)
    {
        $this->values = $values;
    }

    public static function fromEnvironment(): self
    {
        $allowedRedirects = self::env('ALLOWED_REDIRECTS', '');
        $redirects = array_filter(array_map('trim', explode(',', $allowedRedirects)));

        return new self([
            'environment' => self::env('APP_ENV', 'production'),
            'debug' => filter_var(self::env('APP_DEBUG', false), FILTER_VALIDATE_BOOLEAN),
            'app_url' => self::env('APP_URL', 'http://localhost:8000'),
            'session_secret' => self::env('SESSION_SECRET', ''),
            'cognito_region' => self::env('COGNITO_REGION', ''),
            'cognito_user_pool_id' => self::env('COGNITO_USER_POOL_ID', ''),
            'cognito_client_id' => self::env('COGNITO_CLIENT_ID', ''),
            'cognito_client_secret' => self::env('COGNITO_CLIENT_SECRET', ''),
            'allowed_redirects' => $redirects,
            'code_ttl' => (int) (self::env('CODE_TTL', 300)),
        ]);
    }

    private static function env(string $key, mixed $default = null): mixed
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

        if ($value === false || $value === null) {
            return $default;
        }

        return $value;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function isDebug(): bool
    {
        return (bool) $this->values['debug'];
    }

    /**
     * @return string[]
     */
    public function allowedRedirects(): array
    {
        return $this->values['allowed_redirects'];
    }

    public function codeTtl(): int
    {
        return $this->values['code_ttl'];
    }
}
