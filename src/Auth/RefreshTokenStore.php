<?php

declare(strict_types=1);

namespace App\Auth;

use DateTimeImmutable;
use JsonException;

final class RefreshTokenStore
{
    private string $directory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, '/');

        if (!is_dir($this->directory)) {
            mkdir($this->directory, 0750, true);
        }
    }

    public function remember(string $refreshToken, string $username, string $clientId, string $scope = ''): void
    {
        $key = $this->hash($refreshToken);
        $record = [
            'username' => $username,
            'client_id' => $clientId,
            'scope' => $scope,
            'stored_at' => (new DateTimeImmutable())->format(DateTimeImmutable::ATOM),
        ];

        file_put_contents($this->pathFor($key), json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX);
    }

    /**
     * @return array<string, string>|null
     */
    public function find(string $refreshToken): ?array
    {
        $key = $this->hash($refreshToken);
        $path = $this->pathFor($key);

        if (!is_file($path)) {
            return null;
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            return null;
        }

        try {
            /** @var array<string, string> $data */
            $data = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            unlink($path);
            return null;
        }

        return $data;
    }

    public function forget(string $refreshToken): void
    {
        $key = $this->hash($refreshToken);
        $path = $this->pathFor($key);

        if (is_file($path)) {
            unlink($path);
        }
    }

    private function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    private function pathFor(string $key): string
    {
        return $this->directory . '/' . $key . '.json';
    }
}
