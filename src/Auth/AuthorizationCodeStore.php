<?php

declare(strict_types=1);

namespace App\Auth;

use DateInterval;
use DateTimeImmutable;
use JsonException;
use Ramsey\Uuid\Uuid;

final class AuthorizationCodeStore
{
    private string $directory;
    private int $ttl;

    public function __construct(string $directory, int $ttl)
    {
        $this->directory = rtrim($directory, '/');
        $this->ttl = $ttl;

        if (!is_dir($this->directory)) {
            mkdir($this->directory, 0750, true);
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function create(array $payload): string
    {
        $code = str_replace('-', '', Uuid::uuid4()->toString());
        $expiresAt = (new DateTimeImmutable())->add(new DateInterval(sprintf('PT%dS', $this->ttl)));

        $record = array_merge($payload, [
            'code' => $code,
            'expires_at' => $expiresAt->format(DateTimeImmutable::ATOM),
            'issued_at' => (new DateTimeImmutable())->format(DateTimeImmutable::ATOM),
        ]);

        $path = $this->pathFor($code);
        file_put_contents($path, json_encode($record, JSON_THROW_ON_ERROR), LOCK_EX);

        return $code;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function get(string $code): ?array
    {
        $path = $this->pathFor($code);

        if (!is_file($path)) {
            return null;
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            return null;
        }

        try {
            $data = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            unlink($path);
            return null;
        }

        $expiresAt = new DateTimeImmutable($data['expires_at'] ?? 'now');

        if ($expiresAt < new DateTimeImmutable()) {
            unlink($path);
            return null;
        }

        return $data;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function consume(string $code): ?array
    {
        $data = $this->get($code);

        if ($data !== null) {
            $path = $this->pathFor($code);
            if (is_file($path)) {
                unlink($path);
            }
        }

        return $data;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function redeem(string $code): ?array
    {
        return $this->consume($code);
    }

    private function pathFor(string $code): string
    {
        return $this->directory . '/' . $code . '.json';
    }
}
