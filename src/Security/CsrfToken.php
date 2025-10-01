<?php

declare(strict_types=1);

namespace App\Security;

final class CsrfToken
{
    public const DEFAULT_NAMESPACE = '_csrf';

    public static function generate(string $key): string
    {
        self::ensureNamespace();
        $token = bin2hex(random_bytes(32));
        $_SESSION[self::DEFAULT_NAMESPACE][$key] = $token;

        return $token;
    }

    public static function validate(string $key, ?string $token): bool
    {
        self::ensureNamespace();

        if ($token === null) {
            return false;
        }

        $stored = $_SESSION[self::DEFAULT_NAMESPACE][$key] ?? null;
        if ($stored === null) {
            return false;
        }

        $isValid = hash_equals($stored, $token);
        unset($_SESSION[self::DEFAULT_NAMESPACE][$key]);

        return $isValid;
    }

    private static function ensureNamespace(): void
    {
        if (!isset($_SESSION[self::DEFAULT_NAMESPACE]) || !is_array($_SESSION[self::DEFAULT_NAMESPACE])) {
            $_SESSION[self::DEFAULT_NAMESPACE] = [];
        }
    }
}
