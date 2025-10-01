<?php

declare(strict_types=1);

namespace App\Support;

final class Environment
{
    /**
     * Ensure selected keys are also available via getenv() for libraries relying on process env.
     *
     * @param array<int, string> $keys
     */
    public static function syncToGetenv(array $keys): void
    {
        foreach ($keys as $key) {
            if ($key === '') {
                continue;
            }

            $value = $_ENV[$key] ?? $_SERVER[$key] ?? null;
            if ($value === null) {
                continue;
            }

            if (getenv($key) === false) {
                putenv($key . '=' . $value);
            }
        }
    }
}
