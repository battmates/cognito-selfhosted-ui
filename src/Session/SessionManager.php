<?php

declare(strict_types=1);

namespace App\Session;

use App\Config\Config;

final class SessionManager
{
    private const DEFAULT_NAME = 'cognito_ui_session';

    public static function start(Config $config): void
    {
        if (PHP_SAPI === 'cli' || session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $cookieParams = session_get_cookie_params();
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $cookieParams['path'] ?? '/',
            'domain' => $cookieParams['domain'] ?? '',
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        session_name(self::DEFAULT_NAME);
        session_start();
    }
}
