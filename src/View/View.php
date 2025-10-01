<?php

declare(strict_types=1);

namespace App\View;

final class View
{
    public static function render(string $template, array $data = []): string
    {
        $viewPath = self::resolvePath($template);
        extract($data, EXTR_SKIP);
        ob_start();
        include $viewPath;
        return (string) ob_get_clean();
    }

    private static function resolvePath(string $template): string
    {
        $root = dirname(__DIR__, 2);
        $path = $root . '/resources/views/' . str_replace('..', '', $template) . '.php';

        if (!is_file($path)) {
            throw new \RuntimeException(sprintf('View [%s] not found at path %s', $template, $path));
        }

        return $path;
    }
}
