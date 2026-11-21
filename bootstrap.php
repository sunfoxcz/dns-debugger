<?php

declare(strict_types=1);

if (PHP_VERSION_ID < 80400) {
    throw new RuntimeException('DNSSEC Debugger requires PHP 8.4 or later.');
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'DnsDebugger\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relativeClass) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
