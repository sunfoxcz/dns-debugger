<?php

declare(strict_types=1);

namespace DnsDebugger\Dnssec\Model;

enum Status: string
{
    case Ok = 'ok';
    case Warning = 'warning';
    case Error = 'error';
    case Info = 'info';
}
