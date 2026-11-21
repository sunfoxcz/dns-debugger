<?php

declare(strict_types=1);

namespace DnsDebugger\Renderer;

use DnsDebugger\Dnssec\Model\ChainResult;

interface ChainResultRenderer
{
    public function render(ChainResult $result): string;
}
