<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

enum AuthMode: int
{
    case None = 0;
    case Password = 1;
    case PublicKey = 2;
    case Both = 3;

    public function needsPassword(): bool
    {
        return $this === self::Password || $this === self::Both;
    }

    public function needsKeys(): bool
    {
        return $this === self::PublicKey || $this === self::Both;
    }
}
