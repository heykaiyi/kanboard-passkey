<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

use RuntimeException;

/**
 * Raised whenever a ceremony cannot be completed.
 *
 * The message is written to be shown to the user as-is: it says what failed,
 * never why in terms an attacker could use to probe the server.
 */
class WebAuthnException extends RuntimeException
{
}
