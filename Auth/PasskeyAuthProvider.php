<?php

namespace Kanboard\Plugin\Passkey\Auth;

use Kanboard\Core\Base;
use Kanboard\Core\Security\OptionalAuthenticationProviderInterface;
use Kanboard\Core\Security\PreAuthenticationProviderInterface;
use Kanboard\User\DatabaseUserProvider;

/**
 * Turns a verified assertion into a Kanboard session.
 *
 * The signature check happens in the controller; by the time this provider
 * runs, the only thing left is to open the session. Going through the
 * authentication manager rather than writing the session directly is what
 * gets the login recorded, the lockout counter reset and every listener on
 * auth.success fired, exactly as a password login would.
 *
 * isEnabled() keeps the provider inert on ordinary requests: pre-authentication
 * providers run on every anonymous hit, and this one must only ever act on the
 * request that just completed a ceremony.
 */
class PasskeyAuthProvider extends Base implements PreAuthenticationProviderInterface, OptionalAuthenticationProviderInterface
{
    const NAME = 'Passkey';
    const SESSION_KEY = 'passkeyVerifiedUserId';

    /**
     * @var DatabaseUserProvider|null
     */
    private $userProvider = null;

    public function getName()
    {
        return self::NAME;
    }

    public function isEnabled()
    {
        return session_exists(self::SESSION_KEY);
    }

    public function authenticate()
    {
        $userId = (int) session_get(self::SESSION_KEY);

        // One shot: a stale value must never be able to open a second session.
        session_remove(self::SESSION_KEY);

        if ($userId <= 0) {
            return false;
        }

        $user = $this->userModel->getById($userId);

        if (empty($user) || $user['is_active'] != 1) {
            return false;
        }

        $this->userProvider = new DatabaseUserProvider($user);

        return true;
    }

    public function getUser()
    {
        return $this->userProvider;
    }
}
