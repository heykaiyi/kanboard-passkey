<?php

namespace Kanboard\Plugin\Passkey\Auth;

use Kanboard\Auth\TotpAuth;
use Kanboard\Core\Base;
use Kanboard\Core\Security\PostAuthenticationProviderInterface;
use Kanboard\Plugin\Passkey\WebAuthn\Server;
use Kanboard\Plugin\Passkey\WebAuthn\WebAuthnException;

/**
 * The second factor, chosen per user.
 *
 * Kanboard keeps exactly one post-authentication provider — getPostAuthenticationProvider()
 * pops the last one registered — so a plugin that simply registers its own
 * would take two-factor authentication away from everyone still using a
 * one-time code. This provider therefore stands in front of the built-in TOTP
 * one and hands every call straight through unless the signed-in user has
 * actually chosen a passkey. Users on Google Authenticator keep the exact
 * behaviour they had; users on a passkey get a ceremony instead of a code.
 *
 * The assertion travels in the same `code` field the numeric form posts, which
 * is what lets the whole thing work through core's TwoFactorController without
 * touching it — and that matters, because PostAuthenticationMiddleware will
 * not route to any other controller while the second factor is pending.
 */
class PasskeyTwoFactorProvider extends Base implements PostAuthenticationProviderInterface
{
    const SESSION_CHALLENGE = 'passkeyTwoFactorChallenge';
    const SESSION_OPTIONS = 'passkeyTwoFactorOptions';

    /**
     * @var TotpAuth|null
     */
    private $totp = null;

    /**
     * @var string
     */
    private $code = '';

    /**
     * The name is also the key this provider is filed under, and it is read
     * at registration time — long before there is a session to ask about the
     * user. It therefore has to be constant, and it has to differ from
     * TotpAuth's, or one would silently replace the other in the registry.
     */
    public function getName()
    {
        return t('Passkey or one-time code');
    }

    /**
     * Called once before the user is prompted: issue the challenge.
     */
    public function beforeCode()
    {
        if (! $this->usesPasskey()) {
            session_remove(self::SESSION_OPTIONS);
            $this->getTotp()->beforeCode();
            return;
        }

        $userId = $this->userSession->getId();
        $challenge = Server::createChallenge();
        $options = $this->passkeySettingsModel->getServer()->getRequestOptions(
            $challenge,
            $this->passkeyCredentialModel->getCredentialIdsByUser($userId)
        );

        session_set(self::SESSION_CHALLENGE, base64_encode($challenge));
        session_set(self::SESSION_OPTIONS, json_encode($options));
    }

    public function authenticate()
    {
        if (! $this->usesPasskey()) {
            return $this->getTotp()->authenticate();
        }

        try {
            $this->verifyAssertion();
            return true;
        } catch (WebAuthnException $e) {
            $this->logger->info('Passkey second factor rejected: '.$e->getMessage());
            $this->resetChallenge();
            return false;
        }
    }

    public function setCode($code)
    {
        $this->code = (string) $code;
        $this->getTotp()->setCode($code);
    }

    public function generateSecret()
    {
        return $this->getTotp()->generateSecret();
    }

    public function setSecret($secret)
    {
        $this->getTotp()->setSecret($secret);
    }

    public function getSecret()
    {
        return $this->getTotp()->getSecret();
    }

    public function getKeyUrl($label)
    {
        return $this->getTotp()->getKeyUrl($label);
    }

    /**
     * @throws WebAuthnException
     */
    private function verifyAssertion()
    {
        $challenge = base64_decode((string) session_get(self::SESSION_CHALLENGE), true);

        if ($challenge === false || $challenge === '') {
            throw new WebAuthnException('No challenge is pending');
        }

        $assertion = json_decode($this->code, true);

        if (! is_array($assertion) || empty($assertion['id'])) {
            throw new WebAuthnException('The browser sent nothing to check');
        }

        $credential = $this->passkeyCredentialModel->getByCredentialId($assertion['id']);

        // The passkey has to belong to the half-authenticated user, or a
        // second factor would be no factor at all.
        if ($credential === null || (int) $credential['user_id'] !== $this->userSession->getId()) {
            throw new WebAuthnException('This passkey is not registered for this account');
        }

        $signCount = $this->passkeySettingsModel->getServer()->verifyRequest($assertion, $challenge, $credential);

        $this->passkeyCredentialModel->markAsUsed($credential['id'], $signCount);
        $this->resetChallenge();
    }

    /**
     * Drop the challenge so a retry gets a fresh one.
     *
     * TwoFactorController only calls beforeCode() when `twoFactorBeforeCodeCalled`
     * is unset, so clearing that here is what stops a failed attempt from
     * leaving the same challenge on the page.
     */
    private function resetChallenge()
    {
        session_remove(self::SESSION_CHALLENGE);
        session_remove(self::SESSION_OPTIONS);
        session_remove('twoFactorBeforeCodeCalled');
    }

    /**
     * Whether the signed-in user answers the second factor with a passkey.
     *
     * Public because the prompt template has to ask the same question, and one
     * of the two deciding it is one too many.
     *
     * Deliberately not memoised: the answer depends on session state that can
     * change within a request, and the provider is asked at most twice.
     *
     * @return bool
     */
    public function usesPasskey()
    {
        $userId = $this->userSession->getId();

        // A pending TOTP enrolment always wins: the user is on core's setup
        // screen and expects the code they just scanned to be checked.
        if ($userId <= 0 || session_exists('twoFactorSecret')) {
            return false;
        }

        $user = $this->userModel->getById($userId);

        return ! empty($user)
            && empty($user['twofactor_secret'])
            && $this->passkeySettingsModel->isTwoFactorPasskey($userId)
            && $this->passkeyCredentialModel->countByUser($userId) > 0;
    }

    /**
     * @return TotpAuth
     */
    private function getTotp()
    {
        if ($this->totp === null) {
            $this->totp = new TotpAuth($this->container);
        }

        return $this->totp;
    }
}
