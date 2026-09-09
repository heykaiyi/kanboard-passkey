<?php

namespace Kanboard\Plugin\Passkey\Controller;

use Kanboard\Controller\UserViewController;
use Kanboard\Core\Controller\AccessForbiddenException;
use Kanboard\Plugin\Passkey\WebAuthn\Server;
use Kanboard\Plugin\Passkey\WebAuthn\WebAuthnException;

/**
 * Where a user enrols and manages their own passkeys.
 */
class PasskeyController extends UserViewController
{
    const SESSION_CHALLENGE = 'passkeyRegistrationChallenge';

    /**
     * List of passkeys and the second-factor choice.
     */
    public function index()
    {
        $user = $this->getCurrentUser();

        $this->response->html($this->helper->layout->user('Passkey:passkey/index', array(
            'user' => $user,
            'credentials' => $this->passkeyCredentialModel->getAllByUser($user['id']),
            'two_factor_passkey' => $this->passkeySettingsModel->isTwoFactorPasskey($user['id']),
            'two_factor_activated' => $user['twofactor_activated'] == 1,
            'has_totp_secret' => ! empty($user['twofactor_secret']),
            'passwordless_enabled' => $this->passkeySettingsModel->isPasswordlessLoginEnabled(),
            'relying_party_id' => $this->passkeySettingsModel->getRelyingPartyId(),
            'title' => t('Passkeys'),
        )));
    }

    /**
     * Issue the options for navigator.credentials.create().
     */
    public function createOptions()
    {
        $user = $this->getCurrentUser();
        $this->checkJsonCSRF();

        $challenge = Server::createChallenge();
        session_set(self::SESSION_CHALLENGE, base64_encode($challenge));

        $options = $this->passkeySettingsModel->getServer()->getCreationOptions(
            $challenge,
            array(
                'handle' => $this->passkeySettingsModel->getUserHandle($user['id']),
                'name' => $user['username'],
                'displayName' => $user['name'] ?: $user['username'],
            ),
            // Offering the existing credentials keeps the authenticator from
            // silently enrolling the same device twice.
            $this->passkeyCredentialModel->getCredentialIdsByUser($user['id'])
        );

        $this->response->json(array('publicKey' => $options));
    }

    /**
     * Store what navigator.credentials.create() produced.
     */
    public function createVerify()
    {
        $user = $this->getCurrentUser();
        $this->checkJsonCSRF();

        $payload = $this->request->getJson();
        $challenge = base64_decode((string) session_get(self::SESSION_CHALLENGE), true);
        session_remove(self::SESSION_CHALLENGE);

        if ($challenge === false || $challenge === '') {
            $this->response->json(array('error' => t('This registration took too long, please try again.')), 400);
            return;
        }

        try {
            $credential = $this->passkeySettingsModel->getServer()->verifyCreation(
                isset($payload['credential']) && is_array($payload['credential']) ? $payload['credential'] : array(),
                $challenge
            );
        } catch (WebAuthnException $e) {
            $this->logger->info('Passkey registration rejected: '.$e->getMessage());
            $this->response->json(array('error' => $e->getMessage()), 400);
            return;
        }

        if ($this->passkeyCredentialModel->getByCredentialId($credential['credential_id']) !== null) {
            $this->response->json(array('error' => t('This passkey is already registered.')), 400);
            return;
        }

        $name = trim((string) (isset($payload['name']) ? $payload['name'] : ''));
        $name = $name === '' ? t('Passkey') : mb_substr($name, 0, 100);

        if (! $this->passkeyCredentialModel->create($user['id'], $credential, $name)) {
            $this->response->json(array('error' => t('Unable to save this passkey.')), 500);
            return;
        }

        $this->flash->success(t('Passkey registered successfully.'));

        $this->response->json(array(
            'redirect' => $this->helper->url->to('PasskeyController', 'index', array('user_id' => $user['id'], 'plugin' => 'Passkey')),
        ));
    }

    /**
     * Ask before removing a passkey.
     */
    public function confirm()
    {
        $user = $this->getCurrentUser();
        $credential = $this->getCredential($user);

        $this->response->html($this->helper->layout->user('Passkey:passkey/remove', array(
            'user' => $user,
            'credential' => $credential,
        )));
    }

    /**
     * Remove a passkey.
     */
    public function remove()
    {
        $this->checkCSRFParam();
        $user = $this->getCurrentUser();
        $credential = $this->getCredential($user);

        if ($this->passkeyCredentialModel->remove($credential['id'], $user['id'])) {
            $this->flash->success(t('Passkey removed successfully.'));
        } else {
            $this->flash->failure(t('Unable to remove this passkey.'));
        }

        // A second factor with no passkey left behind it would lock the user
        // out on the next login.
        if ($this->passkeyCredentialModel->countByUser($user['id']) === 0 && $this->passkeySettingsModel->isTwoFactorPasskey($user['id'])) {
            $this->disablePasskeyTwoFactor($user['id']);
            $this->flash->failure(t('Two-factor authentication was turned off because your last passkey is gone.'));
        }

        $this->response->redirect($this->helper->url->to('PasskeyController', 'index', array('user_id' => $user['id'], 'plugin' => 'Passkey')), true);
    }

    /**
     * Rename a passkey.
     */
    public function rename()
    {
        $this->checkCSRFForm();
        $user = $this->getCurrentUser();
        $credential = $this->getCredential($user);
        $values = $this->request->getValues();

        $name = trim((string) (isset($values['name']) ? $values['name'] : ''));

        if ($name === '') {
            $this->flash->failure(t('The name cannot be empty.'));
        } else {
            $this->passkeyCredentialModel->rename($credential['id'], $user['id'], mb_substr($name, 0, 100));
            $this->flash->success(t('Passkey renamed successfully.'));
        }

        $this->response->redirect($this->helper->url->to('PasskeyController', 'index', array('user_id' => $user['id'], 'plugin' => 'Passkey')));
    }

    /**
     * Switch the second factor between a one-time code and a passkey.
     */
    public function saveTwoFactor()
    {
        $this->checkCSRFForm();
        $user = $this->getCurrentUser();
        $values = $this->request->getValues();
        $wantsPasskey = ! empty($values['two_factor_passkey']);

        if ($wantsPasskey && $this->passkeyCredentialModel->countByUser($user['id']) === 0) {
            $this->flash->failure(t('Register a passkey first.'));
        } elseif ($wantsPasskey) {
            $this->enablePasskeyTwoFactor($user['id']);
            $this->flash->success(t('Your passkey is now your second factor.'));
        } else {
            $this->disablePasskeyTwoFactor($user['id']);
            $this->flash->success(t('Two-factor authentication with a passkey is turned off.'));
        }

        $this->response->redirect($this->helper->url->to('PasskeyController', 'index', array('user_id' => $user['id'], 'plugin' => 'Passkey')));
    }

    private function enablePasskeyTwoFactor($userId)
    {
        $this->passkeySettingsModel->setTwoFactorPasskey($userId, true);

        // Clearing the TOTP secret is what tells the provider which factor to
        // ask for; leaving both configured would be ambiguous.
        $this->userModel->update(array(
            'id' => $userId,
            'twofactor_activated' => 1,
            'twofactor_secret' => '',
        ));

        $this->userSession->setPostAuthenticationAsValidated();
    }

    private function disablePasskeyTwoFactor($userId)
    {
        $this->passkeySettingsModel->setTwoFactorPasskey($userId, false);

        $user = $this->userModel->getById($userId);

        // Only turn the whole feature off when the passkey was what was
        // holding it up; a user who also set up a one-time code keeps it.
        if (! empty($user) && empty($user['twofactor_secret'])) {
            $this->userModel->update(array('id' => $userId, 'twofactor_activated' => 0));
            $this->userSession->disablePostAuthentication();
        }
    }

    /**
     * Passkeys are personal: not even an administrator manages someone else's.
     *
     * @return array
     * @throws AccessForbiddenException
     */
    private function getCurrentUser()
    {
        $user = $this->getUser();

        if ($user['id'] != $this->userSession->getId()) {
            throw new AccessForbiddenException();
        }

        return $user;
    }

    /**
     * @param  array $user
     * @return array
     * @throws AccessForbiddenException
     */
    private function getCredential(array $user)
    {
        $credential = $this->passkeyCredentialModel->getById($this->request->getIntegerParam('credential_id'), $user['id']);

        if ($credential === null) {
            throw new AccessForbiddenException();
        }

        return $credential;
    }

    /**
     * The token travels in the JSON body: these endpoints are called by fetch(),
     * not by a form.
     *
     * @throws AccessForbiddenException
     */
    private function checkJsonCSRF()
    {
        $payload = $this->request->getJson();

        if (! isset($payload['csrf_token']) || ! $this->token->validateCSRFToken($payload['csrf_token'])) {
            throw new AccessForbiddenException();
        }
    }
}
