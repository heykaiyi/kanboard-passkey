<?php

namespace Kanboard\Plugin\Passkey\Controller;

use Kanboard\Controller\BaseController;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Event\AuthFailureEvent;
use Kanboard\Event\AuthSuccessEvent;
use Kanboard\Plugin\Passkey\Auth\PasskeyAuthProvider;
use Kanboard\Plugin\Passkey\WebAuthn\Base64Url;
use Kanboard\Plugin\Passkey\WebAuthn\Server;
use Kanboard\Plugin\Passkey\WebAuthn\WebAuthnException;

/**
 * Signing in with a passkey and no password.
 *
 * The ceremony is usernameless: the request carries no allowCredentials list,
 * the authenticator offers whatever discoverable passkey it holds for this
 * site, and the account falls out of the credential id that comes back. That
 * is why nothing here takes a username — there is none to leak or to guess
 * against.
 */
class PasskeyLoginController extends BaseController
{
    const SESSION_CHALLENGE = 'passkeyLoginChallenge';

    /**
     * Issue the options for navigator.credentials.get().
     */
    public function options()
    {
        if (! $this->passkeySettingsModel->isPasswordlessLoginEnabled()) {
            $this->response->json(array('error' => t('Signing in with a passkey is disabled.')), 403);
            return;
        }

        $this->checkJsonCSRF();

        $challenge = Server::createChallenge();
        session_set(self::SESSION_CHALLENGE, base64_encode($challenge));

        $this->response->json(array(
            'publicKey' => $this->passkeySettingsModel->getServer()->getRequestOptions($challenge),
        ));
    }

    /**
     * Check the assertion and open a session.
     */
    public function verify()
    {
        if (! $this->passkeySettingsModel->isPasswordlessLoginEnabled()) {
            $this->response->json(array('error' => t('Signing in with a passkey is disabled.')), 403);
            return;
        }

        $this->checkJsonCSRF();

        $challenge = base64_decode((string) session_get(self::SESSION_CHALLENGE), true);
        session_remove(self::SESSION_CHALLENGE);

        if ($challenge === false || $challenge === '') {
            $this->response->json(array('error' => t('This sign-in took too long, please try again.')), 400);
            return;
        }

        $payload = $this->request->getJson();
        $assertion = isset($payload['credential']) && is_array($payload['credential']) ? $payload['credential'] : array();

        try {
            $credential = $this->findCredential($assertion);
            $signCount = $this->passkeySettingsModel->getServer()->verifyRequest($assertion, $challenge, $credential);
        } catch (WebAuthnException $e) {
            $this->logger->info('Passkey sign-in rejected: '.$e->getMessage());
            $this->dispatcher->dispatch(new AuthFailureEvent(), AuthenticationManager::EVENT_FAILURE);
            $this->response->json(array('error' => $e->getMessage()), 401);
            return;
        }

        $this->passkeyCredentialModel->markAsUsed($credential['id'], $signCount);

        // Open the session through the registered provider rather than by
        // hand, so the login is recorded and every auth.success listener runs
        // exactly as it would for a password login. The provider is invoked
        // by name instead of through preAuthentication(), which would walk
        // every other pre-authentication provider first.
        session_set(PasskeyAuthProvider::SESSION_KEY, (int) $credential['user_id']);
        $provider = $this->authenticationManager->getProvider(PasskeyAuthProvider::NAME);

        if (! $provider->authenticate() || ! $this->userProfile->initialize($provider->getUser())) {
            session_remove(PasskeyAuthProvider::SESSION_KEY);
            $this->dispatcher->dispatch(new AuthFailureEvent(), AuthenticationManager::EVENT_FAILURE);
            $this->response->json(array('error' => t('This account cannot sign in.')), 403);
            return;
        }

        $this->dispatcher->dispatch(new AuthSuccessEvent(PasskeyAuthProvider::NAME), AuthenticationManager::EVENT_SUCCESS);

        $this->response->json(array('redirect' => $this->getRedirectUrl()));
    }

    /**
     * @param  array $assertion
     * @return array
     * @throws WebAuthnException
     */
    private function findCredential(array $assertion)
    {
        if (empty($assertion['id'])) {
            throw new WebAuthnException(t('The browser sent nothing to check.'));
        }

        $credential = $this->passkeyCredentialModel->getByCredentialId($assertion['id']);

        if ($credential === null) {
            throw new WebAuthnException(t('This passkey is not registered here.'));
        }

        // A discoverable credential also names the account it belongs to. It
        // is not what the lookup is based on, but when the authenticator sends
        // it, it has to agree with what was stored at enrolment.
        $userHandle = isset($assertion['response']['userHandle']) ? $assertion['response']['userHandle'] : null;

        if (is_string($userHandle) && $userHandle !== '') {
            $expected = $this->passkeySettingsModel->getUserHandle($credential['user_id']);

            if (! hash_equals($expected, Base64Url::decode($userHandle))) {
                throw new WebAuthnException(t('This passkey belongs to a different account.'));
            }
        }

        return $credential;
    }

    private function getRedirectUrl()
    {
        $url = $this->helper->url->to('DashboardController', 'show');

        if (session_exists('redirectAfterLogin')) {
            if ($this->request->isSafeRedirectUri(session_get('redirectAfterLogin'))) {
                $url = session_get('redirectAfterLogin');
            }

            session_remove('redirectAfterLogin');
        }

        return $url;
    }

    /**
     * @throws \Kanboard\Core\Controller\AccessForbiddenException
     */
    private function checkJsonCSRF()
    {
        $payload = $this->request->getJson();

        if (! isset($payload['csrf_token']) || ! $this->token->validateCSRFToken($payload['csrf_token'])) {
            throw new \Kanboard\Core\Controller\AccessForbiddenException();
        }
    }
}
