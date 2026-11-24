<?php

namespace Kanboard\Plugin\Passkey\Helper;

use Kanboard\Core\Base;
use Kanboard\Plugin\Passkey\Auth\PasskeyTwoFactorProvider;

/**
 * Presentation bits the templates need.
 */
class PasskeyHelper extends Base
{
    /**
     * Well-known AAGUIDs, so a passkey list reads "iCloud Keychain" rather
     * than a hex string. The value is self-reported by the authenticator and
     * is not verified here — it labels a row, it never grants anything.
     *
     * Source: the community passkey AAGUID list maintained at
     * https://github.com/passkeydeveloper/passkey-authenticator-aaguids
     */
    private static $AUTHENTICATORS = array(
        'fbfc3007154e4ecc8c0b6e020557d7bd' => 'iCloud Keychain',
        'dd4ec289e01d41c9bb8970fa845d4bf2' => 'iCloud Keychain (Managed)',
        'adce000235bcc60a648b0b25f1f05503' => 'Chrome on Mac',
        'ea9b8d664d011d213ce4b6b48cb575d4' => 'Google Password Manager',
        '08987058cadc4b81b6e130de50dcbe96' => 'Windows Hello',
        '9ddd1817af5a4672a2b93e3dd95000a9' => 'Windows Hello',
        '6028b017b1d44c02b4b3afcdafc96bb2' => 'Windows Hello',
        'bada5566a7aa401fbd9645619a55120d' => '1Password',
        'd548826e79b4db40a3d811116f7e8349' => 'Bitwarden',
        '531126d6e717415c93203d9aa6981239' => 'Dashlane',
        'b84e404815dc4dd08640f4f60813c8af' => 'NordPass',
        '0ea242b443c44a1b8b17dd6d0b6baec6' => 'Keeper',
        'f38095407f1449c1a8b38f813b225541' => 'Enpass',
        '891494da2c904d31a9cd4eab0aed1309' => 'Sesame',
        '2fc0579f811347eab116bb5a8db9202a' => 'YubiKey 5 NFC',
        'cb69481e8ff7403993ec0a2729a154a8' => 'YubiKey 5',
        'ee882879721c491397753dfcce97072a' => 'YubiKey 5',
        'fa2b99dc9e3942578f924a30d23c4118' => 'YubiKey 5 NFC',
        'de1e552ddb1d4423a619566b625cdc84' => 'YubiKey 5',
        '73bb0cd4e50249b89c6fb59445bf720b' => 'YubiKey 5 FIPS',
        'd8522d9f575b488688a9ba99fa02f35b' => 'YubiKey Bio',
    );

    /**
     * @param  array $credential
     * @return string
     */
    public function getAuthenticatorName(array $credential)
    {
        $aaguid = strtolower(str_replace('-', '', (string) $credential['aaguid']));

        if (isset(self::$AUTHENTICATORS[$aaguid])) {
            return self::$AUTHENTICATORS[$aaguid];
        }

        // An all-zero AAGUID is what an authenticator sends when it declines
        // to identify itself, which most platform passkeys do.
        if ($aaguid === '' || trim($aaguid, '0') === '') {
            return t('Unknown provider');
        }

        return t('Security key');
    }

    /**
     * A passkey that is backup eligible is synced across the user's devices;
     * one that is not lives on a single authenticator and is lost with it.
     *
     * @param  array $credential
     * @return string
     */
    public function getStorageLabel(array $credential)
    {
        return $credential['is_backup_eligible'] == 1 ? t('Synced') : t('This device only');
    }

    /**
     * Options for the current 2FA challenge, or an empty string when the user
     * is not on the passkey path.
     *
     * @return string  JSON, ready for a data attribute
     */
    public function getTwoFactorOptions()
    {
        $options = (string) session_get(PasskeyTwoFactorProvider::SESSION_OPTIONS);

        if ($options === '') {
            return '';
        }

        // The options outlive the request that issued them, and the choice
        // that produced them can have changed since. Ask the provider rather
        // than trusting the session on its own.
        $provider = new PasskeyTwoFactorProvider($this->container);

        return $provider->usesPasskey() ? $options : '';
    }

    /**
     * @return bool
     */
    public function isTwoFactorPasskey()
    {
        return $this->getTwoFactorOptions() !== '';
    }

    /**
     * Where a passkey sign-in should land, rendered into the login page so the
     * browser knows before the ceremony starts.
     *
     * @return string  a same-site path, or '' for the dashboard
     */
    public function getLoginRedirect()
    {
        return $this->safeRedirect(session_get('redirectAfterLogin'));
    }

    /**
     * Where the second-factor prompt should land once it is answered.
     *
     * @return string  a same-site path, or '' for wherever core sends it
     */
    public function getTwoFactorRedirect()
    {
        return $this->safeRedirect(session_get(PasskeyTwoFactorProvider::SESSION_REDIRECT));
    }

    /**
     * Where core sends a second factor that did not check out. The prompt
     * compares against it to tell a failure from a success.
     *
     * @return string
     */
    public function getTwoFactorRetryUrl()
    {
        return $this->helper->url->to('TwoFactorController', 'code');
    }

    /**
     * @param  mixed $uri
     * @return string
     */
    private function safeRedirect($uri)
    {
        $uri = (string) $uri;

        return $this->request->isSafeRedirectUri($uri) ? $uri : '';
    }

    /**
     * A CSRF token for the fetch() calls.
     *
     * It goes in a data attribute rather than a hidden input because the
     * sign-in button is moved into the login form, and a second field named
     * csrf_token inside that form would be posted alongside the form's own.
     *
     * @return string
     */
    public function getCsrfToken()
    {
        return $this->token->getCSRFToken();
    }

    /**
     * The handful of strings the browser side needs, translated here so the
     * script itself carries no copy.
     *
     * @return string  JSON, ready for a data attribute
     */
    public function getMessages()
    {
        return json_encode(array(
            'cancelled' => t('The request was cancelled or timed out.'),
            'duplicate' => t('This device already holds a passkey for this account.'),
            'failed' => t('Your passkey could not be used.'),
            'working' => t('Waiting for your passkey...'),
        ));
    }

    /**
     * @return bool
     */
    public function isSignInAvailable()
    {
        return $this->passkeySettingsModel->isPasswordlessLoginEnabled() && $this->passkeyCredentialModel->hasAny();
    }
}
