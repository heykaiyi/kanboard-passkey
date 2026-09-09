<?php

namespace Kanboard\Plugin\Passkey\Model;

use Kanboard\Core\Base;
use Kanboard\Plugin\Passkey\WebAuthn\Base64Url;
use Kanboard\Plugin\Passkey\WebAuthn\Server;

/**
 * Everything the ceremonies need to know about this installation, plus the
 * two per-user switches.
 *
 * The relying party id is the one setting that cannot be guessed wrong
 * quietly: a passkey is bound to it forever, so changing it later orphans
 * every credential already enrolled. It is derived from the configured
 * application URL — the value an administrator already had to get right for
 * email links to work — and only falls back to the request when that is unset.
 */
class PasskeySettingsModel extends Base
{
    const KEY_RP_ID = 'passkey_rp_id';
    const KEY_RP_NAME = 'passkey_rp_name';
    const KEY_ORIGINS = 'passkey_origins';
    const KEY_USER_VERIFICATION = 'passkey_user_verification';
    const KEY_PASSWORDLESS = 'passkey_passwordless';

    const META_TWO_FACTOR = 'passkey.two_factor';
    const META_USER_HANDLE = 'passkey.user_handle';

    /**
     * @return Server
     */
    public function getServer()
    {
        return new Server(
            $this->getRelyingPartyId(),
            $this->getRelyingPartyName(),
            $this->getAllowedOrigins(),
            $this->isUserVerificationRequired()
        );
    }

    /**
     * @return string
     */
    public function getRelyingPartyId()
    {
        $configured = trim($this->configModel->get(self::KEY_RP_ID, ''));

        if ($configured !== '') {
            return $configured;
        }

        $host = parse_url($this->getApplicationUrl(), PHP_URL_HOST);

        return $host ?: $this->getRequestHost();
    }

    /**
     * @return string
     */
    public function getRelyingPartyName()
    {
        $configured = trim($this->configModel->get(self::KEY_RP_NAME, ''));

        return $configured !== '' ? $configured : ($this->configModel->get('application_title', '') ?: 'Kanboard');
    }

    /**
     * An origin is a scheme, a host and a port — never a bare hostname.
     *
     * Administrators reasonably type just the host, because that is what the
     * relying party id field right above wants. Read literally that matches
     * nothing the browser will ever send, and every ceremony then fails with
     * "this origin is not allowed", which says nothing about what to fix. So
     * a value with no scheme is read as the origin it plainly meant.
     *
     * @param  string $value
     * @return string
     */
    public static function normalizeOrigin($value)
    {
        $value = rtrim(trim($value), '/');

        if ($value === '' || strpos($value, '://') !== false) {
            return $value;
        }

        $host = preg_replace('/:\d+$/', '', $value);

        // Loopback is the one place a browser treats plain HTTP as secure,
        // so it is the one place https would be the wrong guess.
        $scheme = in_array($host, array('localhost', '127.0.0.1', '[::1]'), true) ? 'http' : 'https';

        return $scheme.'://'.$value;
    }

    /**
     * @return string[]
     */
    public function getAllowedOrigins()
    {
        $configured = trim($this->configModel->get(self::KEY_ORIGINS, ''));

        if ($configured !== '') {
            $origins = array_map(array(__CLASS__, 'normalizeOrigin'), explode(',', $configured));

            return array_values(array_unique(array_filter($origins)));
        }

        $applicationUrl = $this->getApplicationUrl();

        if ($applicationUrl !== '') {
            $parts = parse_url($applicationUrl);

            if (! empty($parts['scheme']) && ! empty($parts['host'])) {
                $port = empty($parts['port']) ? '' : ':'.$parts['port'];
                return array($parts['scheme'].'://'.$parts['host'].$port);
            }
        }

        return array($this->getRequestOrigin());
    }

    /**
     * A passkey that only proves presence is a single factor. Requiring
     * verification is what makes it stand in for a password plus a code.
     *
     * @return bool
     */
    public function isUserVerificationRequired()
    {
        return $this->configModel->get(self::KEY_USER_VERIFICATION, 'required') !== 'preferred';
    }

    /**
     * @return bool
     */
    public function isPasswordlessLoginEnabled()
    {
        return $this->configModel->get(self::KEY_PASSWORDLESS, '1') === '1';
    }

    /**
     * Does this user use a passkey instead of a one-time code as second factor?
     *
     * @param  int $userId
     * @return bool
     */
    public function isTwoFactorPasskey($userId)
    {
        return $this->userMetadataModel->get($userId, self::META_TWO_FACTOR, '0') === '1';
    }

    /**
     * @param  int  $userId
     * @param  bool $enabled
     */
    public function setTwoFactorPasskey($userId, $enabled)
    {
        $this->userMetadataModel->save($userId, array(self::META_TWO_FACTOR => $enabled ? '1' : '0'));
    }

    /**
     * The opaque handle the authenticator stores next to the passkey.
     *
     * It has to stay the same for the life of the account so every passkey
     * groups under one entry in the user's password manager, and it must not
     * be the Kanboard user id — that would put an internal identifier into a
     * credential anyone can read off the device.
     *
     * @param  int $userId
     * @return string  Raw bytes
     */
    public function getUserHandle($userId)
    {
        $handle = $this->userMetadataModel->get($userId, self::META_USER_HANDLE, '');

        if ($handle === '') {
            $handle = Base64Url::encode(random_bytes(32));
            $this->userMetadataModel->save($userId, array(self::META_USER_HANDLE => $handle));
        }

        return Base64Url::decode($handle);
    }

    private function getApplicationUrl()
    {
        return trim($this->configModel->get('application_url', ''));
    }

    private function getRequestHost()
    {
        $host = $this->request->getServerVariable('HTTP_HOST');
        $host = preg_replace('/:\d+$/', '', (string) $host);

        return $host === '' ? 'localhost' : $host;
    }

    private function getRequestOrigin()
    {
        $host = (string) $this->request->getServerVariable('HTTP_HOST');

        if ($host === '') {
            return 'http://localhost';
        }

        return ($this->request->isHTTPS() ? 'https' : 'http').'://'.$host;
    }
}
