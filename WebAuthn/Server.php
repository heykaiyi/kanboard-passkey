<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * The two WebAuthn ceremonies, with no dependency on Kanboard.
 *
 * Attestation is requested as "none" and is not verified. That is the right
 * default outside an enterprise deployment: verifying it would mean shipping
 * and maintaining the FIDO metadata service, and it only answers "which brand
 * of authenticator is this", never "is this the right user". The credential
 * public key comes out of the same signed structure either way.
 */
class Server
{
    const CHALLENGE_BYTES = 32;

    private $rpId;
    private $rpName;
    private $origins;
    private $requireUserVerification;

    /**
     * @param string   $rpId                     Registrable domain, e.g. "kanboard.example.com"
     * @param string   $rpName                   Shown by the authenticator
     * @param string[] $origins                  Origins allowed to run a ceremony
     * @param bool     $requireUserVerification  Demand a PIN/biometric, not just a tap
     */
    public function __construct($rpId, $rpName, array $origins, $requireUserVerification = true)
    {
        $this->rpId = $rpId;
        $this->rpName = $rpName;
        $this->origins = $origins;
        $this->requireUserVerification = $requireUserVerification;
    }

    public static function createChallenge()
    {
        return random_bytes(self::CHALLENGE_BYTES);
    }

    /**
     * Options for navigator.credentials.create().
     *
     * @param  string $challenge          Raw challenge bytes
     * @param  array  $user               array('handle' => raw bytes, 'name' => string, 'displayName' => string)
     * @param  array  $excludeCredentials base64url credential ids already registered
     * @return array
     */
    public function getCreationOptions($challenge, array $user, array $excludeCredentials = array())
    {
        $parameters = array();

        foreach (CoseKey::supportedAlgorithms() as $algorithm) {
            $parameters[] = array('type' => 'public-key', 'alg' => $algorithm);
        }

        $exclude = array();

        foreach ($excludeCredentials as $credentialId) {
            $exclude[] = array('type' => 'public-key', 'id' => $credentialId);
        }

        return array(
            'rp' => array('id' => $this->rpId, 'name' => $this->rpName),
            'user' => array(
                'id' => Base64Url::encode($user['handle']),
                'name' => $user['name'],
                'displayName' => $user['displayName'],
            ),
            'challenge' => Base64Url::encode($challenge),
            'pubKeyCredParams' => $parameters,
            'timeout' => 120000,
            'excludeCredentials' => $exclude,
            'authenticatorSelection' => array(
                // "required" is what makes the credential discoverable, which
                // is what lets the user sign in without typing a username.
                'residentKey' => 'required',
                'requireResidentKey' => true,
                'userVerification' => $this->requireUserVerification ? 'required' : 'preferred',
            ),
            'attestation' => 'none',
        );
    }

    /**
     * Options for navigator.credentials.get().
     *
     * @param  string $challenge         Raw challenge bytes
     * @param  array  $allowCredentials  base64url credential ids; empty means "let the user pick"
     * @return array
     */
    public function getRequestOptions($challenge, array $allowCredentials = array())
    {
        $allow = array();

        foreach ($allowCredentials as $credentialId) {
            $allow[] = array('type' => 'public-key', 'id' => $credentialId);
        }

        return array(
            'challenge' => Base64Url::encode($challenge),
            'rpId' => $this->rpId,
            'timeout' => 120000,
            'allowCredentials' => $allow,
            'userVerification' => $this->requireUserVerification ? 'required' : 'preferred',
        );
    }

    /**
     * Check what came back from navigator.credentials.create().
     *
     * @param  array  $credential  The decoded JSON sent by the browser
     * @param  string $challenge   The raw challenge issued for this ceremony
     * @return array               Everything worth storing about the new credential
     * @throws WebAuthnException
     */
    public function verifyCreation(array $credential, $challenge)
    {
        $response = isset($credential['response']) && is_array($credential['response']) ? $credential['response'] : array();

        if (empty($response['clientDataJSON']) || empty($response['attestationObject'])) {
            throw new WebAuthnException('The browser sent an incomplete response');
        }

        $clientDataJson = Base64Url::decode($response['clientDataJSON']);
        $this->verifyClientData($clientDataJson, 'webauthn.create', $challenge);

        $attestation = CborDecoder::decodeAll(Base64Url::decode($response['attestationObject']));

        if (! is_array($attestation) || empty($attestation['authData'])) {
            throw new WebAuthnException('The attestation object is malformed');
        }

        $authenticatorData = AuthenticatorData::parse($attestation['authData']);
        $this->verifyAuthenticatorData($authenticatorData);

        if (! $authenticatorData->has(AuthenticatorData::FLAG_ATTESTED_DATA) || $authenticatorData->credentialId === '') {
            throw new WebAuthnException('The authenticator did not return a credential');
        }

        $key = CoseKey::toPublicKey($authenticatorData->credentialPublicKey);

        return array(
            'credential_id' => Base64Url::encode($authenticatorData->credentialId),
            'public_key' => $key['pem'],
            'algorithm' => $key['algorithm'],
            'sign_count' => $authenticatorData->signCount,
            'aaguid' => bin2hex($authenticatorData->aaguid),
            'transports' => $this->readTransports($response),
            'is_backup_eligible' => $authenticatorData->has(AuthenticatorData::FLAG_BACKUP_ELIGIBLE) ? 1 : 0,
        );
    }

    /**
     * Check what came back from navigator.credentials.get().
     *
     * @param  array  $credential  The decoded JSON sent by the browser
     * @param  string $challenge   The raw challenge issued for this ceremony
     * @param  array  $stored      The credential row: public_key, algorithm, sign_count
     * @return int                 The new signature counter, to be persisted
     * @throws WebAuthnException
     */
    public function verifyRequest(array $credential, $challenge, array $stored)
    {
        $response = isset($credential['response']) && is_array($credential['response']) ? $credential['response'] : array();

        if (empty($response['clientDataJSON']) || empty($response['authenticatorData']) || empty($response['signature'])) {
            throw new WebAuthnException('The browser sent an incomplete response');
        }

        $clientDataJson = Base64Url::decode($response['clientDataJSON']);
        $this->verifyClientData($clientDataJson, 'webauthn.get', $challenge);

        $rawAuthenticatorData = Base64Url::decode($response['authenticatorData']);
        $authenticatorData = AuthenticatorData::parse($rawAuthenticatorData);
        $this->verifyAuthenticatorData($authenticatorData);

        $signedData = $rawAuthenticatorData.hash('sha256', $clientDataJson, true);
        $signature = Base64Url::decode($response['signature']);

        if (! CoseKey::verify((int) $stored['algorithm'], $stored['public_key'], $signedData, $signature)) {
            throw new WebAuthnException('The passkey signature is not valid');
        }

        $this->verifySignCount($authenticatorData->signCount, (int) $stored['sign_count']);

        return $authenticatorData->signCount;
    }

    private function verifyClientData($json, $expectedType, $challenge)
    {
        $clientData = json_decode($json, true);

        if (! is_array($clientData)) {
            throw new WebAuthnException('The client data could not be read');
        }

        if (! isset($clientData['type']) || $clientData['type'] !== $expectedType) {
            throw new WebAuthnException('The client data is for a different operation');
        }

        if (! isset($clientData['challenge']) || ! hash_equals($challenge, Base64Url::decode($clientData['challenge']))) {
            throw new WebAuthnException('The challenge does not match');
        }

        if (! isset($clientData['origin']) || ! $this->isAllowedOrigin($clientData['origin'])) {
            // Naming it is what makes the log line actionable: this rejection
            // is almost always a misconfigured allowed-origins list, and
            // without the value there is nothing to compare it against.
            throw new WebAuthnException(sprintf(
                'This origin is not allowed to use passkeys: %s is not one of %s',
                isset($clientData['origin']) ? $clientData['origin'] : '(none sent)',
                implode(', ', $this->origins)
            ));
        }

        // A cross-origin ceremony means the page ran inside someone else's iframe.
        if (! empty($clientData['crossOrigin'])) {
            throw new WebAuthnException('Passkeys cannot be used from an embedded frame');
        }
    }

    private function verifyAuthenticatorData(AuthenticatorData $authenticatorData)
    {
        if (! hash_equals(hash('sha256', $this->rpId, true), $authenticatorData->rpIdHash)) {
            throw new WebAuthnException('The passkey belongs to a different site');
        }

        if (! $authenticatorData->has(AuthenticatorData::FLAG_USER_PRESENT)) {
            throw new WebAuthnException('The authenticator reported no user interaction');
        }

        if ($this->requireUserVerification && ! $authenticatorData->has(AuthenticatorData::FLAG_USER_VERIFIED)) {
            throw new WebAuthnException('Unlock the passkey with your PIN, fingerprint or face');
        }
    }

    /**
     * A counter that fails to move forward is how a cloned authenticator shows
     * itself. Synced passkeys report zero and are exempt, as the spec allows.
     */
    private function verifySignCount($received, $stored)
    {
        if ($received === 0 && $stored === 0) {
            return;
        }

        if ($received <= $stored) {
            throw new WebAuthnException('This passkey may have been cloned and was rejected');
        }
    }

    private function isAllowedOrigin($origin)
    {
        foreach ($this->origins as $allowed) {
            if (strcasecmp(rtrim($allowed, '/'), rtrim($origin, '/')) === 0) {
                return true;
            }
        }

        return false;
    }

    private function readTransports(array $response)
    {
        if (empty($response['transports']) || ! is_array($response['transports'])) {
            return '';
        }

        $transports = array_filter($response['transports'], function ($transport) {
            return is_string($transport) && preg_match('/^[a-z\-]{1,16}$/', $transport) === 1;
        });

        return implode(',', array_slice($transports, 0, 6));
    }
}
