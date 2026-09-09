<?php

namespace Kanboard\Plugin\Passkey\Test;

use Kanboard\Plugin\Passkey\WebAuthn\Base64Url;

/**
 * An authenticator built out of OpenSSL, so the tests exercise the real
 * parsing and signature paths rather than fixtures.
 *
 * It also contains the only CBOR *encoder* in the plugin: the server never
 * needs one, but producing an attestation object does.
 */
class VirtualAuthenticator
{
    public $credentialId;
    public $signCount = 0;

    private $key;
    private $rpId;
    private $algorithm;

    public function __construct($rpId, $algorithm = -7)
    {
        $this->rpId = $rpId;
        $this->algorithm = $algorithm;
        $this->credentialId = random_bytes(32);
        $this->key = $this->createKey($algorithm);
    }

    /**
     * @param  string $challenge  base64url, as the server issued it
     * @param  string $origin
     * @param  int    $flags
     * @return array  The shape navigator.credentials.create() returns
     */
    public function create($challenge, $origin, $flags = 0x45)
    {
        $authenticatorData = hash('sha256', $this->rpId, true)
            .chr($flags)
            .pack('N', $this->signCount)
            .str_repeat("\0", 16)
            .pack('n', strlen($this->credentialId))
            .$this->credentialId
            .$this->getCoseKey();

        $attestation = self::map(array(
            array(self::text('fmt'), self::text('none')),
            array(self::text('attStmt'), self::map(array())),
            array(self::text('authData'), self::bytes($authenticatorData)),
        ));

        return array(
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => array(
                'clientDataJSON' => Base64Url::encode($this->clientData('webauthn.create', $challenge, $origin)),
                'attestationObject' => Base64Url::encode($attestation),
                'transports' => array('internal'),
            ),
        );
    }

    /**
     * @param  string $challenge  base64url, as the server issued it
     * @param  string $origin
     * @param  int    $flags
     * @return array  The shape navigator.credentials.get() returns
     */
    public function get($challenge, $origin, $flags = 0x05)
    {
        $this->signCount++;

        $authenticatorData = hash('sha256', $this->rpId, true).chr($flags).pack('N', $this->signCount);
        $clientDataJson = $this->clientData('webauthn.get', $challenge, $origin);
        $signature = $this->sign($authenticatorData.hash('sha256', $clientDataJson, true));

        return array(
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => array(
                'clientDataJSON' => Base64Url::encode($clientDataJson),
                'authenticatorData' => Base64Url::encode($authenticatorData),
                'signature' => Base64Url::encode($signature),
                'userHandle' => null,
            ),
        );
    }

    /**
     * The PEM OpenSSL itself would write for this key, to compare against what
     * CoseKey builds from the coordinates.
     */
    public function getReferencePem()
    {
        if ($this->algorithm === -8) {
            return '';
        }

        $details = openssl_pkey_get_details($this->key);

        return trim($details['key']);
    }

    private function clientData($type, $challenge, $origin)
    {
        return json_encode(array(
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $origin,
            'crossOrigin' => false,
        ));
    }

    private function createKey($algorithm)
    {
        switch ($algorithm) {
            case -7:
                return openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
            case -35:
                return openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'));
            case -257:
                return openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048));
            case -8:
                return sodium_crypto_sign_keypair();
        }

        throw new \InvalidArgumentException('Unsupported test algorithm');
    }

    private function sign($data)
    {
        if ($this->algorithm === -8) {
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($this->key));
        }

        $digest = $this->algorithm === -35 ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA256;
        openssl_sign($data, $signature, $this->key, $digest);

        return $signature;
    }

    private function getCoseKey()
    {
        if ($this->algorithm === -8) {
            return self::map(array(
                array(self::int(1), self::int(1)),
                array(self::int(3), self::int(-8)),
                array(self::int(-1), self::int(6)),
                array(self::int(-2), self::bytes(sodium_crypto_sign_publickey($this->key))),
            ));
        }

        $details = openssl_pkey_get_details($this->key);

        if ($this->algorithm === -257) {
            return self::map(array(
                array(self::int(1), self::int(3)),
                array(self::int(3), self::int(-257)),
                array(self::int(-1), self::bytes($details['rsa']['n'])),
                array(self::int(-2), self::bytes($details['rsa']['e'])),
            ));
        }

        $curve = $this->algorithm === -35 ? 2 : 1;
        $size = $this->algorithm === -35 ? 48 : 32;

        return self::map(array(
            array(self::int(1), self::int(2)),
            array(self::int(3), self::int($this->algorithm)),
            array(self::int(-1), self::int($curve)),
            array(self::int(-2), self::bytes(str_pad($details['ec']['x'], $size, "\0", STR_PAD_LEFT))),
            array(self::int(-3), self::bytes(str_pad($details['ec']['y'], $size, "\0", STR_PAD_LEFT))),
        ));
    }

    // -- the CBOR encoder the server does not need ---------------------------

    public static function head($major, $value)
    {
        if ($value < 24) {
            return chr(($major << 5) | $value);
        }

        if ($value < 256) {
            return chr(($major << 5) | 24).chr($value);
        }

        if ($value < 65536) {
            return chr(($major << 5) | 25).pack('n', $value);
        }

        return chr(($major << 5) | 26).pack('N', $value);
    }

    public static function int($value)
    {
        return $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value);
    }

    public static function bytes($value)
    {
        return self::head(2, strlen($value)).$value;
    }

    public static function text($value)
    {
        return self::head(3, strlen($value)).$value;
    }

    public static function map(array $pairs)
    {
        $encoded = self::head(5, count($pairs));

        foreach ($pairs as $pair) {
            $encoded .= $pair[0].$pair[1];
        }

        return $encoded;
    }
}
