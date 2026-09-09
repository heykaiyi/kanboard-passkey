<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * A COSE_Key (RFC 8152) as an authenticator hands it over, turned into
 * something OpenSSL or libsodium can verify with.
 *
 * The three algorithms below are what real authenticators ship: ES256 for
 * everything Apple, Android and every FIDO2 key; RS256 for Windows Hello on
 * older TPMs; EdDSA for a handful of security keys. PS256 is deliberately
 * absent — openssl_verify() has no PSS padding, and no authenticator requires
 * it when ES256 is offered.
 */
class CoseKey
{
    const ES256 = -7;
    const EDDSA = -8;
    const ES384 = -35;
    const ES512 = -36;
    const RS256 = -257;

    const KTY_OKP = 1;
    const KTY_EC2 = 2;
    const KTY_RSA = 3;

    const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
    const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    const OID_ED25519 = '1.3.101.112';

    private static $CURVES = array(
        1 => array('oid' => '1.2.840.10045.3.1.7', 'size' => 32),  // P-256
        2 => array('oid' => '1.3.132.0.34',        'size' => 48),  // P-384
        3 => array('oid' => '1.3.132.0.35',        'size' => 66),  // P-521
    );

    /**
     * Algorithms advertised in pubKeyCredParams, most preferred first.
     *
     * @return int[]
     */
    public static function supportedAlgorithms()
    {
        $algorithms = array(self::ES256, self::RS256);

        if (function_exists('sodium_crypto_sign_verify_detached')) {
            $algorithms[] = self::EDDSA;
        }

        return $algorithms;
    }

    /**
     * @param  string $cbor  The credentialPublicKey bytes
     * @return array         array('algorithm' => int, 'pem' => string)
     * @throws WebAuthnException
     */
    public static function toPublicKey($cbor)
    {
        $key = CborDecoder::decodeAll($cbor);

        if (! is_array($key) || ! isset($key[1], $key[3])) {
            throw new WebAuthnException('The authenticator sent a malformed public key');
        }

        $kty = $key[1];
        $algorithm = $key[3];

        switch ($kty) {
            case self::KTY_EC2:
                $der = self::ec2ToDer($key, $algorithm);
                break;
            case self::KTY_RSA:
                $der = self::rsaToDer($key);
                break;
            case self::KTY_OKP:
                $der = self::okpToDer($key);
                break;
            default:
                throw new WebAuthnException('Unsupported public key type');
        }

        if (! in_array($algorithm, self::supportedAlgorithms(), true) &&
            ! in_array($algorithm, array(self::ES384, self::ES512), true)) {
            throw new WebAuthnException('Unsupported signature algorithm');
        }

        return array('algorithm' => (int) $algorithm, 'pem' => Der::toPem($der));
    }

    /**
     * Check a signature made by a stored credential.
     *
     * @param  int    $algorithm
     * @param  string $pem
     * @param  string $data
     * @param  string $signature
     * @return bool
     * @throws WebAuthnException
     */
    public static function verify($algorithm, $pem, $data, $signature)
    {
        if ($algorithm === self::EDDSA) {
            return self::verifyEd25519($pem, $data, $signature);
        }

        $digest = self::digestFor($algorithm);
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw new WebAuthnException('The stored public key could not be read');
        }

        return openssl_verify($data, $signature, $key, $digest) === 1;
    }

    private static function digestFor($algorithm)
    {
        switch ($algorithm) {
            case self::ES256:
            case self::RS256:
                return OPENSSL_ALGO_SHA256;
            case self::ES384:
                return OPENSSL_ALGO_SHA384;
            case self::ES512:
                return OPENSSL_ALGO_SHA512;
        }

        throw new WebAuthnException('Unsupported signature algorithm');
    }

    private static function verifyEd25519($pem, $data, $signature)
    {
        if (! function_exists('sodium_crypto_sign_verify_detached')) {
            throw new WebAuthnException('This server has no Ed25519 support');
        }

        // The 32 raw bytes are the tail of the SubjectPublicKeyInfo.
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);

        if ($der === false || strlen($der) < 32) {
            throw new WebAuthnException('The stored public key could not be read');
        }

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $data, substr($der, -32));
    }

    private static function ec2ToDer(array $key, $algorithm)
    {
        if (! isset($key[-1], $key[-2], $key[-3]) || ! isset(self::$CURVES[$key[-1]])) {
            throw new WebAuthnException('The authenticator sent an unusable EC key');
        }

        $curve = self::$CURVES[$key[-1]];
        $x = $key[-2];
        $y = $key[-3];

        if (strlen($x) !== $curve['size'] || strlen($y) !== $curve['size']) {
            throw new WebAuthnException('The authenticator sent an unusable EC key');
        }

        $expected = array(1 => self::ES256, 2 => self::ES384, 3 => self::ES512);

        if ($expected[$key[-1]] !== $algorithm) {
            throw new WebAuthnException('The key curve does not match its algorithm');
        }

        return Der::sequence(
            Der::sequence(Der::oid(self::OID_EC_PUBLIC_KEY).Der::oid($curve['oid'])).
            Der::bitString(chr(0x04).$x.$y)
        );
    }

    private static function rsaToDer(array $key)
    {
        if (! isset($key[-1], $key[-2])) {
            throw new WebAuthnException('The authenticator sent an unusable RSA key');
        }

        return Der::sequence(
            Der::sequence(Der::oid(self::OID_RSA_ENCRYPTION).Der::null()).
            Der::bitString(Der::sequence(Der::unsignedInteger($key[-1]).Der::unsignedInteger($key[-2])))
        );
    }

    private static function okpToDer(array $key)
    {
        // Curve 6 is Ed25519; nothing else is used for WebAuthn.
        if (! isset($key[-1], $key[-2]) || $key[-1] !== 6 || strlen($key[-2]) !== 32) {
            throw new WebAuthnException('The authenticator sent an unusable Ed25519 key');
        }

        return Der::sequence(Der::sequence(Der::oid(self::OID_ED25519)).Der::bitString($key[-2]));
    }
}
