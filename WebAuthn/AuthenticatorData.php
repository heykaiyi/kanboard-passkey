<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * The authenticator data structure both ceremonies return.
 *
 * Layout: 32 bytes of SHA-256(rpId), one flags byte, a four byte signature
 * counter, then — only during registration — the attested credential data,
 * and optionally the extension output.
 */
class AuthenticatorData
{
    const FLAG_USER_PRESENT = 0x01;
    const FLAG_USER_VERIFIED = 0x04;
    const FLAG_BACKUP_ELIGIBLE = 0x08;
    const FLAG_BACKED_UP = 0x10;
    const FLAG_ATTESTED_DATA = 0x40;
    const FLAG_EXTENSION_DATA = 0x80;

    public $raw;
    public $rpIdHash;
    public $flags;
    public $signCount;
    public $aaguid = '';
    public $credentialId = '';
    public $credentialPublicKey = '';

    /**
     * @param  string $data
     * @return AuthenticatorData
     * @throws WebAuthnException
     */
    public static function parse($data)
    {
        if (strlen($data) < 37) {
            throw new WebAuthnException('The authenticator sent truncated data');
        }

        $authenticatorData = new self();
        $authenticatorData->raw = $data;
        $authenticatorData->rpIdHash = substr($data, 0, 32);
        $authenticatorData->flags = ord($data[32]);
        $counter = unpack('N', substr($data, 33, 4));
        $authenticatorData->signCount = $counter[1];

        if ($authenticatorData->has(self::FLAG_ATTESTED_DATA)) {
            $authenticatorData->parseAttestedCredentialData($data);
        }

        return $authenticatorData;
    }

    /**
     * @param  int $flag
     * @return bool
     */
    public function has($flag)
    {
        return ($this->flags & $flag) === $flag;
    }

    private function parseAttestedCredentialData($data)
    {
        if (strlen($data) < 55) {
            throw new WebAuthnException('The authenticator sent truncated credential data');
        }

        $this->aaguid = substr($data, 37, 16);
        $length = unpack('n', substr($data, 53, 2))[1];

        // The spec caps credential ids at 1023 bytes.
        if ($length > 1023 || strlen($data) < 55 + $length) {
            throw new WebAuthnException('The authenticator sent an unusable credential id');
        }

        $this->credentialId = substr($data, 55, $length);

        // The COSE key has no length prefix: decode it to find where it ends,
        // so the extension output that may follow is not swallowed into it.
        $offset = 55 + $length;
        $start = $offset;
        CborDecoder::decode($data, $offset);
        $this->credentialPublicKey = substr($data, $start, $offset - $start);
    }
}
