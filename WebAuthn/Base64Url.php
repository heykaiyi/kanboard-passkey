<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * base64url, the encoding every WebAuthn field travels in.
 *
 * The browser sends unpadded base64url and refuses padded input in
 * `PublicKeyCredential.parseCreationOptionsFromJSON()`, so encode() never pads
 * and decode() tolerates both.
 */
class Base64Url
{
    public static function encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param  string $data
     * @return string  Raw bytes, or an empty string when the input is not valid base64url
     */
    public static function decode($data)
    {
        if (! is_string($data) || $data === '' || preg_match('/^[A-Za-z0-9_\-=]+$/', $data) !== 1) {
            return '';
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }
}
