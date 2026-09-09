<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * The subset of CBOR (RFC 8949) that authenticators actually emit.
 *
 * Two things WebAuthn needs that a "decode this string" helper cannot give:
 * the COSE public key sits at the tail of the authenticator data with no
 * length prefix, so the caller has to learn where it ended; and the CTAP2
 * canonical form is definite-length only, so indefinite-length items are a
 * sign of a malformed message rather than something to accommodate.
 */
class CborDecoder
{
    /**
     * Decode one item and report how many bytes it used.
     *
     * @param  string  $data
     * @param  int     $offset  Advanced past the decoded item
     * @return mixed
     * @throws WebAuthnException
     */
    public static function decode($data, &$offset = 0)
    {
        $value = self::decodeItem($data, $offset, 0);

        return $value;
    }

    /**
     * Decode an item that is expected to be the whole string.
     *
     * @param  string $data
     * @return mixed
     * @throws WebAuthnException
     */
    public static function decodeAll($data)
    {
        $offset = 0;
        $value = self::decodeItem($data, $offset, 0);

        if ($offset !== strlen($data)) {
            throw new WebAuthnException('Trailing bytes after the CBOR value');
        }

        return $value;
    }

    /**
     * @param  string $data
     * @param  int    $offset
     * @param  int    $depth   Guards against a hand-crafted deeply nested message
     * @return mixed
     * @throws WebAuthnException
     */
    private static function decodeItem($data, &$offset, $depth)
    {
        if ($depth > 16) {
            throw new WebAuthnException('CBOR value is nested too deeply');
        }

        $first = self::byte($data, $offset);
        $major = $first >> 5;
        $info = $first & 0x1f;

        if ($info === 31) {
            throw new WebAuthnException('Indefinite-length CBOR is not accepted');
        }

        $value = self::argument($data, $offset, $info);

        switch ($major) {
            case 0: // unsigned integer
                return $value;
            case 1: // negative integer: -1 - n
                return -1 - $value;
            case 2: // byte string
            case 3: // text string
                return self::bytes($data, $offset, $value);
            case 4: // array
                $items = array();
                for ($i = 0; $i < $value; $i++) {
                    $items[] = self::decodeItem($data, $offset, $depth + 1);
                }
                return $items;
            case 5: // map
                $map = array();
                for ($i = 0; $i < $value; $i++) {
                    $key = self::decodeItem($data, $offset, $depth + 1);

                    if (! is_int($key) && ! is_string($key)) {
                        throw new WebAuthnException('Unsupported CBOR map key');
                    }

                    $map[$key] = self::decodeItem($data, $offset, $depth + 1);
                }
                return $map;
            case 6: // tag: the tag itself carries no meaning here, decode what it wraps
                return self::decodeItem($data, $offset, $depth + 1);
            case 7:
                return self::simpleValue($info, $value);
        }

        throw new WebAuthnException('Unsupported CBOR major type');
    }

    /**
     * Read the argument that follows the initial byte.
     */
    private static function argument($data, &$offset, $info)
    {
        if ($info < 24) {
            return $info;
        }

        switch ($info) {
            case 24:
                return self::byte($data, $offset);
            case 25:
                return self::unpackInt($data, $offset, 2, 'n');
            case 26:
                return self::unpackInt($data, $offset, 4, 'N');
            case 27:
                $high = self::unpackInt($data, $offset, 4, 'N');
                $low = self::unpackInt($data, $offset, 4, 'N');

                // PHP integers are signed; anything past 2^63 cannot be represented.
                if ($high > 0x7fffffff) {
                    throw new WebAuthnException('CBOR integer is out of range');
                }

                return ($high << 32) | $low;
        }

        throw new WebAuthnException('Reserved CBOR additional information');
    }

    private static function simpleValue($info, $value)
    {
        switch ($info) {
            case 20:
                return false;
            case 21:
                return true;
            case 22:
                return null;
            case 25:
            case 26:
            case 27:
                // Floats have no place in an attestation object or a COSE key.
                throw new WebAuthnException('Unexpected CBOR float');
        }

        return $value;
    }

    private static function byte($data, &$offset)
    {
        if ($offset >= strlen($data)) {
            throw new WebAuthnException('Truncated CBOR value');
        }

        return ord($data[$offset++]);
    }

    private static function bytes($data, &$offset, $length)
    {
        if ($length < 0 || $offset + $length > strlen($data)) {
            throw new WebAuthnException('Truncated CBOR string');
        }

        $value = substr($data, $offset, $length);
        $offset += $length;

        return $value;
    }

    private static function unpackInt($data, &$offset, $length, $format)
    {
        $raw = self::bytes($data, $offset, $length);
        $unpacked = unpack($format, $raw);

        return $unpacked[1];
    }
}
