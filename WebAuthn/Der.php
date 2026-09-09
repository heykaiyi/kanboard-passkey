<?php

namespace Kanboard\Plugin\Passkey\WebAuthn;

/**
 * Just enough DER to wrap a COSE key into a SubjectPublicKeyInfo.
 *
 * OpenSSL will not take the raw coordinates an authenticator sends, and PHP
 * has no builder for this, so the four shapes needed here are assembled by
 * hand.
 */
class Der
{
    public static function sequence($contents)
    {
        return self::tag(0x30, $contents);
    }

    public static function bitString($contents)
    {
        // The leading zero is the count of unused bits in the final byte.
        return self::tag(0x03, chr(0).$contents);
    }

    public static function null()
    {
        return chr(0x05).chr(0x00);
    }

    /**
     * An unsigned big-endian number as a DER INTEGER.
     */
    public static function unsignedInteger($bytes)
    {
        $bytes = ltrim($bytes, chr(0));

        if ($bytes === '') {
            $bytes = chr(0);
        } elseif (ord($bytes[0]) > 0x7f) {
            // DER integers are signed, so a high bit needs a zero in front.
            $bytes = chr(0).$bytes;
        }

        return self::tag(0x02, $bytes);
    }

    /**
     * @param  string $dotted  e.g. "1.2.840.10045.2.1"
     * @return string
     */
    public static function oid($dotted)
    {
        $parts = array_map('intval', explode('.', $dotted));
        $encoded = chr($parts[0] * 40 + $parts[1]);

        foreach (array_slice($parts, 2) as $part) {
            $encoded .= self::base128($part);
        }

        return self::tag(0x06, $encoded);
    }

    private static function base128($value)
    {
        $bytes = chr($value & 0x7f);
        $value >>= 7;

        while ($value > 0) {
            $bytes = chr(0x80 | ($value & 0x7f)).$bytes;
            $value >>= 7;
        }

        return $bytes;
    }

    private static function tag($tag, $contents)
    {
        return chr($tag).self::length(strlen($contents)).$contents;
    }

    private static function length($length)
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xff).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }

    /**
     * Wrap DER in the PEM armour openssl_verify() expects.
     */
    public static function toPem($der)
    {
        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
    }
}
