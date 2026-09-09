<?php

/**
 * The WebAuthn suite. No PHPUnit, no composer: `php Test/run.php` from the
 * plugin directory is the whole thing.
 *
 * Every ceremony below is run against a real authenticator built out of
 * OpenSSL and libsodium, so the signatures, the DER and the CBOR are the ones
 * a browser would send rather than fixtures that agree with the parser by
 * construction.
 */

require_once __DIR__.'/bootstrap.php';

use Kanboard\Plugin\Passkey\Test\VirtualAuthenticator;
use Kanboard\Plugin\Passkey\WebAuthn\AuthenticatorData;
use Kanboard\Plugin\Passkey\WebAuthn\Base64Url;
use Kanboard\Plugin\Passkey\WebAuthn\CborDecoder;
use Kanboard\Plugin\Passkey\WebAuthn\CoseKey;
use Kanboard\Plugin\Passkey\WebAuthn\Der;
use Kanboard\Plugin\Passkey\WebAuthn\Server;
use Kanboard\Plugin\Passkey\WebAuthn\WebAuthnException;

const RP_ID = 'kanboard.example.com';
const ORIGIN = 'https://kanboard.example.com';

$passed = 0;
$failed = array();

function test($name, callable $body)
{
    global $passed, $failed;

    try {
        $body();
        $passed++;
        echo "  ok   $name\n";
    } catch (Throwable $e) {
        $failed[] = $name.': '.$e->getMessage();
        echo "  FAIL $name\n       ".$e->getMessage()."\n";
    }
}

function group($name)
{
    echo "\n$name\n";
}

function assertTrue($value, $message = 'expected true')
{
    if ($value !== true) {
        throw new RuntimeException($message);
    }
}

function assertSame($expected, $actual, $message = '')
{
    if ($expected !== $actual) {
        throw new RuntimeException(($message !== '' ? $message.': ' : '')
            .'expected '.var_export($expected, true).', got '.var_export($actual, true));
    }
}

/**
 * Run something that must be rejected, and check it is rejected for the stated
 * reason rather than by accident.
 */
function assertRejected(callable $body, $expectedFragment)
{
    try {
        $body();
    } catch (WebAuthnException $e) {
        if (stripos($e->getMessage(), $expectedFragment) === false) {
            throw new RuntimeException('rejected, but for the wrong reason: '.$e->getMessage());
        }

        return;
    }

    throw new RuntimeException('was accepted, but should have been rejected ('.$expectedFragment.')');
}

function server($requireUserVerification = true, array $origins = array(ORIGIN))
{
    return new Server(RP_ID, 'Kanboard', $origins, $requireUserVerification);
}

/**
 * A registered credential, in the shape the database row holds.
 */
function enrol(VirtualAuthenticator $authenticator, $server = null)
{
    $server = $server ?: server();
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);

    return $server->verifyCreation($credential, $challenge);
}

// -- base64url ---------------------------------------------------------------

group('Base64Url');

test('round-trips arbitrary bytes', function () {
    assertSame('', Base64Url::encode(''));

    for ($length = 1; $length < 40; $length++) {
        $bytes = random_bytes($length);
        assertSame($bytes, Base64Url::decode(Base64Url::encode($bytes)), "length $length");
    }
});

test('never emits padding, but accepts it', function () {
    $encoded = Base64Url::encode('kanboard');
    assertSame(false, strpos($encoded, '='), 'encode() padded its output');

    $padded = $encoded.str_repeat('=', (4 - strlen($encoded) % 4) % 4);
    assertSame('kanboard', Base64Url::decode($padded), 'padded input was refused');
});

test('uses the url alphabet', function () {
    // 0xff 0xfe 0xfd is "//79" in standard base64.
    assertSame('__79', Base64Url::encode("\xff\xfe\xfd"));
});

test('returns an empty string for input that is not base64url', function () {
    foreach (array('', 'a b', 'abc/def', 'abc+def', "abc\ndef", 'ábc') as $input) {
        assertSame('', Base64Url::decode($input), 'accepted '.var_export($input, true));
    }
});

test('returns an empty string for a non-string', function () {
    assertSame('', Base64Url::decode(null));
    assertSame('', Base64Url::decode(array()));
});

// -- CBOR --------------------------------------------------------------------

group('CborDecoder');

test('decodes the major types an authenticator emits', function () {
    assertSame(0, CborDecoder::decodeAll("\x00"));
    assertSame(23, CborDecoder::decodeAll("\x17"));
    assertSame(255, CborDecoder::decodeAll("\x18\xff"));
    assertSame(65535, CborDecoder::decodeAll("\x19\xff\xff"));
    assertSame(-1, CborDecoder::decodeAll("\x20"));
    assertSame(-257, CborDecoder::decodeAll("\x39\x01\x00"));
    assertSame('ab', CborDecoder::decodeAll("\x42ab"));
    assertSame('fmt', CborDecoder::decodeAll("\x63fmt"));
    assertSame(array(1, 2), CborDecoder::decodeAll("\x82\x01\x02"));
    assertSame(array('a' => 1), CborDecoder::decodeAll("\xa1\x61a\x01"));
});

test('decodes true, false and null', function () {
    assertSame(false, CborDecoder::decodeAll("\xf4"));
    assertSame(true, CborDecoder::decodeAll("\xf5"));
    assertSame(null, CborDecoder::decodeAll("\xf6"));
});

test('reports where an item ended, so the COSE key can be sliced out', function () {
    $offset = 0;
    CborDecoder::decode("\xa1\x61a\x01trailing", $offset);
    assertSame(4, $offset);
});

test('rejects trailing bytes when the whole string should be one item', function () {
    assertRejected(function () {
        CborDecoder::decodeAll("\x01\x01");
    }, 'trailing');
});

test('rejects a truncated item', function () {
    assertRejected(function () {
        CborDecoder::decodeAll("\x19\xff");
    }, '');
});

test('rejects the indefinite lengths CTAP2 forbids', function () {
    assertRejected(function () {
        CborDecoder::decodeAll("\x5f\x41a\xff");
    }, '');
});

test('rejects a message nested past the depth guard', function () {
    assertRejected(function () {
        CborDecoder::decodeAll(str_repeat("\x81", 40)."\x01");
    }, 'deep');
});

test('rejects a length that overruns the buffer instead of allocating it', function () {
    // Claims a 4GB byte string in 5 bytes.
    assertRejected(function () {
        CborDecoder::decodeAll("\x5a\xff\xff\xff\xff");
    }, '');
});

// -- DER ---------------------------------------------------------------------

group('Der');

test('encodes the OIDs the key types need', function () {
    assertSame('06072a8648ce3d0201', bin2hex(Der::oid('1.2.840.10045.2.1')));
    assertSame('06092a864886f70d010101', bin2hex(Der::oid('1.2.840.113549.1.1.1')));
    assertSame('06032b6570', bin2hex(Der::oid('1.3.101.112')));
});

test('pads an integer whose high bit is set', function () {
    assertSame('020200ff', bin2hex(Der::unsignedInteger("\xff")));
    assertSame('02017f', bin2hex(Der::unsignedInteger("\x7f")));
});

test('strips leading zeros, but keeps the number', function () {
    assertSame('020101', bin2hex(Der::unsignedInteger("\x00\x00\x01")));
    assertSame('020100', bin2hex(Der::unsignedInteger("\x00\x00")));
});

test('switches to long-form lengths past 127 bytes', function () {
    // 0x30 SEQUENCE, 0x81 "one length byte follows", 0x80 = 128.
    assertSame('308180', bin2hex(substr(Der::sequence(str_repeat("\0", 128)), 0, 3)));
    assertSame('3003', bin2hex(substr(Der::sequence(str_repeat("\0", 3)), 0, 2)));
});

// -- COSE keys ---------------------------------------------------------------

group('CoseKey');

foreach (array('ES256' => -7, 'ES384' => -35, 'RS256' => -257) as $name => $algorithm) {
    test("builds the same PEM OpenSSL does for $name", function () use ($algorithm) {
        $authenticator = new VirtualAuthenticator(RP_ID, $algorithm);
        $stored = enrol($authenticator);

        assertSame($algorithm, $stored['algorithm']);
        assertSame($authenticator->getReferencePem(), trim($stored['public_key']), 'the DER is not what OpenSSL emits');
    });
}

test('builds a usable Ed25519 key', function () {
    if (! function_exists('sodium_crypto_sign_verify_detached')) {
        return;
    }

    $authenticator = new VirtualAuthenticator(RP_ID, -8);
    $stored = enrol($authenticator);
    assertSame(-8, $stored['algorithm']);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
    server()->verifyRequest($assertion, $challenge, $stored);
});

test('offers Ed25519 only when libsodium is there to verify it', function () {
    $algorithms = CoseKey::supportedAlgorithms();
    assertTrue(in_array(-7, $algorithms, true), 'ES256 is not offered');
    assertTrue(in_array(-257, $algorithms, true), 'RS256 is not offered');
    assertSame(function_exists('sodium_crypto_sign_verify_detached'), in_array(-8, $algorithms, true));
});

test('rejects a key whose curve does not match its algorithm', function () {
    // A P-256 point claiming to be ES384.
    $key = VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::int(1), VirtualAuthenticator::int(2)),
        array(VirtualAuthenticator::int(3), VirtualAuthenticator::int(-35)),
        array(VirtualAuthenticator::int(-1), VirtualAuthenticator::int(1)),
        array(VirtualAuthenticator::int(-2), VirtualAuthenticator::bytes(random_bytes(32))),
        array(VirtualAuthenticator::int(-3), VirtualAuthenticator::bytes(random_bytes(32))),
    ));

    assertRejected(function () use ($key) {
        CoseKey::toPublicKey($key);
    }, 'curve');
});

test('rejects a coordinate of the wrong length', function () {
    $key = VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::int(1), VirtualAuthenticator::int(2)),
        array(VirtualAuthenticator::int(3), VirtualAuthenticator::int(-7)),
        array(VirtualAuthenticator::int(-1), VirtualAuthenticator::int(1)),
        array(VirtualAuthenticator::int(-2), VirtualAuthenticator::bytes(random_bytes(31))),
        array(VirtualAuthenticator::int(-3), VirtualAuthenticator::bytes(random_bytes(32))),
    ));

    assertRejected(function () use ($key) {
        CoseKey::toPublicKey($key);
    }, 'unusable');
});

test('rejects an unknown key type', function () {
    $key = VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::int(1), VirtualAuthenticator::int(9)),
        array(VirtualAuthenticator::int(3), VirtualAuthenticator::int(-7)),
    ));

    assertRejected(function () use ($key) {
        CoseKey::toPublicKey($key);
    }, 'Unsupported public key type');
});

test('rejects PS256, which openssl_verify() cannot check', function () {
    $key = VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::int(1), VirtualAuthenticator::int(3)),
        array(VirtualAuthenticator::int(3), VirtualAuthenticator::int(-37)),
        array(VirtualAuthenticator::int(-1), VirtualAuthenticator::bytes(random_bytes(256))),
        array(VirtualAuthenticator::int(-2), VirtualAuthenticator::bytes("\x01\x00\x01")),
    ));

    assertRejected(function () use ($key) {
        CoseKey::toPublicKey($key);
    }, 'Unsupported signature algorithm');
});

// -- authenticator data ------------------------------------------------------

group('AuthenticatorData');

test('reads the flags a ceremony turns on', function () {
    // UP | UV | BE | BS, and no attested credential data.
    $data = hash('sha256', RP_ID, true).chr(0x1d).pack('N', 7);
    $parsed = AuthenticatorData::parse($data);

    assertTrue($parsed->has(AuthenticatorData::FLAG_USER_PRESENT));
    assertTrue($parsed->has(AuthenticatorData::FLAG_USER_VERIFIED));
    assertTrue($parsed->has(AuthenticatorData::FLAG_BACKUP_ELIGIBLE));
    assertTrue($parsed->has(AuthenticatorData::FLAG_BACKED_UP));
    assertSame(false, $parsed->has(AuthenticatorData::FLAG_ATTESTED_DATA));
    assertSame(7, $parsed->signCount);
});

test('rejects data too short to hold a header', function () {
    assertRejected(function () {
        AuthenticatorData::parse(str_repeat("\0", 36));
    }, 'truncated');
});

test('rejects a credential id longer than the data that follows', function () {
    $data = hash('sha256', RP_ID, true).chr(0x45).pack('N', 0).str_repeat("\0", 16).pack('n', 400);

    assertRejected(function () use ($data) {
        AuthenticatorData::parse($data);
    }, 'unusable credential id');
});

test('does not swallow extension output into the public key', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN, 0x45 | 0x80);

    // Re-open the attestation object and append an extension map to authData,
    // the way an authenticator that was asked for credProps would.
    $attestation = CborDecoder::decodeAll(Base64Url::decode($credential['response']['attestationObject']));
    $extensions = VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::text('credProtect'), VirtualAuthenticator::int(2)),
    ));

    $withExtensions = AuthenticatorData::parse($attestation['authData'].$extensions);
    $without = AuthenticatorData::parse($attestation['authData']);

    assertSame($without->credentialPublicKey, $withExtensions->credentialPublicKey, 'the extension bytes leaked into the key');
    assertSame($authenticator->credentialId, $withExtensions->credentialId);
});

// -- registration ------------------------------------------------------------

group('Registration ceremony');

test('accepts a well-formed registration and returns what to store', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    assertSame(Base64Url::encode($authenticator->credentialId), $stored['credential_id']);
    assertSame(0, $stored['sign_count']);
    assertSame(32, strlen($stored['aaguid']), 'the aaguid should be 16 bytes as hex');
    assertSame('internal', $stored['transports']);
    assertTrue(is_int($stored['is_backup_eligible']));
});

test('records that a synced passkey is backup eligible', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN, 0x45 | AuthenticatorData::FLAG_BACKUP_ELIGIBLE);
    $stored = server()->verifyCreation($credential, $challenge);

    assertSame(1, $stored['is_backup_eligible']);
});

test('rejects a challenge that is not the one this session issued', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $credential = $authenticator->create(Base64Url::encode(Server::createChallenge()), ORIGIN);

    assertRejected(function () use ($credential) {
        server()->verifyCreation($credential, Server::createChallenge());
    }, 'challenge');
});

test('rejects an origin that is not on the list', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), 'https://phishing.example');

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'origin');
});

test('rejects a ceremony run inside someone else\'s frame', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);

    $clientData = json_decode(Base64Url::decode($credential['response']['clientDataJSON']), true);
    $clientData['crossOrigin'] = true;
    $credential['response']['clientDataJSON'] = Base64Url::encode(json_encode($clientData));

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'frame');
});

test('rejects an assertion replayed into the registration endpoint', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);

    assertRejected(function () use ($assertion, $challenge) {
        server()->verifyCreation($assertion, $challenge);
    }, 'incomplete');
});

test('rejects a passkey bound to a different site', function () {
    $authenticator = new VirtualAuthenticator('evil.example');
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'different site');
});

test('rejects a registration with no user interaction', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN, 0x40);

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'no user interaction');
});

test('rejects an unverified user when verification is required', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN, 0x41);

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'PIN, fingerprint or face');
});

test('accepts an unverified user when verification is only preferred', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN, 0x41);
    $stored = server(false)->verifyCreation($credential, $challenge);

    assertSame(Base64Url::encode($authenticator->credentialId), $stored['credential_id']);
});

test('rejects a registration with no attested credential', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);

    // Drop the attested data flag, keeping the bytes.
    $attestation = CborDecoder::decodeAll(Base64Url::decode($credential['response']['attestationObject']));
    $authData = $attestation['authData'];
    $authData[32] = chr(0x05);

    $credential['response']['attestationObject'] = Base64Url::encode(VirtualAuthenticator::map(array(
        array(VirtualAuthenticator::text('fmt'), VirtualAuthenticator::text('none')),
        array(VirtualAuthenticator::text('attStmt'), VirtualAuthenticator::map(array())),
        array(VirtualAuthenticator::text('authData'), VirtualAuthenticator::bytes($authData)),
    )));

    assertRejected(function () use ($credential, $challenge) {
        server()->verifyCreation($credential, $challenge);
    }, 'did not return a credential');
});

test('rejects an attestation object that is not a map', function () {
    $credential = array('response' => array(
        'clientDataJSON' => Base64Url::encode('{}'),
        'attestationObject' => Base64Url::encode("\x01"),
    ));

    assertRejected(function () use ($credential) {
        server()->verifyCreation($credential, Server::createChallenge());
    }, '');
});

test('keeps only transport values that look like transports', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);
    $credential['response']['transports'] = array('usb', 'INTERNAL', '<script>', 'hybrid', str_repeat('a', 20), 'nfc');
    $stored = server()->verifyCreation($credential, $challenge);

    assertSame('usb,hybrid,nfc', $stored['transports']);
});

// -- assertion ---------------------------------------------------------------

group('Assertion ceremony');

test('accepts a well-formed assertion and moves the counter forward', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
    $signCount = server()->verifyRequest($assertion, $challenge, $stored);

    assertSame(1, $signCount);
});

foreach (array('ES256' => -7, 'ES384' => -35, 'RS256' => -257) as $name => $algorithm) {
    test("verifies a real $name signature", function () use ($algorithm) {
        $authenticator = new VirtualAuthenticator(RP_ID, $algorithm);
        $stored = enrol($authenticator);

        $challenge = Server::createChallenge();
        $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
        server()->verifyRequest($assertion, $challenge, $stored);
    });
}

test('rejects a signature made over a different challenge', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);
    $assertion = $authenticator->get(Base64Url::encode(Server::createChallenge()), ORIGIN);

    assertRejected(function () use ($assertion, $stored) {
        server()->verifyRequest($assertion, Server::createChallenge(), $stored);
    }, 'challenge');
});

test('rejects a signature from a different passkey', function () {
    $mine = new VirtualAuthenticator(RP_ID);
    $stored = enrol($mine);

    $theirs = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $assertion = $theirs->get(Base64Url::encode($challenge), ORIGIN);

    assertRejected(function () use ($assertion, $challenge, $stored) {
        server()->verifyRequest($assertion, $challenge, $stored);
    }, 'not valid');
});

test('rejects a tampered signature', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
    $signature = Base64Url::decode($assertion['response']['signature']);
    $signature[10] = chr(ord($signature[10]) ^ 0xff);
    $assertion['response']['signature'] = Base64Url::encode($signature);

    assertRejected(function () use ($assertion, $challenge, $stored) {
        server()->verifyRequest($assertion, $challenge, $stored);
    }, 'not valid');
});

test('rejects authenticator data edited after signing', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
    $authData = Base64Url::decode($assertion['response']['authenticatorData']);
    $authData[32] = chr(0x05 | 0x08);
    $assertion['response']['authenticatorData'] = Base64Url::encode($authData);

    assertRejected(function () use ($assertion, $challenge, $stored) {
        server()->verifyRequest($assertion, $challenge, $stored);
    }, 'not valid');
});

test('rejects a replayed assertion on its signature counter', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
    $stored['sign_count'] = server()->verifyRequest($assertion, $challenge, $stored);

    // The same signed bytes, sent a second time.
    assertRejected(function () use ($assertion, $challenge, $stored) {
        server()->verifyRequest($assertion, $challenge, $stored);
    }, 'cloned');
});

test('lets a synced passkey keep its counter at zero', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    for ($i = 0; $i < 3; $i++) {
        $authenticator->signCount = -1; // so get() increments back to zero
        $challenge = Server::createChallenge();
        $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN);
        assertSame(0, server()->verifyRequest($assertion, $challenge, $stored));
    }
});

test('rejects an unverified assertion when verification is required', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN, 0x01);

    assertRejected(function () use ($assertion, $challenge, $stored) {
        server()->verifyRequest($assertion, $challenge, $stored);
    }, 'PIN, fingerprint or face');
});

test('accepts an unverified assertion when verification is only preferred', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator, server(false));

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), ORIGIN, 0x01);
    server(false)->verifyRequest($assertion, $challenge, $stored);
});

test('rejects a registration replayed into the assertion endpoint', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $stored = enrol($authenticator);

    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), ORIGIN);

    assertRejected(function () use ($credential, $challenge, $stored) {
        server()->verifyRequest($credential, $challenge, $stored);
    }, 'incomplete');
});

test('rejects an empty response object', function () {
    assertRejected(function () {
        server()->verifyRequest(array(), Server::createChallenge(), array('public_key' => '', 'algorithm' => -7, 'sign_count' => 0));
    }, 'incomplete');
});

test('accepts an origin listed alongside others, and only that one', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $origins = array('https://kanboard.internal', ORIGIN);
    $stored = enrol($authenticator, server(true, $origins));

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), 'https://kanboard.internal');
    server(true, $origins)->verifyRequest($assertion, $challenge, $stored);

    $challenge = Server::createChallenge();
    $assertion = $authenticator->get(Base64Url::encode($challenge), 'https://kanboard.other');

    assertRejected(function () use ($assertion, $challenge, $stored, $origins) {
        server(true, $origins)->verifyRequest($assertion, $challenge, $stored);
    }, 'origin');
});

test('names the offending origin, so the log says what to fix', function () {
    $authenticator = new VirtualAuthenticator(RP_ID);
    $challenge = Server::createChallenge();
    $credential = $authenticator->create(Base64Url::encode($challenge), 'https://phishing.example');

    try {
        server()->verifyCreation($credential, $challenge);
    } catch (WebAuthnException $e) {
        assertTrue(strpos($e->getMessage(), 'https://phishing.example') !== false, 'the rejected origin is not in the message');
        assertTrue(strpos($e->getMessage(), ORIGIN) !== false, 'the allowed origins are not in the message');
        return;
    }

    throw new RuntimeException('the wrong origin was accepted');
});

// -- ceremony options --------------------------------------------------------

group('Ceremony options');

test('asks for a discoverable credential, so sign-in needs no username', function () {
    $options = server()->getCreationOptions(Server::createChallenge(), array(
        'handle' => random_bytes(32),
        'name' => 'admin',
        'displayName' => 'Administrator',
    ));

    assertSame('required', $options['authenticatorSelection']['residentKey']);
    assertSame(true, $options['authenticatorSelection']['requireResidentKey']);
    assertSame('required', $options['authenticatorSelection']['userVerification']);
    assertSame('none', $options['attestation']);
    assertSame(RP_ID, $options['rp']['id']);
});

test('advertises every algorithm it can actually verify', function () {
    $options = server()->getCreationOptions(Server::createChallenge(), array(
        'handle' => random_bytes(32), 'name' => 'a', 'displayName' => 'a',
    ));

    $advertised = array_column($options['pubKeyCredParams'], 'alg');
    assertSame(CoseKey::supportedAlgorithms(), $advertised);
});

test('sends the challenge and the user handle as base64url', function () {
    $challenge = Server::createChallenge();
    $handle = random_bytes(32);
    $options = server()->getCreationOptions($challenge, array(
        'handle' => $handle, 'name' => 'a', 'displayName' => 'a',
    ));

    assertSame($challenge, Base64Url::decode($options['challenge']));
    assertSame($handle, Base64Url::decode($options['user']['id']));
});

test('leaves allowCredentials empty for a usernameless sign-in', function () {
    $options = server()->getRequestOptions(Server::createChallenge());

    assertSame(array(), $options['allowCredentials']);
    assertSame(RP_ID, $options['rpId']);
});

test('narrows to one credential when the user is already half-signed-in', function () {
    $options = server()->getRequestOptions(Server::createChallenge(), array('abc', 'def'));

    assertSame(2, count($options['allowCredentials']));
    assertSame('abc', $options['allowCredentials'][0]['id']);
    assertSame('public-key', $options['allowCredentials'][0]['type']);
});

test('drops userVerification to preferred when the setting says so', function () {
    assertSame('preferred', server(false)->getRequestOptions(Server::createChallenge())['userVerification']);
    assertSame('required', server()->getRequestOptions(Server::createChallenge())['userVerification']);
});

test('issues a 32 byte challenge every time', function () {
    $first = Server::createChallenge();
    $second = Server::createChallenge();

    assertSame(32, strlen($first));
    assertSame(false, $first === $second, 'two challenges came out the same');
});

// -- result ------------------------------------------------------------------

echo "\n";

if (empty($failed)) {
    echo "$passed passed\n";
    exit(0);
}

echo count($failed).' failed, '.$passed." passed\n";
exit(1);
