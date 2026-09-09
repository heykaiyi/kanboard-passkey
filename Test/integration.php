<?php

/**
 * The half of the plugin the unit suite cannot reach: the second factor, which
 * only makes sense inside a real Kanboard container with a real database.
 *
 * Run it from a Kanboard installation that has this plugin in place:
 *
 *     php plugins/Passkey/Test/integration.php
 *
 * It creates a throwaway user, enrols a virtual passkey for them, drives the
 * provider the way TwoFactorController does, and removes everything it made.
 * Nothing else in the installation is touched, and no setting is changed.
 */

use Kanboard\Plugin\Passkey\Auth\PasskeyTwoFactorProvider;
use Kanboard\Plugin\Passkey\Model\PasskeySettingsModel;
use Kanboard\Plugin\Passkey\Test\VirtualAuthenticator;
use Kanboard\Plugin\Passkey\WebAuthn\Base64Url;
use Kanboard\Plugin\Passkey\WebAuthn\Server;

$root = dirname(__DIR__, 3);

if (! file_exists($root.'/app/common.php')) {
    fwrite(STDERR, "Run this from inside a Kanboard installation (plugins/Passkey/Test/integration.php).\n");
    exit(2);
}

$_SESSION = array();
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';

require $root.'/app/common.php';
require_once __DIR__.'/VirtualAuthenticator.php';

$passed = 0;
$failed = array();
$userId = null;

function test($name, callable $body)
{
    global $passed, $failed;

    try {
        $body();
        $passed++;
        echo "  ok   $name\n";
    } catch (Throwable $e) {
        $failed[] = $name;
        echo "  FAIL $name\n       ".$e->getMessage()."\n";
    }
}

function assertTrue($value, $message = 'expected true')
{
    if ($value !== true) {
        throw new RuntimeException($message);
    }
}

function assertFalse($value, $message = 'expected false')
{
    if ($value !== false) {
        throw new RuntimeException($message);
    }
}

/**
 * Sign the user in as far as the second factor, the way the middleware leaves
 * them: session open, post-authentication pending.
 */
function halfSignIn($userId)
{
    global $container;

    $user = $container['userModel']->getById($userId);
    $_SESSION = array();
    session_set('user', array(
        'id' => (int) $user['id'],
        'username' => $user['username'],
        'role' => $user['role'],
        'twofactor_activated' => true,
    ));
}

/**
 * The assertion, in the JSON shape the template posts in the `code` field.
 */
function assertionCode(VirtualAuthenticator $authenticator, $origin, $flags = 0x05)
{
    $options = json_decode(session_get(PasskeyTwoFactorProvider::SESSION_OPTIONS), true);

    return json_encode($authenticator->get($options['challenge'], $origin, $flags));
}

try {
    /** @var PasskeySettingsModel $settings */
    $settings = $container['passkeySettingsModel'];
    $credentials = $container['passkeyCredentialModel'];

    // Whatever this installation is configured for, so the test needs no
    // setting changed and leaves none behind.
    $rpId = $settings->getRelyingPartyId();
    $origins = $settings->getAllowedOrigins();
    $origin = $origins[0];

    echo "Relying party: $rpId ($origin)\n\n";

    $username = 'passkey-test-'.bin2hex(random_bytes(4));
    $userId = $container['userModel']->create(array(
        'username' => $username,
        'name' => 'Passkey integration test',
        'password' => bin2hex(random_bytes(16)),
        'role' => 'app-user',
    ));

    if (empty($userId)) {
        throw new RuntimeException('Could not create the test user');
    }

    echo "Test user: $username (#$userId)\n";

    $authenticator = new VirtualAuthenticator($rpId);
    $challenge = Server::createChallenge();
    $stored = $settings->getServer()->verifyCreation(
        $authenticator->create(Base64Url::encode($challenge), $origin),
        $challenge
    );

    if (! $credentials->create($userId, $stored, 'Integration test key')) {
        throw new RuntimeException('Could not store the test credential');
    }

    echo "\nEnrolment\n";

    test('stores the credential and finds it again by id', function () use ($credentials, $stored, $userId) {
        $row = $credentials->getByCredentialId($stored['credential_id']);
        assertTrue($row !== null, 'the credential could not be found');
        assertTrue((int) $row['user_id'] === $userId, 'the credential was filed under the wrong user');
    });

    test('does not find a credential id that was never enrolled', function () use ($credentials) {
        assertTrue($credentials->getByCredentialId(Base64Url::encode(random_bytes(32))) === null);
    });

    test('issues one stable user handle per account', function () use ($settings, $userId) {
        $first = $settings->getUserHandle($userId);
        assertTrue(strlen($first) === 32, 'the handle should be 32 bytes');
        assertTrue($first === $settings->getUserHandle($userId), 'the handle changed between calls');
    });

    echo "\nAllowed origins\n";

    test('reads a bare hostname as the origin it plainly meant', function () {
        $normalize = array('Kanboard\\Plugin\\Passkey\\Model\\PasskeySettingsModel', 'normalizeOrigin');

        // The mistake this exists for: the field above wants a bare host, so
        // people type one here too, and then nothing ever matches.
        assertTrue(call_user_func($normalize, 'kb.example.com') === 'https://kb.example.com');
        assertTrue(call_user_func($normalize, ' kb.example.com/ ') === 'https://kb.example.com');
        assertTrue(call_user_func($normalize, 'kb.example.com:8443') === 'https://kb.example.com:8443');

        // Loopback is the one host where a browser accepts plain HTTP.
        assertTrue(call_user_func($normalize, 'localhost:8000') === 'http://localhost:8000');
        assertTrue(call_user_func($normalize, '127.0.0.1') === 'http://127.0.0.1');

        // Anything already an origin is left exactly as it is.
        assertTrue(call_user_func($normalize, 'https://kb.example.com') === 'https://kb.example.com');
        assertTrue(call_user_func($normalize, 'http://kb.example.com:8080') === 'http://kb.example.com:8080');
        assertTrue(call_user_func($normalize, 'https://kb.example.com/') === 'https://kb.example.com');
        assertTrue(call_user_func($normalize, '') === '');
    });

    test('accepts a ceremony from the origin this installation actually serves', function () use ($settings, $rpId, $origin) {
        // The regression: with a bare hostname configured, this threw.
        $authenticator = new VirtualAuthenticator($rpId);
        $challenge = Server::createChallenge();
        $settings->getServer()->verifyCreation(
            $authenticator->create(Base64Url::encode($challenge), $origin),
            $challenge
        );
    });

    echo "\nSecond factor: passkey\n";

    $settings->setTwoFactorPasskey($userId, true);
    $container['userModel']->update(array('id' => $userId, 'twofactor_activated' => 1, 'twofactor_secret' => ''));

    test('accepts the passkey the user enrolled', function () use ($container, $authenticator, $origin, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();

        assertTrue(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'no challenge was issued');

        $provider->setCode(assertionCode($authenticator, $origin));
        assertTrue($provider->authenticate(), 'a valid assertion was rejected');
    });

    test('narrows the ceremony to that user\'s own passkeys', function () use ($container, $userId, $stored) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();

        $options = json_decode(session_get(PasskeyTwoFactorProvider::SESSION_OPTIONS), true);
        assertTrue(count($options['allowCredentials']) === 1, 'expected exactly one credential to be offered');
        assertTrue($options['allowCredentials'][0]['id'] === $stored['credential_id'], 'a different credential was offered');
    });

    test('rejects a passkey belonging to somebody else', function () use ($container, $rpId, $origin, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();

        $stranger = new VirtualAuthenticator($rpId);
        $options = json_decode(session_get(PasskeyTwoFactorProvider::SESSION_OPTIONS), true);
        $provider->setCode(json_encode($stranger->get($options['challenge'], $origin)));

        assertFalse($provider->authenticate(), 'an unregistered passkey was accepted');
    });

    test('rejects an assertion for a challenge that was never issued', function () use ($container, $authenticator, $origin, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        $provider->setCode(json_encode($authenticator->get(Base64Url::encode(Server::createChallenge()), $origin)));

        assertFalse($provider->authenticate(), 'a stale challenge was accepted');
    });

    test('rejects a code that is not an assertion at all', function () use ($container, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        $provider->setCode('123456');

        assertFalse($provider->authenticate(), 'a numeric code was accepted as an assertion');
    });

    test('clears the challenge after a failure, so the retry gets a new one', function () use ($container, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        $first = session_get(PasskeyTwoFactorProvider::SESSION_CHALLENGE);
        $provider->setCode('123456');
        $provider->authenticate();

        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_CHALLENGE), 'the challenge survived a failure');
        assertFalse(session_exists('twoFactorBeforeCodeCalled'), 'the controller would not issue a new challenge');

        $provider->beforeCode();
        assertTrue($first !== session_get(PasskeyTwoFactorProvider::SESSION_CHALLENGE), 'the same challenge came back');
    });

    test('will not accept the same assertion twice', function () use ($container, $authenticator, $origin, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        $code = assertionCode($authenticator, $origin);
        $provider->setCode($code);
        assertTrue($provider->authenticate(), 'the first attempt should have passed');

        $provider->beforeCode();
        $provider->setCode($code);
        assertFalse($provider->authenticate(), 'a replayed assertion was accepted');
    });

    test('records when the passkey was last used', function () use ($credentials, $stored) {
        $row = $credentials->getByCredentialId($stored['credential_id']);
        assertTrue((int) $row['last_used_at'] > 0, 'last_used_at was never written');
        assertTrue((int) $row['sign_count'] > 0, 'the signature counter was not advanced');
    });

    echo "\nSecond factor: one-time code, on the same provider\n";

    $settings->setTwoFactorPasskey($userId, false);

    test('hands a TOTP user straight through to the built-in provider', function () use ($container, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);

        $secret = $provider->generateSecret();
        assertTrue(is_string($secret) && $secret !== '', 'no TOTP secret was generated');

        $provider->beforeCode();
        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'a passkey challenge was issued to a TOTP user');

        $otp = new Otp\Otp();
        $provider->setSecret($secret);
        $provider->setCode($otp->totp(Base32\Base32::decode($secret)));

        assertTrue($provider->authenticate(), 'a valid one-time code was rejected');

        $provider->setCode('000000');
        assertFalse($provider->authenticate(), 'a wrong one-time code was accepted');
    });

    test('offers a key url a phone can scan', function () use ($container, $userId) {
        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->setSecret($provider->generateSecret());

        assertTrue(strpos($provider->getKeyUrl('test@example.com'), 'otpauth://') === 0, 'the key url is not an otpauth uri');
    });

    test('leaves a pending TOTP enrolment to core, even for a passkey user', function () use ($container, $settings, $userId) {
        $settings->setTwoFactorPasskey($userId, true);
        halfSignIn($userId);

        // What TwoFactorController::show() sets while the user is scanning.
        $provider = new PasskeyTwoFactorProvider($container);
        session_set('twoFactorSecret', $provider->generateSecret());
        $provider->beforeCode();

        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'the passkey path hijacked a TOTP enrolment');
        $settings->setTwoFactorPasskey($userId, false);
    });

    test('ignores a stale ceremony left in the session by an earlier request', function () use ($container, $settings, $userId) {
        halfSignIn($userId);
        $settings->setTwoFactorPasskey($userId, true);
        $container['userModel']->update(array('id' => $userId, 'twofactor_activated' => 1, 'twofactor_secret' => ''));

        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        assertTrue($provider->usesPasskey(), 'the user should be on the passkey path');

        $helper = new Kanboard\Plugin\Passkey\Helper\PasskeyHelper($container);
        assertTrue($helper->getTwoFactorOptions() !== '', 'the prompt should offer a ceremony');

        // The user switches back to a one-time code. TwoFactorController will
        // not call beforeCode() again this session, so the options are still
        // sitting there — the prompt must not use them.
        $settings->setTwoFactorPasskey($userId, false);
        $container['userModel']->update(array('id' => $userId, 'twofactor_secret' => 'ABCDEFGHIJKLMNOP'));

        assertTrue($helper->getTwoFactorOptions() === '', 'a stale passkey prompt was rendered to a one-time-code user');

        $container['userModel']->update(array('id' => $userId, 'twofactor_secret' => ''));
    });

    test('drops a pending ceremony when somebody signs in', function () use ($container, $settings, $userId) {
        halfSignIn($userId);
        $settings->setTwoFactorPasskey($userId, true);

        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();
        session_set('twoFactorBeforeCodeCalled', true);
        assertTrue(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'no ceremony to drop');

        // A session outlives a login, so the next user must not inherit it.
        $plugin = new Kanboard\Plugin\Passkey\Plugin($container);
        $plugin->onLoginSuccess(new Kanboard\Event\AuthSuccessEvent('Database'));

        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'the challenge outlived the login');
        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_CHALLENGE), 'the challenge outlived the login');
        assertFalse(session_exists('twoFactorBeforeCodeCalled'), 'the next user would not get a fresh ceremony');

        $settings->setTwoFactorPasskey($userId, false);
    });

    test('falls back to a code when the user has a passkey flag but no passkey', function () use ($container, $credentials, $settings, $userId, $stored) {
        $row = $credentials->getByCredentialId($stored['credential_id']);
        $settings->setTwoFactorPasskey($userId, true);
        $credentials->remove($row['id'], $userId);

        halfSignIn($userId);
        $provider = new PasskeyTwoFactorProvider($container);
        $provider->beforeCode();

        assertFalse(session_exists(PasskeyTwoFactorProvider::SESSION_OPTIONS), 'a ceremony was issued with no passkey to answer it');
    });
} catch (Throwable $e) {
    echo "\nAborted: ".$e->getMessage()."\n";
    $failed[] = 'bootstrap';
}

// -- clean up ----------------------------------------------------------------

if (! empty($userId)) {
    $container['db']->table('passkey_credentials')->eq('user_id', $userId)->remove();
    $container['userModel']->remove($userId);
    echo "\nRemoved the test user.\n";
}

echo "\n";

if (empty($failed)) {
    echo "$passed passed\n";
    exit(0);
}

echo count($failed).' failed, '.$passed." passed\n";
exit(1);
