<?php

/**
 * The WebAuthn layer has no Kanboard dependency, so its tests do not need the
 * container, a database or a request. Loading the six files by hand keeps the
 * suite runnable from the plugin directory alone.
 */
foreach (array('WebAuthnException', 'Base64Url', 'CborDecoder', 'Der', 'CoseKey', 'AuthenticatorData', 'Server') as $class) {
    require_once __DIR__.'/../WebAuthn/'.$class.'.php';
}

require_once __DIR__.'/VirtualAuthenticator.php';
