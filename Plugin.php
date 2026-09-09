<?php

namespace Kanboard\Plugin\Passkey;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Core\Security\Role;
use Kanboard\Core\Translator;
use Kanboard\Event\AuthSuccessEvent;
use Kanboard\Plugin\Passkey\Auth\PasskeyAuthProvider;
use Kanboard\Plugin\Passkey\Auth\PasskeyTwoFactorProvider;

/**
 * Passkeys (WebAuthn) for Kanboard.
 *
 * Two things, sharing one credential store:
 *
 *  - signing in with no password at all, using a discoverable credential from
 *    iCloud Keychain, Google Password Manager, Windows Hello, a password
 *    manager or a security key;
 *  - a passkey as the second factor, chosen per user, alongside the one-time
 *    code Kanboard already ships.
 *
 * No core file is modified. The only core template replaced is twofactor/check,
 * and the replacement renders Kanboard's own markup untouched for anyone still
 * on a one-time code — PostAuthenticationMiddleware will not route to any other
 * controller while a second factor is pending, so the prompt has nowhere else
 * it could live.
 */
class Plugin extends Base
{
    public function initialize()
    {
        // The provider that opens the session once an assertion checks out.
        // It stays inert unless PasskeyLoginController has just verified one.
        $this->authenticationManager->register(new PasskeyAuthProvider($this->container));

        // Registered last on purpose: getPostAuthenticationProvider() pops the
        // final entry, and this one delegates to TotpAuth for every user who
        // has not chosen a passkey.
        $this->authenticationManager->register(new PasskeyTwoFactorProvider($this->container));

        $this->helper->register('passkey', '\Kanboard\Plugin\Passkey\Helper\PasskeyHelper');

        // Signing in happens before there is a session, so these two have to
        // be reachable by an anonymous request.
        $this->applicationAccessMap->add('PasskeyLoginController', array('options', 'verify'), Role::APP_PUBLIC);

        $this->route->addRoute('/user/:user_id/passkeys', 'PasskeyController', 'index', 'Passkey');
        $this->route->addRoute('/settings/passkeys', 'ConfigController', 'show', 'Passkey');

        $this->template->hook->attach('template:auth:login-form:after', 'Passkey:auth/login');
        $this->template->hook->attach('template:user:sidebar:actions', 'Passkey:user/sidebar');
        $this->template->hook->attach('template:config:sidebar', 'Passkey:config/sidebar');

        // The second-factor prompt, with the numeric form kept verbatim for
        // users who are not on a passkey.
        $this->template->setTemplateOverride('twofactor/check', 'Passkey:twofactor/check');

        $this->hook->on('template:layout:js', array('template' => 'plugins/Passkey/Assets/js/passkey.js'));
        $this->hook->on('template:layout:css', array('template' => 'plugins/Passkey/Assets/css/passkey.css'));

        $this->dispatcher->addListener(AuthenticationManager::EVENT_SUCCESS, array($this, 'onLoginSuccess'));

        $this->registerBreadcrumbs();
    }

    /**
     * Name these pages for a theme that draws a breadcrumb.
     *
     * Kanboard has no breadcrumb of its own — it joins the trail into the
     * <h1> — so there is nothing core to hook. A theme that builds one has to
     * do it from the route, which means it cannot know a plugin's controllers
     * unless the plugin says. Guarded by class_exists, so this is inert on an
     * installation without that theme rather than a hard dependency on it.
     */
    private function registerBreadcrumbs()
    {
        $sidebar = '\Kanboard\Plugin\Shadcn\Helper\SidebarHelper';

        if (! class_exists($sidebar) || ! method_exists($sidebar, 'registerSection')) {
            return;
        }

        // Passkeys are personal, so the profile page belongs under Users.
        call_user_func(array($sidebar, 'registerSection'), 'PasskeyController', t('Passkeys'), 'users');

        // This one shares a short name with core's, hence the last argument.
        call_user_func(array($sidebar, 'registerSection'), 'ConfigController', t('Passkeys'), 'settings', 'Passkey');
    }

    /**
     * A passkey unlocked with a fingerprint, face or PIN is already two
     * factors — something you have and something you are. Asking for a
     * one-time code on top would be theatre, so the post-authentication step
     * is marked as satisfied, exactly as Kanboard does for RememberMe.
     *
     * When user verification is not required, the passkey proves possession
     * only and the second factor is left to run.
     *
     * @param AuthSuccessEvent $event
     */
    public function onLoginSuccess(AuthSuccessEvent $event)
    {
        // A session survives a login: UserSession::initialize() regenerates the
        // id but deliberately keeps the data, so whatever the previous user
        // left behind is still here. A pending ceremony is the dangerous part
        // of that — TwoFactorController only calls beforeCode() when
        // twoFactorBeforeCodeCalled is unset, so without this the next user
        // would be shown the previous user's challenge, or none at all.
        session_remove(PasskeyTwoFactorProvider::SESSION_CHALLENGE);
        session_remove(PasskeyTwoFactorProvider::SESSION_OPTIONS);
        session_remove('twoFactorBeforeCodeCalled');

        if ($event->getAuthType() === PasskeyAuthProvider::NAME && $this->passkeySettingsModel->isUserVerificationRequired()) {
            $this->userSession->setPostAuthenticationAsValidated();
        }
    }

    public function onStartup()
    {
        Translator::load($this->languageModel->getCurrentLanguage(), __DIR__.'/Locale');
    }

    public function getClasses()
    {
        return array(
            'Plugin\Passkey\Model' => array(
                'PasskeyCredentialModel',
                'PasskeySettingsModel',
            ),
        );
    }

    public function getPluginName()
    {
        return 'Passkey';
    }

    public function getPluginDescription()
    {
        return t('Sign in with a passkey, or use one as your second factor');
    }

    public function getPluginAuthor()
    {
        return 'kaiyi';
    }

    public function getPluginVersion()
    {
        return '0.1.2';
    }

    public function getPluginHomepage()
    {
        return 'https://github.com/heykaiyi/kanboard-passkey';
    }

    public function getCompatibleVersion()
    {
        return '>=1.2.0';
    }
}
