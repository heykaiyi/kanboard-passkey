<?php

namespace Kanboard\Plugin\Passkey;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Core\Security\OAuthAuthenticationProviderInterface;
use Kanboard\Core\Security\Role;
use Kanboard\Core\Translator;
use Kanboard\Event\AuthSuccessEvent;
use LogicException;
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
    const SESSION_SECOND_FACTOR_PASSED = 'passkeySecondFactorPassedFor';

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
     * Some ways in have already done what the second factor is there to do.
     *
     * Kanboard exempts exactly one — RememberMe, in AuthSubscriber — by
     * naming it. Two more belong on that list once the second factor is a
     * passkey, and both are decided in isSecondFactorAlreadySatisfied().
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

        // A new login starts unproven, whoever held this session before.
        session_remove(self::SESSION_SECOND_FACTOR_PASSED);

        $this->rememberWhereToGoAfterSecondFactor();

        if ($this->isSecondFactorAlreadySatisfied($event->getAuthType())) {
            $this->userSession->setPostAuthenticationAsValidated();
        }
    }

    /**
     * Keep the page the user was heading for, past the second factor.
     *
     * This runs inside the login, before the controller that handled it reads
     * redirectAfterLogin. That controller then deletes it and redirects, and
     * PostAuthenticationMiddleware turns the redirect into the second-factor
     * prompt — so by the time the prompt is answered the destination is gone,
     * and TwoFactorController::check() sends everyone to the dashboard. The
     * copy taken here is what the prompt hands to the browser up front.
     */
    private function rememberWhereToGoAfterSecondFactor()
    {
        $target = (string) session_get('redirectAfterLogin');

        if ($this->request->isSafeRedirectUri($target)) {
            session_set(PasskeyTwoFactorProvider::SESSION_REDIRECT, $target);
        } else {
            session_remove(PasskeyTwoFactorProvider::SESSION_REDIRECT);
        }
    }

    /**
     * Whether the way this user just signed in already carries a second
     * factor, making the prompt a formality to type through.
     *
     * Scoped to users whose second factor is a passkey. A user on a one-time
     * code is on Kanboard's own path, and installing this plugin is not a
     * reason for their login to start behaving differently.
     *
     * @param  string $authType
     * @return bool
     */
    private function isSecondFactorAlreadySatisfied($authType)
    {
        // A passkey unlocked with a fingerprint, face or PIN is already two
        // factors — something you have and something you are. Asking for a
        // second passkey on top would be theatre. Lower user verification to
        // "preferred" and it proves possession only, so the prompt stands.
        if ($authType === PasskeyAuthProvider::NAME) {
            return $this->passkeySettingsModel->isUserVerificationRequired();
        }

        $userId = $this->userSession->getId();

        if ($userId <= 0 || ! $this->passkeySettingsModel->isTwoFactorPasskey($userId)) {
            return false;
        }

        // Signing in through Google or any other OAuth provider means that
        // provider has already authenticated this person against an account
        // that carries its own second factor. Asked by interface rather than
        // by name, so every OAuth plugin counts and none has to be listed.
        try {
            $provider = $this->authenticationManager->getProvider($authType);
        } catch (LogicException $e) {
            return false;
        }

        return $provider instanceof OAuthAuthenticationProviderInterface;
    }

    public function onStartup()
    {
        Translator::load($this->languageModel->getCurrentLanguage(), __DIR__.'/Locale');

        $this->keepSecondFactorAcrossProfileChanges();
    }

    /**
     * Do not ask for the passkey again because the user changed their own
     * account.
     *
     * Every UserModel::update() of the signed-in user — generating an API
     * token, editing the profile, changing the language — calls
     * UserSession::refresh(), which re-runs initialize() and with it resets
     * postAuthenticationValidated to false. The next request then lands on
     * the second-factor prompt in the middle of an ordinary session, and
     * dismissing the passkey sheet there leaves the user on a page that looks
     * exactly like being signed out.
     *
     * This runs on app.bootstrap — after the session is open, before
     * PostAuthenticationMiddleware. A session that has passed the second
     * factor is marked with the user it passed for; when that same user turns
     * up unvalidated in that same session, it was a refresh and not a login,
     * so the validation is put back. A login clears the mark first (see
     * onLoginSuccess), and a logout destroys the session that holds it.
     *
     * Scoped to users whose second factor is a passkey, like the rest of the
     * plugin's changes to how a login behaves.
     */
    private function keepSecondFactorAcrossProfileChanges()
    {
        if (! $this->userSession->hasPostAuthentication()) {
            return;
        }

        $userId = $this->userSession->getId();

        if ($this->userSession->isPostAuthenticationValidated()) {
            session_set(self::SESSION_SECOND_FACTOR_PASSED, $userId);
            return;
        }

        if ((int) session_get(self::SESSION_SECOND_FACTOR_PASSED) === $userId
            && $this->passkeySettingsModel->isTwoFactorPasskey($userId)) {
            $this->userSession->setPostAuthenticationAsValidated();
        }
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
        return '0.1.5';
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
