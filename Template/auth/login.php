<?php
/**
 * The "sign in with a passkey" button.
 *
 * Deliberately the same markup an auth plugin like GoogleAuth emits — a
 * .no-bullet list of links after </form> — because that is the shape themes
 * style as the social row under the sign-in button. Matching it means the
 * passkey button looks like "Login with my Google Account" in whatever theme
 * is installed, instead of carrying its own idea of a button that only agrees
 * with the stock stylesheet.
 *
 * It is an <a role="button"> rather than a <button> for the same reason: the
 * rule that paints that row is written for links.
 *
 * Assets/js/passkey.js lifts the list to be a direct child of .form-login, and
 * folds it into an existing social list when there is one, so two auth plugins
 * produce one row and not two.
 *
 * Nothing is emitted when no passkey exists anywhere on this installation, so
 * a fresh install shows the plain login form it always did.
 */
if (! $this->passkey->isSignInAvailable()) {
    return;
}
?>
<div class="passkey-signin"
     data-messages="<?= $this->text->e($this->passkey->getMessages()) ?>"
     data-options-url="<?= $this->url->href('PasskeyLoginController', 'options', array('plugin' => 'Passkey')) ?>"
     data-verify-url="<?= $this->url->href('PasskeyLoginController', 'verify', array('plugin' => 'Passkey')) ?>"
     data-redirect="<?= $this->text->e($this->passkey->getLoginRedirect()) ?>"
     data-csrf="<?= $this->passkey->getCsrfToken() ?>">
    <ul class="no-bullet js-passkey-list">
        <li>
            <a href="#" role="button" class="passkey-button js-passkey-signin">
                <i class="fa fa-id-badge fa-fw" aria-hidden="true"></i> <?= t('Sign in with a passkey') ?>
            </a>
        </li>
    </ul>
    <p class="passkey-error" role="alert" hidden></p>
</div>
