<?php
/**
 * Override of core's twofactor/check.
 *
 * PostAuthenticationMiddleware will not route anywhere but TwoFactorController
 * while a second factor is pending, so the passkey prompt has to live on this
 * page. The assertion is posted in the same `code` field the numeric form
 * uses, and PasskeyTwoFactorProvider reads it there — which is what keeps core
 * untouched.
 *
 * When the signed-in user is on a one-time code, this renders exactly what
 * Kanboard renders without the plugin.
 */
$passkeyOptions = $this->passkey->getTwoFactorOptions();
?>
<section class="form-login">
    <div class="page-header">
        <h2><?= t('Two factor authentication') ?></h2>
    </div>

    <?php if ($passkeyOptions !== ''): ?>
        <form method="post" class="js-passkey-2fa-form"
              action="<?= $this->url->href('TwoFactorController', 'check', array('user_id' => $this->user->getId())) ?>"
              data-options="<?= $this->text->e($passkeyOptions) ?>"
              data-messages="<?= $this->text->e($this->passkey->getMessages()) ?>">
            <?= $this->form->csrf() ?>
            <input type="hidden" name="code" class="js-passkey-2fa-code" value="">

            <p class="form-help"><?= t('Unlock your passkey to finish signing in.') ?></p>

            <div class="form-actions">
                <button type="button" class="btn btn-blue js-passkey-2fa">
                    <i class="fa fa-id-badge fa-fw" aria-hidden="true"></i> <?= t('Use my passkey') ?>
                </button>
                <?= t('or') ?>
                <?= $this->url->link(t('cancel'), 'AuthController', 'logout', [], true) ?>
            </div>
            <p class="passkey-error" role="alert" hidden></p>
        </form>
    <?php else: ?>
        <form method="post" action="<?= $this->url->href('TwoFactorController', 'check', array('user_id' => $this->user->getId())) ?>">
            <?= $this->form->csrf() ?>

            <?= $this->form->label(t('Code'), 'code') ?>
            <?= $this->form->text('code', array(), array(), array('placeholder="123456"', 'autofocus', 'autocomplete="one-time-code"', 'pattern="[0-9]*"', 'inputmode="numeric"'), 'form-numeric') ?>

            <div class="form-actions">
                <button type="submit" class="btn btn-blue"><?= t('Check my code') ?></button>
                <?= t('or') ?>
                <?= $this->url->link(t('cancel'), 'AuthController', 'logout', [], true) ?>
            </div>
        </form>
    <?php endif ?>
</section>
