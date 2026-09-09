<div class="page-header">
    <h2><?= t('Passkeys') ?></h2>
</div>

<?php if (! $is_secure_context): ?>
    <p class="alert alert-error">
        <?= t('This page is not served over HTTPS. Browsers refuse to create or use passkeys outside a secure context, so nothing here will work until Kanboard is reachable over HTTPS.') ?>
    </p>
<?php endif ?>

<form method="post" action="<?= $this->url->href('ConfigController', 'save', array('plugin' => 'Passkey')) ?>" autocomplete="off">
    <?= $this->form->csrf() ?>

    <?= $this->form->checkbox('passkey_passwordless', t('Allow signing in with a passkey instead of a password'), '1', $this->app->config('passkey_passwordless', '1') === '1') ?>

    <?= $this->form->label(t('Relying party ID'), 'passkey_rp_id') ?>
    <?= $this->form->text('passkey_rp_id', $values, array(), array('placeholder="kanboard.example.com"'), 'form-input-large') ?>
    <p class="form-help">
        <?= t('The domain passkeys are bound to. Leave empty to use the host from the application URL, currently %s.', $effective_rp_id) ?>
        <br>
        <strong><?= t('Changing this invalidates every passkey already registered.') ?></strong>
    </p>

    <?= $this->form->label(t('Display name'), 'passkey_rp_name') ?>
    <?= $this->form->text('passkey_rp_name', $values, array(), array(), 'form-input-large') ?>
    <p class="form-help"><?= t('Shown by the browser and stored in the password manager. Currently %s.', $effective_rp_name) ?></p>

    <?= $this->form->label(t('Allowed origins'), 'passkey_origins') ?>
    <?= $this->form->text('passkey_origins', $values, array(), array('placeholder="https://kanboard.example.com"'), 'form-input-large') ?>
    <p class="form-help">
        <?= t('Comma separated, each one a full origin with its scheme — %s, not %s.', 'https://kanboard.example.com', 'kanboard.example.com') ?>
        <?= t('Leave empty to derive it from the application URL, currently %s.', $effective_origins) ?>
        <?= t('Set this by hand when Kanboard sits behind a proxy that rewrites the host.') ?>
    </p>

    <?= $this->form->label(t('User verification'), 'passkey_user_verification') ?>
    <?= $this->form->select('passkey_user_verification', array(
        'required' => t('Required (fingerprint, face or PIN every time)'),
        'preferred' => t('Preferred (allow a bare tap when the device cannot verify)'),
    ), $values) ?>
    <p class="form-help">
        <?= t('A passkey only stands in for a password plus a code when the device verifies who is holding it. Lower this only if some of your authenticators cannot.') ?>
    </p>

    <div class="form-actions">
        <button type="submit" class="btn btn-blue"><?= t('Save') ?></button>
    </div>
</form>
