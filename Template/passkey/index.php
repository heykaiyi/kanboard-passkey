<div class="page-header">
    <h2><?= t('Passkeys') ?></h2>
</div>

<p class="form-help">
    <?= t('A passkey is stored by iCloud Keychain, Google Password Manager, Windows Hello, a password manager or a security key, and is unlocked with your fingerprint, face or device PIN. It never leaves the device and there is nothing to type.') ?>
</p>

<?php if (empty($credentials)): ?>
    <p class="alert"><?= t('You have not registered any passkey yet.') ?></p>
<?php else: ?>
    <table class="table-striped table-scrolling">
        <tr>
            <th class="column-30"><?= t('Name') ?></th>
            <th class="column-20"><?= t('Provider') ?></th>
            <th class="column-15"><?= t('Storage') ?></th>
            <th class="column-15"><?= t('Added') ?></th>
            <th class="column-15"><?= t('Last used') ?></th>
            <th></th>
        </tr>
        <?php foreach ($credentials as $credential): ?>
            <tr>
                <td>
                    <form method="post" class="passkey-rename"
                          action="<?= $this->url->href('PasskeyController', 'rename', array('user_id' => $user['id'], 'credential_id' => $credential['id'], 'plugin' => 'Passkey')) ?>">
                        <?= $this->form->csrf() ?>
                        <?= $this->form->text('name', $credential, array(), array('maxlength="100"', 'aria-label="'.t('Name').'"')) ?>
                        <button type="submit" class="btn"><?= t('Rename') ?></button>
                    </form>
                </td>
                <td><?= $this->text->e($this->passkey->getAuthenticatorName($credential)) ?></td>
                <td><?= $this->text->e($this->passkey->getStorageLabel($credential)) ?></td>
                <td><?= $this->dt->date($credential['created_at']) ?></td>
                <td>
                    <?= $credential['last_used_at'] > 0 ? $this->dt->datetime($credential['last_used_at']) : t('Never') ?>
                </td>
                <td>
                    <?= $this->modal->confirm('trash-o', t('Remove'), 'PasskeyController', 'confirm', array('user_id' => $user['id'], 'credential_id' => $credential['id'], 'plugin' => 'Passkey')) ?>
                </td>
            </tr>
        <?php endforeach ?>
    </table>
<?php endif ?>

<div class="passkey-register"
     data-messages="<?= $this->text->e($this->passkey->getMessages()) ?>"
     data-options-url="<?= $this->url->href('PasskeyController', 'createOptions', array('user_id' => $user['id'], 'plugin' => 'Passkey')) ?>"
     data-verify-url="<?= $this->url->href('PasskeyController', 'createVerify', array('user_id' => $user['id'], 'plugin' => 'Passkey')) ?>"
     data-csrf="<?= $this->passkey->getCsrfToken() ?>">
    <?= $this->form->label(t('Name this passkey'), 'passkey_name') ?>
    <input type="text" id="form-passkey_name" class="js-passkey-name" maxlength="100"
           placeholder="<?= t('MacBook Touch ID, iPhone, YubiKey...') ?>">

    <div class="form-actions">
        <button type="button" class="btn btn-blue js-passkey-register">
            <i class="fa fa-plus fa-fw" aria-hidden="true"></i> <?= t('Add a passkey') ?>
        </button>
    </div>
    <p class="passkey-error" role="alert" hidden></p>
    <p class="passkey-unsupported form-help" hidden><?= t('This browser cannot create passkeys. Passkeys need an up-to-date browser on a page served over HTTPS.') ?></p>
</div>

<hr>

<div class="page-header">
    <h2><?= t('Two factor authentication') ?></h2>
</div>

<p class="form-help">
    <?= t('Pick what Kanboard asks for after your password: the six digit code from an app such as Google Authenticator, or one of your passkeys.') ?>
</p>

<?php if ($has_totp_secret): ?>
    <p class="alert alert-info">
        <?= t('You currently use a one-time code. Switching to a passkey will delete the code secret, and your authenticator app entry stops working.') ?>
    </p>
<?php endif ?>

<form method="post" action="<?= $this->url->href('PasskeyController', 'saveTwoFactor', array('user_id' => $user['id'], 'plugin' => 'Passkey')) ?>">
    <?= $this->form->csrf() ?>
    <?= $this->form->checkbox('two_factor_passkey', t('Ask for a passkey as my second factor'), 1, $two_factor_passkey) ?>

    <?php if (empty($credentials)): ?>
        <p class="form-help"><?= t('Register a passkey first.') ?></p>
    <?php endif ?>

    <div class="form-actions">
        <button type="submit" class="btn btn-blue"><?= t('Save') ?></button>
    </div>
</form>

<p class="form-help">
    <?= $this->url->link(t('Set up a one-time code instead'), 'TwoFactorController', 'index', array('user_id' => $user['id'])) ?>
</p>

<?php if ($passwordless_enabled): ?>
    <p class="form-help">
        <?= t('Your passkeys can also replace your password entirely: pick "Sign in with a passkey" on the login page.') ?>
    </p>
<?php else: ?>
    <p class="form-help">
        <?= t('An administrator has turned off signing in with a passkey, so your passkeys are only used as a second factor.') ?>
    </p>
<?php endif ?>

<p class="form-help"><?= t('Passkeys on this site are bound to %s.', $relying_party_id) ?></p>
