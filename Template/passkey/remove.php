<div class="page-header">
    <h2><?= t('Remove a passkey') ?></h2>
</div>

<div class="confirm">
    <p class="alert alert-info">
        <?= t('Do you really want to remove this passkey: "%s"?', $credential['name']) ?>
    </p>

    <?= $this->modal->confirmButtons(
        'PasskeyController',
        'remove',
        array('user_id' => $user['id'], 'credential_id' => $credential['id'], 'plugin' => 'Passkey')
    ) ?>
</div>
