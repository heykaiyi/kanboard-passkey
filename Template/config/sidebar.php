<li <?= $this->app->checkMenuSelection('ConfigController', 'show', 'Passkey') ?>>
    <?= $this->url->link(t('Passkeys'), 'ConfigController', 'show', array('plugin' => 'Passkey')) ?>
</li>
