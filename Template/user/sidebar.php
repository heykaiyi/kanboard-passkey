<?php if ($this->user->isCurrentUser($user['id'])): ?>
    <li <?= $this->app->checkMenuSelection('PasskeyController', 'index', 'Passkey') ?>>
        <?= $this->url->link(t('Passkeys'), 'PasskeyController', 'index', array('user_id' => $user['id'], 'plugin' => 'Passkey')) ?>
    </li>
<?php endif ?>
