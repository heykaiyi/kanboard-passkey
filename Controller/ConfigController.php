<?php

namespace Kanboard\Plugin\Passkey\Controller;

use Kanboard\Plugin\Passkey\Model\PasskeySettingsModel;

/**
 * Settings &gt; Passkeys.
 */
class ConfigController extends \Kanboard\Controller\ConfigController
{
    public function show()
    {
        $this->response->html($this->helper->layout->config('Passkey:config/settings', array(
            'title' => t('Passkeys'),
            'effective_rp_id' => $this->passkeySettingsModel->getRelyingPartyId(),
            'effective_rp_name' => $this->passkeySettingsModel->getRelyingPartyName(),
            'effective_origins' => implode(', ', $this->passkeySettingsModel->getAllowedOrigins()),
            'is_secure_context' => $this->request->isHTTPS() || $this->isLoopback(),
        )));
    }

    public function save()
    {
        $values = $this->request->getValues();

        $saved = $this->configModel->save(array(
            PasskeySettingsModel::KEY_RP_ID => trim((string) $this->value($values, PasskeySettingsModel::KEY_RP_ID)),
            PasskeySettingsModel::KEY_RP_NAME => trim((string) $this->value($values, PasskeySettingsModel::KEY_RP_NAME)),
            PasskeySettingsModel::KEY_ORIGINS => $this->normalizeOrigins($this->value($values, PasskeySettingsModel::KEY_ORIGINS)),
            PasskeySettingsModel::KEY_USER_VERIFICATION => $this->value($values, PasskeySettingsModel::KEY_USER_VERIFICATION) === 'preferred' ? 'preferred' : 'required',
            PasskeySettingsModel::KEY_PASSWORDLESS => empty($values[PasskeySettingsModel::KEY_PASSWORDLESS]) ? '0' : '1',
        ));

        if ($saved) {
            $this->flash->success(t('Settings saved successfully.'));
        } else {
            $this->flash->failure(t('Unable to save your settings.'));
        }

        $this->response->redirect($this->helper->url->to('ConfigController', 'show', array('plugin' => 'Passkey')));
    }

    private function value(array $values, $key)
    {
        return isset($values[$key]) ? $values[$key] : '';
    }

    /**
     * Store what was meant rather than what was typed, so the field shows the
     * corrected value the next time this page is opened.
     *
     * @param  string $value
     * @return string
     */
    private function normalizeOrigins($value)
    {
        $origins = array_map(
            array('Kanboard\\Plugin\\Passkey\\Model\\PasskeySettingsModel', 'normalizeOrigin'),
            explode(',', (string) $value)
        );

        return implode(', ', array_unique(array_filter($origins)));
    }

    /**
     * Browsers only expose WebAuthn in a secure context, and localhost counts
     * as one. Worth saying out loud on the settings page, because otherwise
     * the buttons simply do nothing and there is no error to read.
     */
    private function isLoopback()
    {
        $host = preg_replace('/:\d+$/', '', (string) $this->request->getServerVariable('HTTP_HOST'));

        return in_array($host, array('localhost', '127.0.0.1', '[::1]'), true);
    }
}
