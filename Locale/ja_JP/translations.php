<?php

return array(
    // Plugin
    'Sign in with a passkey, or use one as your second factor' => 'パスキーでログイン、または二段階目の認証に使う',

    // Login
    'Sign in with a passkey' => 'パスキーでログイン',
    'Signing in with a passkey is disabled.' => 'パスキーによるログインは管理者が無効にしています。',
    'This sign-in took too long, please try again.' => 'ログインに時間がかかりすぎました。もう一度お試しください。',
    'This passkey is not registered here.' => 'このパスキーはここに登録されていません。',
    'This passkey belongs to a different account.' => 'このパスキーは別のアカウントのものです。',
    'This account cannot sign in.' => 'このアカウントはログインできません。',
    'The browser sent nothing to check.' => 'ブラウザから検証できるデータが届きませんでした。',

    // Passkey page
    'Passkeys' => 'パスキー',
    'Passkey' => 'パスキー',
    'A passkey is stored by iCloud Keychain, Google Password Manager, Windows Hello, a password manager or a security key, and is unlocked with your fingerprint, face or device PIN. It never leaves the device and there is nothing to type.'
        => 'パスキーは iCloud キーチェーン、Google パスワード マネージャー、Windows Hello、パスワード管理アプリ、セキュリティキーなどに保存され、指紋・顔・端末の PIN で解除します。端末から出ることはなく、入力するものもありません。',
    'You have not registered any passkey yet.' => 'まだパスキーを登録していません。',
    'Provider' => '保管場所',
    'Storage' => '同期',
    'Added' => '追加日',
    'Last used' => '最終使用',
    'Never' => '未使用',
    'Synced' => '端末間で同期',
    'This device only' => 'この端末のみ',
    'Unknown provider' => '非公開',
    'Security key' => 'セキュリティキー',
    'Name this passkey' => 'このパスキーの名前',
    'MacBook Touch ID, iPhone, YubiKey...' => 'MacBook Touch ID、iPhone、YubiKey…',
    'Add a passkey' => 'パスキーを追加',
    'Remove a passkey' => 'パスキーを削除',
    'Do you really want to remove this passkey: "%s"?' => 'このパスキー「%s」を削除しますか？',
    'Passkey registered successfully.' => 'パスキーを登録しました。',
    'Passkey removed successfully.' => 'パスキーを削除しました。',
    'Passkey renamed successfully.' => 'パスキーの名前を変更しました。',
    'Unable to save this passkey.' => 'このパスキーを保存できません。',
    'Unable to remove this passkey.' => 'このパスキーを削除できません。',
    'This passkey is already registered.' => 'このパスキーはすでに登録されています。',
    'This registration took too long, please try again.' => '登録に時間がかかりすぎました。もう一度お試しください。',
    'The name cannot be empty.' => '名前は空にできません。',
    'This browser cannot create passkeys. Passkeys need an up-to-date browser on a page served over HTTPS.'
        => 'このブラウザではパスキーを作成できません。新しいブラウザと HTTPS でのアクセスが必要です。',
    'Passkeys on this site are bound to %s.' => 'この Kanboard のパスキーは %s に紐づいています。',
    'Your passkeys can also replace your password entirely: pick "Sign in with a passkey" on the login page.'
        => 'パスキーはパスワードの代わりにもなります。ログイン画面で「パスキーでログイン」を選んでください。',
    'An administrator has turned off signing in with a passkey, so your passkeys are only used as a second factor.'
        => '管理者がパスキーでのログインを無効にしているため、パスキーは二段階目の認証にのみ使われます。',

    // Second factor
    'Passkey or one-time code' => 'パスキーまたはワンタイムコード',
    'Pick what Kanboard asks for after your password: the six digit code from an app such as Google Authenticator, or one of your passkeys.'
        => 'パスワードの次に何を求めるかを選びます。Google Authenticator などのアプリが出す 6 桁のコードか、登録したパスキーです。',
    'Ask for a passkey as my second factor' => '二段階目の認証にパスキーを使う',
    'Register a passkey first.' => '先にパスキーを登録してください。',
    'Your passkey is now your second factor.' => '二段階目の認証にパスキーを使います。',
    'Two-factor authentication with a passkey is turned off.' => 'パスキーによる二段階認証を無効にしました。',
    'Two-factor authentication was turned off because your last passkey is gone.' => '最後のパスキーが削除されたため、二段階認証も無効にしました。',
    'You currently use a one-time code. Switching to a passkey will delete the code secret, and your authenticator app entry stops working.'
        => '現在はワンタイムコードを使っています。パスキーに切り替えるとコードの秘密鍵が削除され、認証アプリの登録は使えなくなります。',
    'Set up a one-time code instead' => 'ワンタイムコードを設定する',
    'Unlock your passkey to finish signing in.' => 'パスキーを解除するとログインが完了します。',
    'Use my passkey' => 'パスキーを使う',

    // Browser-side
    'The request was cancelled or timed out.' => 'キャンセルされたか、時間切れになりました。',
    'This device already holds a passkey for this account.' => 'この端末にはこのアカウントのパスキーがすでにあります。',
    'Your passkey could not be used.' => 'パスキーを使用できませんでした。',
    'Waiting for your passkey...' => 'パスキーを待っています…',

    // Settings
    'Allow signing in with a passkey instead of a password' => 'パスワードの代わりにパスキーでのログインを許可する',
    'Relying party ID' => 'Relying party ID',
    'The domain passkeys are bound to. Leave empty to use the host from the application URL, currently %s.'
        => 'パスキーを紐づけるドメイン。空欄ならアプリケーション URL のホスト名（現在は %s）を使います。',
    'Changing this invalidates every passkey already registered.' => 'これを変更すると、登録済みのパスキーはすべて無効になります。',
    'Display name' => '表示名',
    'Shown by the browser and stored in the password manager. Currently %s.' => 'ブラウザに表示され、パスワード管理アプリに保存される名前です。現在は %s。',
    'Allowed origins' => '許可するオリジン',
    'Comma separated. Leave empty to derive it from the application URL, currently %s.' => 'カンマ区切り。空欄ならアプリケーション URL から導出します（現在は %s）。',
    'Set this by hand when Kanboard sits behind a proxy that rewrites the host.' => 'ホスト名を書き換えるプロキシの背後にある場合は手動で指定してください。',
    'User verification' => '利用者の確認',
    'Required (fingerprint, face or PIN every time)' => '必須（毎回、指紋・顔・PIN）',
    'Preferred (allow a bare tap when the device cannot verify)' => '推奨（端末が確認できない場合はタップのみを許可）',
    'A passkey only stands in for a password plus a code when the device verifies who is holding it. Lower this only if some of your authenticators cannot.'
        => 'パスキーが「パスワード＋コード」の代わりになるのは、端末が持ち主を確認した場合だけです。確認できない認証器がある場合にのみ下げてください。',
    'This page is not served over HTTPS. Browsers refuse to create or use passkeys outside a secure context, so nothing here will work until Kanboard is reachable over HTTPS.'
        => 'このページは HTTPS ではありません。ブラウザは安全なコンテキスト以外でパスキーを作成・使用しないため、HTTPS でアクセスできるようになるまでこの機能は動きません。',
);
