<?php

return array(
    // Plugin
    'Sign in with a passkey, or use one as your second factor' => '用 passkey 登入，或拿它當第二道驗證',

    // Login
    'Sign in with a passkey' => '用 passkey 登入',
    'Signing in with a passkey is disabled.' => '管理者已關閉 passkey 登入。',
    'This sign-in took too long, please try again.' => '這次登入等太久了，請再試一次。',
    'This passkey is not registered here.' => '這個 passkey 沒有註冊在這台 Kanboard。',
    'This passkey belongs to a different account.' => '這個 passkey 屬於另一個帳號。',
    'This account cannot sign in.' => '這個帳號無法登入。',
    'The browser sent nothing to check.' => '瀏覽器沒有送出可驗證的內容。',

    // Passkey page
    'Passkeys' => 'Passkey',
    'Passkey' => 'Passkey',
    'A passkey is stored by iCloud Keychain, Google Password Manager, Windows Hello, a password manager or a security key, and is unlocked with your fingerprint, face or device PIN. It never leaves the device and there is nothing to type.'
        => 'Passkey 會存在 iCloud 鑰匙圈、Google 密碼管理工具、Windows Hello、密碼管理程式或實體安全金鑰裡，用指紋、臉或裝置 PIN 解鎖。它不會離開你的裝置，也沒有東西要打。',
    'You have not registered any passkey yet.' => '你還沒有註冊任何 passkey。',
    'Provider' => '存放位置',
    'Storage' => '同步狀態',
    'Added' => '新增於',
    'Last used' => '最後使用',
    'Never' => '從未使用',
    'Synced' => '跨裝置同步',
    'This device only' => '只在這台裝置',
    'Unknown provider' => '未表明身分',
    'Security key' => '安全金鑰',
    'Name this passkey' => '幫這個 passkey 取名字',
    'MacBook Touch ID, iPhone, YubiKey...' => 'MacBook Touch ID、iPhone、YubiKey…',
    'Add a passkey' => '新增 passkey',
    'Remove a passkey' => '移除 passkey',
    'Do you really want to remove this passkey: "%s"?' => '確定要移除這個 passkey：「%s」嗎？',
    'Passkey registered successfully.' => 'Passkey 註冊成功。',
    'Passkey removed successfully.' => 'Passkey 已移除。',
    'Passkey renamed successfully.' => 'Passkey 已改名。',
    'Unable to save this passkey.' => '無法儲存這個 passkey。',
    'Unable to remove this passkey.' => '無法移除這個 passkey。',
    'This passkey is already registered.' => '這個 passkey 已經註冊過了。',
    'This registration took too long, please try again.' => '這次註冊等太久了，請再試一次。',
    'The name cannot be empty.' => '名字不能空白。',
    'This browser cannot create passkeys. Passkeys need an up-to-date browser on a page served over HTTPS.'
        => '這個瀏覽器不能建立 passkey。Passkey 需要較新的瀏覽器，而且網頁要走 HTTPS。',
    'Passkeys on this site are bound to %s.' => '這台 Kanboard 的 passkey 綁定在 %s。',
    'Your passkeys can also replace your password entirely: pick "Sign in with a passkey" on the login page.'
        => '你的 passkey 也可以完全取代密碼：在登入頁選「用 passkey 登入」。',
    'An administrator has turned off signing in with a passkey, so your passkeys are only used as a second factor.'
        => '管理者關掉了 passkey 登入，所以你的 passkey 只會用在第二道驗證。',

    // Second factor
    'Passkey or one-time code' => 'Passkey 或一次性驗證碼',
    'Pick what Kanboard asks for after your password: the six digit code from an app such as Google Authenticator, or one of your passkeys.'
        => '選一個輸入密碼之後要驗的東西：Google Authenticator 之類的 App 給的六位數驗證碼，或是你的其中一把 passkey。',
    'Ask for a passkey as my second factor' => '第二道驗證改用 passkey',
    'Register a passkey first.' => '請先註冊一把 passkey。',
    'Your passkey is now your second factor.' => '之後第二道驗證會問你的 passkey。',
    'Two-factor authentication with a passkey is turned off.' => '已關閉用 passkey 做第二道驗證。',
    'Two-factor authentication was turned off because your last passkey is gone.' => '最後一把 passkey 被移除了，所以雙重驗證一併關閉。',
    'You currently use a one-time code. Switching to a passkey will delete the code secret, and your authenticator app entry stops working.'
        => '你目前用的是一次性驗證碼。改成 passkey 會刪掉驗證碼的密鑰，驗證器 App 裡那一筆就失效了。',
    'Set up a one-time code instead' => '改用一次性驗證碼',
    'Unlock your passkey to finish signing in.' => '解鎖你的 passkey 就完成登入。',
    'Use my passkey' => '使用我的 passkey',

    // Browser-side
    'The request was cancelled or timed out.' => '要求被取消或逾時了。',
    'This device already holds a passkey for this account.' => '這台裝置已經有這個帳號的 passkey 了。',
    'Your passkey could not be used.' => '這把 passkey 沒辦法使用。',
    'Waiting for your passkey...' => '等你的 passkey…',

    // Settings
    'Allow signing in with a passkey instead of a password' => '允許用 passkey 取代密碼登入',
    'Relying party ID' => 'Relying party ID',
    'The domain passkeys are bound to. Leave empty to use the host from the application URL, currently %s.'
        => 'Passkey 綁定的網域。留空就用應用程式網址的主機名稱，目前是 %s。',
    'Changing this invalidates every passkey already registered.' => '改掉它，已經註冊的 passkey 會全部失效。',
    'Display name' => '顯示名稱',
    'Shown by the browser and stored in the password manager. Currently %s.' => '瀏覽器會顯示、密碼管理工具會存下來的名稱。目前是 %s。',
    'Allowed origins' => '允許的來源',
    'Comma separated. Leave empty to derive it from the application URL, currently %s.' => '用逗號分隔。留空就從應用程式網址推導，目前是 %s。',
    'Set this by hand when Kanboard sits behind a proxy that rewrites the host.' => 'Kanboard 放在會改寫主機名稱的反向代理後面時，要自己填。',
    'User verification' => '使用者驗證',
    'Required (fingerprint, face or PIN every time)' => '必須（每次都要指紋、臉或 PIN）',
    'Preferred (allow a bare tap when the device cannot verify)' => '偏好（裝置沒辦法驗證時，允許只按一下）',
    'A passkey only stands in for a password plus a code when the device verifies who is holding it. Lower this only if some of your authenticators cannot.'
        => 'Passkey 要能取代「密碼＋驗證碼」，前提是裝置確認了拿著它的人是誰。除非你有些驗證器做不到，否則不要降低。',
    'This page is not served over HTTPS. Browsers refuse to create or use passkeys outside a secure context, so nothing here will work until Kanboard is reachable over HTTPS.'
        => '這個頁面不是走 HTTPS。瀏覽器不會在非安全環境下建立或使用 passkey，所以在 Kanboard 能用 HTTPS 連上之前，這裡的功能都不會動。',
);
