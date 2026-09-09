# Passkey — 用 passkey 登入 Kanboard

[English](README.md) · **繁體中文**

幫 Kanboard 加上 [WebAuthn](https://www.w3.org/TR/webauthn-2/) passkey，用在兩個地方：

- **完全不用密碼登入。** 登入頁多一顆按鈕，跑的是不需要帳號的 discoverable
  credential 流程 —— Touch ID、Face ID、Windows Hello、存在 iCloud 鑰匙圈或
  Google 密碼管理工具裡同步的 passkey、1Password、Bitwarden、YubiKey 都行。
  什麼都不用打，連帳號都不會送出去。
- **拿 passkey 當第二道驗證**，每個人自己選，跟 Kanboard 原本的一次性驗證碼並存。
  習慣用 Google Authenticator 的人完全不受影響。

沒有動到任何核心檔案，WebAuthn 的實作全部在這個外掛裡：不用 Composer、沒有
vendor 目錄、解壓完就能用。需求是 PHP 8.1 加 `ext-openssl`，而這本來就是
Kanboard 的需求。

---

## 安裝

Kanboard 外掛就是 `plugins/` 底下的一個目錄，目錄名稱就是它的 namespace，
所以不管用什麼方式裝，它都必須落在 `plugins/Passkey`。

**用 git：**

```
cd /path/to/kanboard/plugins
git clone https://github.com/heykaiyi/kanboard-passkey.git Passkey
```

**用 zip** —— 給沒有 shell 的主機：

```
unzip Passkey-x.y.z.zip -d /path/to/kanboard/plugins
```

壓縮檔裡面已經包了 `Passkey/` 這層目錄，直接解到 `plugins/` 就對了。同一個檔案
也可以丟進 **設定 → 外掛 → 從網址安裝**（要有開 `PLUGIN_INSTALLER`）。

外掛出現後的第一個 request 就會自己建好資料表，沒有額外的安裝步驟。

### 一個前提：HTTPS

瀏覽器只在安全環境下開放 WebAuthn。Kanboard 必須用 **HTTPS** 連得到 ——
或是在 `localhost`，瀏覽器把它當安全環境 —— 否則那些按鈕按了不會有任何反應。
**設定 → Passkey** 偵測到這件事的時候會在頁面最上面講。

---

## 怎麼用

### 註冊一把 passkey

**個人資料 → Passkey**（`/user/<id>/passkeys`）。取個名字，按 **新增 passkey**，
然後照裝置問你的方式確認。清單會顯示每把 passkey 存在哪裡、有沒有跨裝置同步、
上次什麼時候用的。

Passkey 是個人的東西。管理者看得到有這個使用者，但沒辦法幫別人新增或移除
passkey。

### 用它登入

只要這台 Kanboard 上任何一個人有註冊過 passkey，登入頁就會長出
**用 passkey 登入** 按鈕。瀏覽器支援 conditional mediation 的話，passkey
也會直接出現在帳號欄的自動填入清單裡，常見情況連按鈕都不用碰。

用指紋、臉或 PIN 解鎖的 passkey 本身就是兩個因素 —— 你有的東西加上你是誰 ——
所以走這條路會跳過第二道驗證，跟 Kanboard 對「記住我」的處理一樣。如果在設定裡
把 **使用者驗證** 降成「偏好」，這個前提就不成立了，第二道驗證會照常跑。

### 拿它當第二道驗證

同一頁勾 **第二道驗證改用 passkey** 然後儲存。之後用密碼登入完，問的就不是
六位數驗證碼，而是你的 passkey。

改用 passkey 會清掉 TOTP 密鑰，所以驗證器 App 裡那一筆會失效 —— 頁面在你按下
儲存之前就會講。想換回去就按 **改用一次性驗證碼**，那是 Kanboard 自己的畫面，
沒有被動過。把最後一把 passkey 移除的時候，第二道驗證會跟著關掉，不會把你鎖在外面。

#### 什麼時候不會問

Kanboard 自己有一個豁免，就是「記住我」的 session，寫死在核心裡。第二道驗證改成
passkey 之後，還有兩種進來的方式也該在那張名單上，這兩種都不會再問一次：

- **用 passkey 登入。** 用指紋、臉或 PIN 解開的 passkey 本來就是兩個因素，再要一把
  也證明不了新東西。把**使用者驗證**降成 *preferred*，它就只證明「你有這台裝置」，
  那時候就會照問。
- **用 Google 或其他 OAuth 登入。** 那邊已經拿一個本身就有第二道驗證的帳號認過人了。
  判斷是看 provider 實作的介面而不是名字，所以任何 OAuth 外掛都算，不用一個一個列。

兩個豁免都只對「第二道驗證是 passkey」的人生效。還在用一次性驗證碼的人走的是
Kanboard 原本的路 —— 裝了這個外掛不該變成他們登入行為改變的理由。

---

## 設定

**設定 → Passkey**，只有管理者看得到。

| 設定 | 作用 |
| --- | --- |
| 允許用 passkey 取代密碼登入 | 關掉登入按鈕跟對應的端點。passkey 仍然可以當第二道驗證。 |
| Relying party ID | passkey 綁定的網域。預設取應用程式網址的主機名稱。 |
| 顯示名稱 | 瀏覽器會顯示、密碼管理工具會存下來的名稱。預設取應用程式標題。 |
| 允許的來源 | 逗號分隔。預設從應用程式網址推導。放在會改寫主機名稱的反向代理後面時要自己填。 |
| 使用者驗證 | 「必須」（預設）代表每次都要指紋、臉或 PIN。「偏好」允許沒辦法驗證的認證器只按一下。 |

### 關於 relying party ID

**passkey 一旦綁上這個值就是一輩子。** 改掉它，已經註冊的 passkey 全部作廢 ——
瀏覽器連提都不會提。在大家開始註冊之前就決定好，之後不要再動。

預設值取自 **設定 → 應用程式 → 應用程式網址** 的主機名稱，那本來就是管理者為了
讓信件連結正確而必須填對的欄位。只有在那個值是錯的或空的時候，才需要自己指定。

---

## 運作方式

Kanboard 的驗證流程有它自己的形狀，這個外掛是順著做，不是繞過去。

**登入** 走的是驗證管理器，跟其他 provider 一樣。`PasskeyLoginController`
驗完 assertion 之後交給註冊好的 pre-authentication provider，所以登入紀錄會寫進
last-login 表、鎖定計數器會歸零、每個 `auth.success` 監聽器都會照跑，跟密碼登入
一模一樣。其他 request 這個 provider 都是不動作的。

**第二道驗證** 比較麻煩，因為 Kanboard 只留一個 post-authentication provider ——
`getPostAuthenticationProvider()` 取的是最後註冊的那一個 —— 而且第二道驗證還沒過
的時候，`PostAuthenticationMiddleware` 除了 `TwoFactorController` 哪裡都不讓你去。
外掛如果只是直接註冊自己的 provider，等於把雙重驗證從所有還在用驗證碼的人手上
拿走；如果自己開一頁提示畫面，那頁根本走不到。

所以 `PasskeyTwoFactorProvider` 站在內建的 `TotpAuth` 前面，除非這個使用者真的
選了 passkey，否則每個呼叫都原封不動轉給它；assertion 則是塞在數字表單原本用的
`code` 欄位送出去。唯一被覆寫的核心樣板是 `twofactor/check`，而且對還在用驗證碼
的人來說，它渲染的是 Kanboard 自己的原始標記，一字不差。

**WebAuthn 的實作** 在 `WebAuthn/`：一個 CBOR 解碼器、一個手工組出
SubjectPublicKeyInfo 的 COSE key 讀取器、authenticator data 解析、以及兩套流程。
支援 ES256、RS256 跟 Ed25519，涵蓋目前市面上所有的認證器。同一把金鑰產出的 DER
跟 OpenSSL 自己吐的完全一樣。

Attestation 要的是 `none`，而且不驗證。在非企業部署下這是對的預設值：要驗就得
接上並持續維護 FIDO metadata service，而它回答的永遠只是「這是哪個牌子的認證器」，
不是「這是不是本人」。不管驗不驗，credential 公鑰都是從同一份結構裡拿出來的。

### 會檢查什麼

每一次 assertion：challenge 跟這個 session 發出去的那份相符、origin 在允許清單上、
流程不是在別人的 iframe 裡跑的、relying party 雜湊相符、使用者在場、需要的時候
使用者有被驗證、簽章用存下來的公鑰驗得過、簽章計數器有往前走。跨裝置同步的 passkey
計數器固定回報 0，規格允許，所以豁免。

當第二道驗證時，這把 credential 還必須屬於那個驗證到一半的使用者；當登入用時，
認證器回傳的 user handle 必須跟註冊時存下來的相符。

每個端點都有 CSRF 保護，JSON 的也有；登入失敗會餵給 Kanboard 自己的 IP 鎖定計數器。

### 會存什麼

一張表 `passkey_credentials`：credential id、公鑰、演算法、簽章計數器、AAGUID、
transports、名字跟兩個時間戳。裡面沒有任何機密 —— 這張表掉了，代表大家要重新註冊，
不代表誰可以冒充你登入。

每個使用者在 `user_has_metadata` 有兩列：他有沒有選 passkey 當第二道驗證，以及一組
隨機 32 bytes 的 user handle。刻意不用 Kanboard 的 user id，不然等於把內部識別碼
寫進一份任何人都能從裝置上讀出來的 credential 裡。

---

## 測試

兩組測試，都是純 PHP，不用 PHPUnit、不用 Composer、沒東西要先裝。

```
php Test/run.php          # WebAuthn 那層，可以單獨跑
php Test/integration.php  # 第二道驗證，要在 Kanboard 裡面跑
```

第一組只要有 PHP 就能跑：它用 OpenSSL 跟 libsodium 產金鑰，再拿真的金鑰去跑兩
個 ceremony，所以簽章、CBOR、DER 都是瀏覽器真的會送的東西，不是那種剛好跟
parser 對得起來的假資料。該擋的也都測了——別的 session 的 challenge、不在清單
上的 origin、在 iframe 裡跑的 ceremony、屬於別站的 passkey、被動過的簽章、沒往
前走的計數器、把註冊回應拿去登入端點重放。

第二組要在安裝好的環境裡跑，因為第二道驗證正是這個外掛跟 Kanboard 原本機制交界
的地方。它會開一個用完就刪的使用者、幫他註冊一把虛擬 passkey、照
`TwoFactorController` 的順序去驅動 provider，確認還在用一次性密碼的人會原封不動
交給 `TotpAuth`，最後把自己造的東西都刪掉。不會改任何設定，也不會動到安裝裡的其
他東西。

## 相容性

- Kanboard **1.2.0** 以上
- PHP **8.1**+ 加 `ext-openssl`；`ext-sodium` 只有 Ed25519 認證器才需要
- SQLite、MySQL、PostgreSQL
- 任何支援 WebAuthn level 2 的瀏覽器 —— Safari 16+、Chrome 108+、Firefox 122+、
  Edge 108+

---

## 授權

MIT
