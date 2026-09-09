# Passkey — sign in to Kanboard with a passkey

**English** · [繁體中文](README.zh-TW.md)

Adds [WebAuthn](https://www.w3.org/TR/webauthn-2/) passkeys to Kanboard, in two
places:

- **Sign in with no password at all.** A button on the login form runs a
  usernameless ceremony against a discoverable credential — Touch ID, Face ID,
  Windows Hello, a passkey synced through iCloud Keychain or Google Password
  Manager, 1Password, Bitwarden, a YubiKey. Nothing is typed and no username is
  sent.
- **A passkey as the second factor**, chosen per user, next to the one-time
  code Kanboard already ships. Everyone who prefers Google Authenticator keeps
  exactly what they had.

No core file is modified, and the whole WebAuthn implementation is in this
plugin: no Composer install, no vendor directory, nothing to run after
unpacking. It needs PHP 8.1 with `ext-openssl`, which Kanboard already
requires.

---

## Install

A Kanboard plugin is a directory under `plugins/`, and the directory name is
the plugin's namespace — so this one has to land at `plugins/Passkey`,
whichever way it gets there.

**From git:**

```
cd /path/to/kanboard/plugins
git clone https://github.com/heykaiyi/kanboard-passkey.git Passkey
```

**From a zip** — for a host with no shell:

```
unzip Passkey-x.y.z.zip -d /path/to/kanboard/plugins
```

The archive already contains the `Passkey/` directory, so it unpacks straight
into `plugins/`. The same file works in **Settings → Plugins → Install from
URL** on an instance with `PLUGIN_INSTALLER` enabled.

The credential table is created on the first request after the plugin appears;
there is no install step.

### One prerequisite: HTTPS

Browsers only expose WebAuthn in a secure context. Kanboard has to be reachable
over **HTTPS** — or at `localhost`, which browsers treat as secure — or the
buttons will simply do nothing. **Settings → Passkeys** says so at the top of
the page when it detects this.

---

## Using it

### Register a passkey

**Your profile → Passkeys** (`/user/<id>/passkeys`). Give it a name, press
**Add a passkey**, and confirm with whatever your device asks for. The list
shows where each passkey is kept, whether it syncs across your devices, and
when it was last used.

Passkeys are personal. An administrator can see that a user exists but cannot
add or remove that user's passkeys.

### Sign in with it

The login page grows a **Sign in with a passkey** button as soon as one passkey
exists anywhere on the installation. On browsers that support conditional
mediation, the passkey is also offered straight from the username field's
autofill list, so the common case needs no button at all.

A passkey unlocked with a fingerprint, face or PIN is already two factors —
something you have and something you are — so this path skips the second-factor
prompt, exactly as Kanboard does for a "remember me" session. If **user
verification** is lowered to *preferred* in the settings, that no longer holds
and the second factor runs as usual.

### Use it as the second factor

On the same page, tick **Ask for a passkey as my second factor** and save. From
then on a password login is followed by a passkey prompt instead of the six
digit code.

Switching to a passkey clears the TOTP secret, so the entry in the
authenticator app stops working — the page says so before you save. Switching
back is **Set up a one-time code instead**, which is Kanboard's own screen,
untouched. Removing your last passkey turns the second factor off rather than
locking you out.

#### When it is not asked for

Kanboard exempts one way in from the second factor — a "remember me" session —
by naming it. Once the second factor is a passkey, two more belong on that
list, and neither is asked:

- **Signing in with a passkey.** One unlocked with a fingerprint, face or PIN
  is already two factors; a second passkey on top proves nothing new. Lower
  **user verification** to *preferred* and it proves possession only, so the
  prompt comes back.
- **Signing in through Google, or any other OAuth provider.** That provider has
  already authenticated the person against an account carrying its own second
  factor. The test is the provider's interface rather than its name, so every
  OAuth plugin counts and none has to be listed here.

Both apply only to users whose second factor is a passkey. Anyone on a one-time
code stays on Kanboard's own path — installing this plugin is not a reason for
their login to start behaving differently.

---

## Settings

**Settings → Passkeys**, administrators only.

| Setting | What it does |
| --- | --- |
| Allow signing in with a passkey instead of a password | Turns the login button and its endpoints off. Passkeys still work as a second factor. |
| Relying party ID | The domain passkeys are bound to. Defaults to the host of the application URL. |
| Display name | What the browser shows and the password manager stores. Defaults to the application title. |
| Allowed origins | Comma separated. Defaults to the origin of the application URL. Set it by hand behind a proxy that rewrites the host. |
| User verification | *Required* (default) demands a fingerprint, face or PIN every time. *Preferred* allows a bare tap on authenticators that cannot verify. |

### About the relying party ID

**A passkey is bound to this value for life.** Change it and every passkey
already registered stops working — the browser will not even offer them.
Decide it before users start enrolling, and leave it alone afterwards.

The default is the host of **Settings → Application → Application URL**, which
is the value an administrator already had to get right for email links. Only
set it explicitly if that is wrong or empty.

---

## How it works

Kanboard's authentication has a shape this plugin fits into rather than works
around.

**Signing in** goes through the authentication manager like any other provider.
`PasskeyLoginController` checks the assertion, then hands over to a registered
pre-authentication provider, so the login is written to the last-login table,
the lockout counter is reset, and every `auth.success` listener fires exactly as
it would for a password. The provider is inert on every other request.

**The second factor** is harder, because Kanboard keeps exactly one
post-authentication provider — `getPostAuthenticationProvider()` pops the last
one registered — and `PostAuthenticationMiddleware` will not route anywhere but
`TwoFactorController` while a second factor is pending. A plugin that simply
registered its own provider would take two-factor authentication away from
everyone still using a code, and a plugin with its own prompt page could never
reach it.

So `PasskeyTwoFactorProvider` stands in front of the built-in `TotpAuth` and
hands every call straight through unless the signed-in user has actually chosen
a passkey, and the assertion travels in the same `code` field the numeric form
posts. The one core template replaced is `twofactor/check`, and the replacement
renders Kanboard's own markup, verbatim, for anyone on a one-time code.

**The WebAuthn implementation** is `WebAuthn/`: a CBOR decoder, a COSE key
reader that builds a SubjectPublicKeyInfo by hand, an authenticator data
parser, and the two ceremonies. ES256, RS256 and Ed25519 are supported, which
covers every shipping authenticator. The DER it produces is byte-identical to
what OpenSSL emits for the same key.

Attestation is requested as `none` and is not verified. Outside an enterprise
deployment that is the right default: verifying it would mean shipping and
maintaining the FIDO metadata service, and it only ever answers "which brand of
authenticator is this", never "is this the right user". The credential public
key comes out of the same structure either way.

### What is checked

On every assertion: the challenge matches the one this session was issued, the
origin is on the allowed list, the ceremony was not run inside someone else's
frame, the relying party hash matches, the user was present, the user was
verified when that is required, the signature verifies against the stored public
key, and the signature counter moved forward. Synced passkeys report a counter
of zero and are exempt, as the specification allows.

For a second factor, the credential must additionally belong to the
half-authenticated user; for a sign-in, the user handle the authenticator
returns must match the one stored at enrolment.

Every endpoint is CSRF-protected, including the JSON ones, and a failed sign-in
feeds Kanboard's own IP lockout counter.

### What it stores

One table, `passkey_credentials`: the credential id, its public key, the
algorithm, the signature counter, the AAGUID, the transports, a name and two
timestamps. None of it is secret — losing the table means users enrol again, not
that anyone can sign in as them.

Two rows in `user_has_metadata` per user: whether they chose a passkey as their
second factor, and a random 32-byte user handle. The handle is deliberately not
the Kanboard user id, which would put an internal identifier into a credential
anyone can read off the device.

---

## Tests

Two suites, both plain PHP — no PHPUnit, no Composer, nothing to install.

```
php Test/run.php          # the WebAuthn layer, standalone
php Test/integration.php  # the second factor, inside a real Kanboard
```

The first needs nothing but PHP: it builds keys with OpenSSL and libsodium and
runs both ceremonies against them, so the signatures, the CBOR and the DER are
the ones a browser would send rather than fixtures that agree with the parser
by construction. It checks the rejections as well as the happy path — a
challenge from another session, an origin that is not on the list, a ceremony
run in an iframe, a passkey for a different site, a tampered signature, a
counter that did not move, a registration replayed into the sign-in endpoint.

The second has to run from inside an installation, because the second factor is
where this plugin meets Kanboard's own. It creates a throwaway user, enrols a
virtual passkey for them, drives the provider the way `TwoFactorController`
does, checks that a user still on a one-time code is handed to `TotpAuth`
untouched, and removes everything it made. It changes no setting and touches
nothing else in the installation.

## Compatibility

- Kanboard **1.2.0** and later
- PHP **8.1**+ with `ext-openssl`; `ext-sodium` only for Ed25519 authenticators
- SQLite, MySQL and PostgreSQL
- Any browser with WebAuthn level 2 — Safari 16+, Chrome 108+, Firefox 122+,
  Edge 108+

---

## License

MIT
