/*!
 * Passkeys for Kanboard.
 *
 * Three entry points, one ceremony each:
 *
 *   - the login page      : a usernameless get(), which signs the user in
 *   - the passkey page    : a create(), which enrols a new credential
 *   - the two-factor page : a get() restricted to that user's credentials
 *
 * WebAuthn speaks ArrayBuffers and Kanboard speaks JSON, so everything the
 * server sends is base64url and is widened here, and everything the browser
 * produces is narrowed back the same way. `PublicKeyCredential.toJSON()` would
 * do half of this, but it is recent enough that doing it by hand keeps the
 * plugin working on browsers that have passkeys but not that method.
 *
 * This is a file rather than an inline script because Kanboard serves
 * `default-src 'self'`, which refuses inline scripts.
 */
(function () {
    'use strict';

    function toBuffer(value) {
        var normalised = String(value).replace(/-/g, '+').replace(/_/g, '/');
        var padded = normalised + '==='.slice((normalised.length + 3) % 4);
        var binary = window.atob(padded);
        var bytes = new Uint8Array(binary.length);

        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes.buffer;
    }

    function toBase64Url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';

        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function descriptors(list) {
        return (list || []).map(function (item) {
            var descriptor = {type: item.type, id: toBuffer(item.id)};

            if (item.transports) {
                descriptor.transports = item.transports;
            }

            return descriptor;
        });
    }

    function creationOptions(options) {
        options.challenge = toBuffer(options.challenge);
        options.user.id = toBuffer(options.user.id);
        options.excludeCredentials = descriptors(options.excludeCredentials);

        return options;
    }

    function requestOptions(options) {
        options.challenge = toBuffer(options.challenge);
        options.allowCredentials = descriptors(options.allowCredentials);

        return options;
    }

    function serialize(credential) {
        var response = credential.response;
        var json = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: toBase64Url(response.clientDataJSON)
            }
        };

        if (response.attestationObject) {
            json.response.attestationObject = toBase64Url(response.attestationObject);

            if (typeof response.getTransports === 'function') {
                json.response.transports = response.getTransports();
            }
        } else {
            json.response.authenticatorData = toBase64Url(response.authenticatorData);
            json.response.signature = toBase64Url(response.signature);
            json.response.userHandle = response.userHandle ? toBase64Url(response.userHandle) : null;
        }

        return json;
    }

    function post(url, payload) {
        return window.fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
            body: JSON.stringify(payload)
        }).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (body) {
                if (!response.ok) {
                    throw new Error(body.error || 'HTTP ' + response.status);
                }

                return body;
            });
        });
    }

    function messages(container) {
        try {
            return JSON.parse(container.getAttribute('data-messages') || '{}');
        } catch (e) {
            return {};
        }
    }

    /* A DOMException from the authenticator says nothing a user can act on;
     * these three are the ones that actually happen. */
    function describe(error, container) {
        var text = messages(container);

        if (error && error.name === 'NotAllowedError') {
            return text.cancelled || 'The request was cancelled or timed out.';
        }

        if (error && error.name === 'InvalidStateError') {
            return text.duplicate || 'This device already holds a passkey for this account.';
        }

        return (error && error.message) || text.failed || 'Something went wrong.';
    }

    /**
     * The login page's error line is lifted out of its container along with
     * the button, so it is remembered rather than looked up by descent.
     */
    function errorLine(container) {
        return container.passkeyErrorLine || container.querySelector('.passkey-error');
    }

    function showError(container, message) {
        var note = errorLine(container);

        if (note !== null) {
            note.textContent = message;
            note.hidden = false;
        }
    }

    function clearError(container) {
        var note = errorLine(container);

        if (note !== null) {
            note.hidden = true;
        }
    }

    function busy(button, container, isBusy) {
        if (button.tagName === 'A') {
            // Links have no disabled state; this is the pair that means it.
            button.setAttribute('aria-disabled', isBusy ? 'true' : 'false');
            button.classList.toggle('is-busy', isBusy);
        } else {
            button.disabled = isBusy;
        }

        if (isBusy) {
            // innerHTML, so the icon comes back with the label.
            button.setAttribute('data-label', button.innerHTML);
            button.textContent = messages(container).working || 'Waiting for your passkey...';
        } else if (button.hasAttribute('data-label')) {
            button.innerHTML = button.getAttribute('data-label');
        }
    }

    function token(container) {
        return container.getAttribute('data-csrf') || '';
    }

    function supported() {
        return typeof window.PublicKeyCredential !== 'undefined' &&
            typeof navigator.credentials !== 'undefined' &&
            typeof navigator.credentials.create === 'function';
    }

    // -- signing in ----------------------------------------------------------

    var conditionalAbort = null;

    /* The destination travels with the request for a challenge, so it is
     * settled before the passkey sheet opens and nothing that happens while
     * it is open can change where the sign-in lands. */
    function signInOptionsPayload(container, csrf) {
        return {
            csrf_token: csrf,
            redirect: container.getAttribute('data-redirect') || ''
        };
    }

    function signIn(container, button) {
        var csrf = token(container);

        // A conditional request may already be listening for the same
        // credential; two overlapping ceremonies is an error in every browser.
        if (conditionalAbort !== null) {
            conditionalAbort.abort();
            conditionalAbort = null;
        }

        clearError(container);
        busy(button, container, true);

        post(container.getAttribute('data-options-url'), signInOptionsPayload(container, csrf))
            .then(function (body) {
                return navigator.credentials.get({publicKey: requestOptions(body.publicKey)});
            })
            .then(function (credential) {
                return post(container.getAttribute('data-verify-url'), {
                    csrf_token: csrf,
                    credential: serialize(credential)
                });
            })
            .then(function (body) {
                window.location.href = body.redirect;
            })
            .catch(function (error) {
                busy(button, container, false);
                showError(container, describe(error, container));
            });
    }

    /**
     * Offer the passkey inside the username field's autofill list, so the
     * common case needs no button at all. Browsers without it simply never
     * resolve isConditionalMediationAvailable(), and the button remains.
     */
    function offerInAutofill(container) {
        if (typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') {
            return;
        }

        window.PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
            if (!available) {
                return;
            }

            var username = document.querySelector('.form-login form input[name="username"]');

            if (username !== null) {
                username.setAttribute('autocomplete', 'username webauthn');
            }

            var csrf = token(container);
            conditionalAbort = new AbortController();

            post(container.getAttribute('data-options-url'), signInOptionsPayload(container, csrf))
                .then(function (body) {
                    return navigator.credentials.get({
                        publicKey: requestOptions(body.publicKey),
                        mediation: 'conditional',
                        signal: conditionalAbort.signal
                    });
                })
                .then(function (credential) {
                    return post(container.getAttribute('data-verify-url'), {
                        csrf_token: csrf,
                        credential: serialize(credential)
                    });
                })
                .then(function (body) {
                    window.location.href = body.redirect;
                })
                .catch(function () {
                    // Aborted, dismissed, or unsupported after all: the button
                    // is still there and says what went wrong when pressed.
                });
        }).catch(function () {});
    }

    // -- enrolling -----------------------------------------------------------

    function register(container, button) {
        var csrf = token(container);
        var nameField = container.querySelector('.js-passkey-name');
        var name = nameField === null ? '' : nameField.value;

        clearError(container);
        busy(button, container, true);

        post(container.getAttribute('data-options-url'), {csrf_token: csrf})
            .then(function (body) {
                return navigator.credentials.create({publicKey: creationOptions(body.publicKey)});
            })
            .then(function (credential) {
                return post(container.getAttribute('data-verify-url'), {
                    csrf_token: csrf,
                    name: name,
                    credential: serialize(credential)
                });
            })
            .then(function (body) {
                window.location.href = body.redirect;
            })
            .catch(function (error) {
                busy(button, container, false);
                showError(container, describe(error, container));
            });
    }

    // -- second factor -------------------------------------------------------

    /**
     * The options are rendered into the page rather than fetched, because the
     * challenge was already issued server-side when the prompt was built. The
     * assertion goes into the form's `code` field and the form is posted to
     * core's TwoFactorController, so the check itself stays in core.
     */
    function secondFactor(form, button) {
        var options;

        try {
            options = JSON.parse(form.getAttribute('data-options'));
        } catch (e) {
            showError(form, describe(e, form));
            return;
        }

        clearError(form);
        busy(button, form, true);

        navigator.credentials.get({publicKey: requestOptions(options)})
            .then(function (credential) {
                form.querySelector('.js-passkey-2fa-code').value = JSON.stringify(serialize(credential));
                submitSecondFactor(form);
            })
            .catch(function (error) {
                busy(button, form, false);
                showError(form, describe(error, form));
            });
    }

    /**
     * Post the answer, then go where the user was heading.
     *
     * TwoFactorController::check() always redirects to the dashboard on
     * success, and the page the user asked for was dropped on the way here,
     * so a plain submit would land on the dashboard every time. Posted as an
     * XHR instead, core answers with the redirect in X-Ajax-Redirect rather
     * than following it; a redirect back to the prompt means the check
     * failed, and anything else means it passed and the destination the page
     * was given up front applies.
     */
    function submitSecondFactor(form) {
        var target = form.getAttribute('data-redirect') || '';
        var retry = form.getAttribute('data-retry-url') || '';

        window.fetch(form.action, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'},
            body: new FormData(form)
        }).then(function (response) {
            var next = response.headers.get('X-Ajax-Redirect') || '';

            if (!response.ok || next === '') {
                throw new Error('HTTP ' + response.status);
            }

            if (next !== retry && target !== '') {
                next = target;
            }

            window.location.href = next;
        }).catch(function () {
            // Whatever went wrong, the server still has the final say on the
            // code page; reload it rather than leave the user on a spinner.
            window.location.href = retry || window.location.href;
        });
    }

    // -- wiring --------------------------------------------------------------

    function start() {
        var signInBox = document.querySelector('.passkey-signin');
        var registerBox = document.querySelector('.passkey-register');
        var twoFactorForm = document.querySelector('.js-passkey-2fa-form');

        if (registerBox !== null && !supported()) {
            registerBox.querySelector('.js-passkey-register').disabled = true;
            registerBox.querySelector('.passkey-unsupported').hidden = false;
        }

        if (signInBox !== null) {
            if (!supported()) {
                signInBox.parentNode.removeChild(signInBox);
            } else {
                var signInButton = signInBox.querySelector('.js-passkey-signin');

                move(signInBox);

                signInButton.addEventListener('click', function (event) {
                    // It is a link so the theme's social row styles it; it has
                    // nowhere to go, so the jump to the top of the page that
                    // href="#" would otherwise cause is stopped here.
                    event.preventDefault();

                    if (this.getAttribute('aria-disabled') === 'true') {
                        return;
                    }

                    signIn(signInBox, this);
                });

                offerInAutofill(signInBox);
            }
        }

        if (registerBox !== null && supported()) {
            registerBox.querySelector('.js-passkey-register').addEventListener('click', function () {
                register(registerBox, this);
            });
        }

        if (twoFactorForm !== null && supported()) {
            var trigger = twoFactorForm.querySelector('.js-passkey-2fa');

            trigger.addEventListener('click', function () {
                secondFactor(twoFactorForm, this);
            });

            // The user came here to do exactly one thing.
            trigger.focus();
        }
    }

    /**
     * Put the button where the theme expects a social sign-in row to be.
     *
     * The row is styled as `.form-login > ul`, a direct child, and the hook
     * that renders this one wraps it in a div — so the list is lifted out.
     * When another auth plugin has already rendered its own list, ours is
     * folded into it instead: those rules draw a labelled rule above the
     * first list, and two of them would read as two separate offers rather
     * than a choice between three ways in.
     */
    function move(container) {
        var page = document.querySelector('.form-login');
        var list = container.querySelector('.js-passkey-list');

        if (page === null || list === null) {
            return;
        }

        var lists = page.querySelectorAll(':scope > ul');
        var existing = lists.length > 0 ? lists[0] : null;

        if (existing !== null) {
            while (list.firstElementChild !== null) {
                existing.appendChild(list.firstElementChild);
            }

            list.parentNode.removeChild(list);
        } else {
            page.appendChild(list);
        }

        // The error line follows whatever the list ended up being, so it reads
        // as belonging to the button rather than to the form above it.
        var anchor = existing !== null ? existing : list;
        var note = container.querySelector('.passkey-error');

        if (note !== null && anchor.parentNode !== null) {
            anchor.parentNode.insertBefore(note, anchor.nextSibling);
            container.passkeyErrorLine = note;
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
