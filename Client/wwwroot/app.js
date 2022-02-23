class UserManager {
    #accessToken;
    #refreshToken;

    constructor({ clientId, scope }) {
        const cfg = {
            authority: 'https://localhost:5001/',
            client_id: clientId,
            redirect_uri: 'https://localhost:5003/?mode=default',
            response_type: 'code',
            scope: scope,
            post_logout_redirect_uri: 'https://localhost:5003/'
        };

        this.mng = new Oidc.UserManager(cfg);

        this.mng.events.addUserSignedIn(function () {
            console.log('user logged in');
            oidcLoginBtn.hidden = true;
            oidcLogoutBtn.hidden = false;
        });
        this.mng.events.addUserSignedOut(function () {
            console.log('user logged out');
            oidcLoginBtn.hidden = false;
            oidcLogoutBtn.hidden = true;
        });

    }

    getUser() {
        this.mng.getUser()
            .then(user => {
                if (user) {
                    console.log('user received', user)
                    oidcLoginBtn.hidden = true;
                    oidcLogoutBtn.hidden = false;

                    this.#accessToken = user.access_token;
                    this.#refreshToken = user.refresh_token;
                } else {
                    console.error('get user error');
                    oidcLoginBtn.hidden = false;
                    oidcLogoutBtn.hidden = true;
                }
            });
    }

    signInCallback() {
        return this.mng.signinRedirectCallback();
    }

    signIn() {
        this.mng.signinRedirect();
    }

    signOut() {
        this.mng.signoutRedirect();
    }

    doRequest(request) {
        const headers = new Headers(request.headers);
        headers.set('Authorization', 'Bearer ' + this.#accessToken);

        return fetch(new Request(request, { headers }));
    }

    refreshToken() {
        const details = {
            client_id: 'spa.client',
            grant_type: 'refresh_token',
            refresh_token: this.#refreshToken
        };
        const formBody = Object.keys(details).map(key => encodeURIComponent(key) + '=' + encodeURIComponent(details[key])).join('&');
        fetch('https://localhost:5001/connect/token', {
            method: 'post',
            headers: new Headers({
                'Content-Type': 'application/x-www-form-urlencoded'
            }),
            body: formBody
        })
            .then(resp => resp.ok ? resp.json() : `${resp.status}: ${resp.statusText}`)
            .then(res => {
                if (res.access_token) {
                    this.#accessToken = res.access_token;
                    this.#refreshToken = res.refresh_token;
                }

                log(res);
            });
    }

    exchangeToken(style) {
        fetch(`/delegate-token/${this.#accessToken}/${style}`)
            .then(resp => resp.ok ? resp.json() : `${resp.status}: ${resp.statusText}`)
            .then(res => log(res));
    }
}

class CibaManager {
    #accessToken;

    constructor(opts) {
        opts.loginWrap.hidden = false;
        opts.loginInp.value = '';
        opts.pollingWrap.hidden = true;
        opts.timer.innerText = '';
        opts.code.innerText = '';
        opts.state.innerText = '';
        opts.state.style.color = '';
        opts.logout.hidden = true;

        this.opts = opts;
    }

    generateBinding() {
        const partsCount = 2;
        const partSize = 8 / partsCount;
        let s = '';

        for (let parts = 0; parts < partsCount; parts++) {
            for (let i = 0; i < partSize; i++) {
                s += parseInt(Math.random() * 10);
            }
            if (parts + 1 < partsCount) {
                s += '-';
            }
        }

        return s;
    }

    signIn() {
        this.binding = this.generateBinding();

        fetch('/ciba', {
            method: 'post',
            headers: new Headers({
                'Content-Type': 'application/json'
            }),
            body: JSON.stringify({
                login: this.opts.loginInp.value,
                binding: this.binding
            })
        })
            .then(resp => resp.ok ? resp.json() : `${resp.status}:${resp.statusText}`)
            .then(res => {
                log(res);

                if (res.requestId) {
                    this.reqId = res.requestId;
                    this.expires = res.expires;
                    this.interval = res.interval * 1000;

                    this.startPollingTimer(500);
                    this.showPolling();

                    this.startAuthPolling();
                }
            });
    }
    signOut() {
        this.#accessToken = '';

        this.toggleLogin(false);
    }

    startPollingTimer(interval) {
        let seconds = this.expires;
        
        const tick = () => {
            seconds -= interval / 1000;

            if (seconds <= 0) {
                this.stopPollingTimer();
                return;
            }

            let label = '';
            let h = 0;
            if (seconds > 3600) {
                h = parseInt(seconds / 3600);
                label += `${h} hours `;
            }
            let m = 0;
            if (seconds > 60) {
                m = parseInt((seconds - h * 3600) / 60);
                label += `${m} minutes `;
            }

            const s = parseInt(seconds - h * 3600 - m * 60);
            label += `${s} seconds`;

            this.opts.timer.innerText = label;
        }

        tick();

        this.timer = setInterval(() => tick(), interval);
    }

    stopPollingTimer(text) {
        clearInterval(this.timer);
        this.opts.timer.innerText = text || 'Login attempt is expired. Try again';
    }
    showPolling() {
        this.opts.code.innerText = this.binding;
        this.opts.state.innerText = 'waiting for accept..';
        this.opts.state.style.color = '#ff9800';

        this.opts.code.innerText = this.binding;

        this.opts.pollingWrap.hidden = false;
    }
    hidePolling() {
        this.opts.pollingWrap.hidden = true;
        this.opts.timer.innerText = '';
        this.opts.code.innerText = '';
        this.opts.state.innerText = '';
        this.opts.state.style.color = '';
    }
    successPolling() {
        this.opts.state.innerText = 'Successed!';
        this.opts.state.style.color = '#4caf50';
        this.stopPollingTimer(' ');
    }
    errorPolling() {
        this.opts.state.innerText = 'Error';
        this.opts.state.style.color = '#f44336';
        this.stopPollingTimer(' ');
    }

    toggleLogin(state) {
        this.opts.loginWrap.hidden = !state;
        this.opts.logout.hidden = state;
    }

    gotoConfirm(id) {
        window.open('https://localhost:5001/ciba?id=' + id);
    }

    startAuthPolling() {
        setTimeout(() => this.getToken(), this.interval);
    }

    getToken() {
        fetch(`/ciba-token/${this.reqId}`)
            .then(resp => resp.ok ? resp.json() : `${resp.status}:${resp.statusText}`)
            .then(res => {
                if (!res.result && res.continueLoop) {
                    setTimeout(() => this.getToken(), this.interval);
                } else if (res.result) {
                    this.#accessToken = res.token;
                    log(res);
                    this.successPolling();
                    this.toggleLogin(true);
                } else {
                    log(res);
                    this.errorPolling();
                }
            });
    }

    doRequest(request) {
        const headers = new Headers(request.headers);
        headers.set('Authorization', 'Bearer ' + this.#accessToken);

        return fetch(new Request(request, { headers }));
    }
}

function log(data) {
    document.getElementById('result').innerText = JSON.stringify(data, null, 2);
}

document.getElementById('m2m').addEventListener('click', handleM2MClick);
document.getElementById('m2m-jwk').addEventListener('click', handleM2MJwkClick);
//oidc
const oidcLoginBtn = document.getElementById('oidc-login')
oidcLoginBtn.addEventListener('click', handleOidcLogin);
const oidcLogoutBtn = document.getElementById('oidc-logout');
oidcLogoutBtn.addEventListener('click', handleOidcLogout);
document.getElementById('oidc-api').addEventListener('click', handleOidcRequest);
document.getElementById('oidc-refresh').addEventListener('click', handleOidcTokenRefresh);
document.getElementById('oidc-exchange').addEventListener('click', handleOidcTokenExchange);
//ciba
const cibaLoginWrap = document.getElementById('ciba-login-wrap');
document.getElementById('ciba-login-btn').addEventListener('click', handleCibaLogin);
const cibaLoginInp = document.getElementById('ciba-login-inp');
const cibaPollingWrap = document.getElementById('ciba-polling');
const cibaTimer = document.getElementById('ciba-timer');
const cibaCode = document.getElementById('ciba-code');
const cibaLoginState = document.getElementById('ciba-login-state');
const cibaConfirmInp = document.getElementById('ciba-confirm-inp');
document.getElementById('ciba-confirm-btn').addEventListener('click', handleCibaConfirmClick);
const cibaLogout = document.getElementById('ciba-logout');
cibaLogout.addEventListener('click', handleCibaLogout);
document.getElementById('ciba-api').addEventListener('click', handleCibaRequest);
//oidc-ref
document.getElementById('oidc-ref-login').addEventListener('click', handleOidcRefLogin);
document.getElementById('oidc-ref-api').addEventListener('click', handleOidcRefRequest);


function handleM2MClick() {
    fetch('/m2m')
        .then(resp => resp.ok ? resp.json() : `${resp.status}:${resp.statusText}`)
        .then(res => log(res));
}
function handleM2MJwkClick() {
    fetch('/m2m-jwk')
        .then(resp => resp.ok ? resp.json() : `${resp.status}:${resp.statusText}`)
        .then(res => log(res));
}

const mng = new UserManager({
    clientId: 'spa.client',
    scope: 'openid scope3 offline_access'
});

function oidcGetUser() {
    mng.getUser();
}

function handleOidcLogin() {
    mng.signIn();
}
function handleOidcLogout() {
    mng.signOut();
}
function handleOidcRequest() {
    mng.doRequest(new Request('https://localhost:5002/weatherforecast'))
        .then(resp => resp.ok ? resp.json() : `${resp.status}: ${resp.statusText}`)
        .then(res => {
            log(res);
            console.log(res);
        });
}
function handleOidcTokenRefresh() {
    mng.refreshToken();
}
function handleOidcTokenExchange() {
    const radio = document.querySelector('input[name="token-exchange"]:checked');
    const style = radio.value;
    mng.exchangeToken(style);
}


const ciba = new CibaManager({
    loginWrap: cibaLoginWrap,
    loginInp: cibaLoginInp,
    logout: cibaLogout,
    pollingWrap: cibaPollingWrap,
    timer: cibaTimer,
    code: cibaCode,
    state: cibaLoginState
});

function handleCibaLogin() {
    ciba.signIn();
}
function handleCibaLogout() {
    ciba.logout();
}
function handleCibaRequest() {
    ciba.doRequest(new Request('https://localhost:5002/weatherforecast'))
        .then(resp => resp.ok ? resp.json() : `${resp.status}: ${resp.statusText}`)
        .then(res => {
            log(res);
            console.log(res);
        });
}
function handleCibaConfirmClick() {
    ciba.gotoConfirm(cibaConfirmInp.value);
}

const mngRef = new Oidc.UserManager({
    authority: 'https://localhost:5001/',
    client_id: 'spa.client.referenceToken',
    redirect_uri: 'https://localhost:5003/?mode=ref_token',
    response_type: 'code',
    scope: 'openid scope3',
    post_logout_redirect_uri: 'https://localhost:5003/'
});

function handleOidcRefLogin() {
    mngRef.signinRedirect();
}
function handleOidcRefRequest() {
    fetch('https://localhost:5002/weatherforecast', {
        headers: new Headers({
            'Authorization': 'Bearer ' + window.RefAccessToken
        })
    })
        .then(resp => resp.ok ? resp.json() : `${resp.status}: ${resp.statusText}`)
        .then(res => {
            log(res);
            console.log(res);
        });
}

const url = new URL(window.location);
if (url.searchParams.has('code')) {
    const mode = url.searchParams.get('mode');
    if (mode === 'default') {
        mng.signInCallback()
            .then(res => {
                console.log('retrieve token', res);
                oidcGetUser();
            });
    } else if (mode === 'ref_token') {
        mngRef.signinRedirectCallback()
            .then(res => {
                console.log('retrieve reference token', res);
                mngRef.getUser()
                    .then(user => {
                    if (user) {
                        console.log('user received', user)
                    
                        window.RefAccessToken = user.access_token;
                    } else {
                        console.error('get user error');
                    }
                });
            });
    }

    url.search = '';
    window.history.replaceState(null, document.title, url);
} else {
    oidcGetUser();
    mngRef.getUser();
}