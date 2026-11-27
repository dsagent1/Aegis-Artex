"""Generic, env-configured session factory so the relay (and any mode) can AUTHENTICATE to the target
without hardcoding client creds in the engine. Fixes relay F1: exploitgym/redteam built the vectors ctx
without session_for_role, so resumed stateful footholds ran unauthenticated (and got falsely refuted).

STEP 1 / B0 (corpus+chaining roadmap): this is now a ROBUST session manager, not a one-shot login. It
is the board-locked #1 enabler -- an unauthenticated scan sees ~10% of a real app's surface, so every
later catalog vector (nuclei/MSF) is only as good as our ability to HOLD an authenticated session. The
returned session, in addition to the cookie jar:
  * captures a BEARER/JWT token from the login response and sets it as the Authorization header;
  * captures a CSRF/XSRF token (cookie or login-body) and injects it as a header on unsafe verbs;
  * RE-AUTHENTICATES automatically on session expiry (401/403 or a redirect to a login page) and
    retries the original request ONCE -- so a long hunt doesn't silently start failing after the
    session times out.
All of this is transparent to callers: it is still `session_for_role(role) -> requests.Session`.

Config via env (point at the mirror on the box, NOT in code -- same doctrine as AEGIS_DB_USER etc.):
  AEGIS_ROLE_MAP         JSON {role: identity}, e.g. {"owner":"Alex Morgan","finance":"Fiona Clarke",...}
  AEGIS_LOGIN_URL        login endpoint (default {base}/api/auth/login)
  AEGIS_LOGIN_PIN        shared PIN (default AEGIS_TEST_PIN, else 000000)
  AEGIS_LOGIN_ID_FIELD   login body field for the identity (default "name")
  AEGIS_LOGIN_PIN_FIELD  login body field for the PIN (default "pin")
  AEGIS_LOGIN_TOKEN_FIELDS  CSV of JSON fields to read a bearer token from the login response
                            (default token,access_token,accessToken,jwt,id_token,accessTokenJwt)
  AEGIS_AUTH_HEADER      header to carry the bearer token (default Authorization)
  AEGIS_AUTH_SCHEME      scheme prefix for the token (default "Bearer"; "" for a raw token)
  AEGIS_CSRF_COOKIE      CSV of CSRF cookie names to mirror into a header
                            (default XSRF-TOKEN,csrf-token,_csrf,csrfToken,CSRF-TOKEN)
  AEGIS_CSRF_HEADER      header to send the CSRF value in (default: auto -- X-XSRF-TOKEN for an
                            XSRF-TOKEN cookie, else X-CSRF-Token)
  AEGIS_SESSION_REAUTH   "0" disables automatic re-auth-on-expiry (default on)

from_env(base) -> session_for_role(role)->requests.Session (cached), or None if no AEGIS_ROLE_MAP
(offline-safe: no map -> no factory -> modes behave exactly as before). An unknown/anon role gets an
UNAUTHENTICATED session (never a silent fallback to a privileged identity)."""
import os, json

_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def _csv(name, default):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def _dig(obj, keys):
    """Find the first of `keys` in a (possibly nested under data/result) JSON object -> value or None."""
    if not isinstance(obj, dict):
        return None
    for k in keys:
        if obj.get(k) not in (None, ""):
            return obj[k]
    for wrap in ("data", "result", "auth", "session", "authentication", "tokens"):
        if isinstance(obj.get(wrap), dict):
            v = _dig(obj[wrap], keys)
            if v is not None:
                return v
    return None


def from_env(base):
    try:
        role_map = json.loads(os.environ.get("AEGIS_ROLE_MAP", "") or "{}")
    except Exception:
        role_map = {}
    # AEGIS_HOST_HEADER: force a Host header on every request. Lets the hunt reach an origin that vhosts
    # on Host (hit the origin IP directly with Host: chikov.com to bypass a CF WAF / wrong default vhost),
    # so surface discovery reads the REAL app instead of a 403/other-vhost -> no more phantom surfaces.
    host_hdr = (os.environ.get("AEGIS_HOST_HEADER") or "").strip() or None
    if not isinstance(role_map, dict) or not role_map:
        # No role map: still hand back a Host-override factory if AEGIS_HOST_HEADER is set; else None.
        if host_hdr:
            import requests as _rq
            try: _rq.packages.urllib3.disable_warnings()
            except Exception: pass
            def _host_factory(role=None):
                s = _rq.Session(); s.verify = False
                s.headers["Host"] = host_hdr
                s.headers.setdefault("User-Agent", "Mozilla/5.0")
                return s
            return _host_factory
        return None
    role_map = {str(k).lower(): v for k, v in role_map.items()}
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass

    url = os.environ.get("AEGIS_LOGIN_URL") or ((base or "https://localhost:8443").rstrip("/") + "/api/auth/login")
    pin = os.environ.get("AEGIS_LOGIN_PIN") or os.environ.get("AEGIS_TEST_PIN") or "000000"
    id_field = os.environ.get("AEGIS_LOGIN_ID_FIELD", "name")
    pin_field = os.environ.get("AEGIS_LOGIN_PIN_FIELD", "pin")
    token_fields = _csv("AEGIS_LOGIN_TOKEN_FIELDS",
                        "token,access_token,accessToken,jwt,id_token,accessTokenJwt")
    auth_header = os.environ.get("AEGIS_AUTH_HEADER", "Authorization")
    auth_scheme = os.environ.get("AEGIS_AUTH_SCHEME", "Bearer")
    csrf_cookies = _csv("AEGIS_CSRF_COOKIE", "XSRF-TOKEN,csrf-token,_csrf,csrfToken,CSRF-TOKEN")
    csrf_header_env = os.environ.get("AEGIS_CSRF_HEADER")
    reauth_on = str(os.environ.get("AEGIS_SESSION_REAUTH", "1")).lower() not in ("0", "false", "no", "off")
    cache = {}

    def _csrf_header_for(cookie_name):
        if csrf_header_env:
            return csrf_header_env
        # framework convention: XSRF-TOKEN cookie -> X-XSRF-TOKEN header (Angular/Laravel); else X-CSRF-Token
        return "X-XSRF-TOKEN" if cookie_name.upper() == "XSRF-TOKEN" else "X-CSRF-Token"

    class _RobustSession(requests.Session):
        """A requests.Session that carries bearer + CSRF headers and re-auths on expiry."""

        def __init__(self, ident):
            super().__init__()
            self.verify = False
            if host_hdr:                   # AEGIS_HOST_HEADER: reach the real vhost behind a WAF/origin
                self.headers["Host"] = host_hdr
            self._ident = ident            # None => anonymous role (never re-auths to a privileged id)
            self._authing = False          # recursion guard around the login call

        # -- login: post creds, then harvest a bearer token + CSRF token into the session --
        def _login(self):
            if not self._ident or self._authing:
                return
            self._authing = True
            try:
                r = self.post(url, json={id_field: self._ident, pin_field: pin}, timeout=20, verify=False)
                body = None
                try:
                    body = r.json()
                except Exception:
                    body = None
                tok = _dig(body, token_fields) if body is not None else None
                if tok:
                    self.headers[auth_header] = (auth_scheme + " " + str(tok)).strip() if auth_scheme else str(tok)
            except Exception:
                pass
            finally:
                self._authing = False

        def _apply_csrf(self, method, headers):
            """Mirror a CSRF cookie into the matching request header for unsafe verbs."""
            if method.upper() not in _UNSAFE:
                return headers
            for cn in csrf_cookies:
                val = None
                try:
                    val = self.cookies.get(cn)
                except Exception:
                    val = None
                if val:
                    hn = _csrf_header_for(cn)
                    headers = dict(headers or {})
                    headers.setdefault(hn, val)
                    break
            return headers

        def request(self, method, req_url, **kwargs):
            kwargs["headers"] = self._apply_csrf(method, kwargs.get("headers"))
            kwargs.setdefault("verify", False)
            resp = super().request(method, req_url, **kwargs)
            if not reauth_on or self._authing or not self._ident:
                return resp
            if self._looks_expired(resp):
                self._login()                              # refresh creds/token in place
                # retry ONCE with refreshed CSRF header
                kwargs["headers"] = self._apply_csrf(method, kwargs.get("headers"))
                try:
                    resp = super().request(method, req_url, **kwargs)
                except Exception:
                    pass
            return resp

        @staticmethod
        def _looks_expired(resp):
            try:
                if resp.status_code in (401, 403):
                    return True
                # a redirect to a login page (session timeout on a browser-style app)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = (resp.headers.get("location") or "").lower()
                    return "login" in loc or "signin" in loc or "/auth" in loc
            except Exception:
                pass
            return False

    def session_for_role(role):
        role = (role or "").lower().strip()
        if role in cache:
            return cache[role]
        ident = role_map.get(role)                       # KNOWN role -> authenticate; unknown/anon -> stay anon
        s = _RobustSession(ident)
        if ident:
            s._login()
        cache[role] = s
        return s

    return session_for_role
