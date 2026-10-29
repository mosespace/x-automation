"""
X Automation Service
====================
A FastAPI service that posts tweets to X (Twitter) via the internal GraphQL API,
using curl_cffi for browser-grade TLS fingerprinting.

Setup:
    1. (Optional) Copy .env.example to .env and set PROXY_URL.
    2. pip install -r requirements.txt
    3. uvicorn execution.main:app --host 0.0.0.0 --port 8000

Endpoints:
    POST /tweet          — Post a tweet (pass auth_token + ct0 in body)
    POST /login/start    — Log in with username + password, returns cookies
    POST /login/continue — Answer a 2FA / confirmation step of a login
    POST /debug-tweet    — Post a test tweet and return raw X response
    GET  /health         — Service status and cache diagnostics
    GET  /ip             — Outbound IP (verify proxy routing)
"""

import asyncio
import datetime
import json
import logging
import os
import re
import time
import uuid

from bs4 import BeautifulSoup
from curl_cffi import CurlMime
from curl_cffi.requests import AsyncSession
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from x_client_transaction import ClientTransaction

load_dotenv()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("x-automation")

PROXY_URL = os.environ.get("PROXY_URL")
# Optional shared secret. When set, /tweet, /debug-tweet and /ip require an
# `x-api-key` header with this value. /health stays open for health checks.
SERVICE_API_KEY = os.environ.get("SERVICE_API_KEY")

BROWSER = "chrome136"

# Stable session UUID — mimics a single browser tab
CLIENT_UUID = str(uuid.uuid4())

# Public bearer token — same for every X web client
BEARER = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

# ── Dynamic GraphQL config ──────────────────────────────────────────
# X's web client (abs.twimg.com/x-web) posts through a persisted Relay
# mutation. Its id, and the script that signs x-client-transaction-id, are
# scraped from X's JS at runtime. The fallback is the last id seen there.
ASSETS_URL = "https://abs.twimg.com/x-web/x-web/assets/"
GRAPHQL_URL = "https://api.x.com/graphql"
CREATE_TWEET_OP = "createTweetMutation"
FALLBACK_QUERY_ID = "CQg_EnWgzRTsnDVd7FFZJw"
# Lazy chunks the composer has been bundled into, checked in order
COMPOSER_CHUNKS = ("media-upload-button", "tweet-composer-slot", "schedule-button")
CREATE_TWEET_RE = re.compile(
    r'params:\{id:[`"]([\w-]+)[`"],metadata:\{\},name:[`"]createTweetMutation[`"]'
    r',operationKind:[`"]mutation[`"],text:null(?:,providedVariables:\{([^}]*)\})?'
)

# Relay "provided variables" the mutation declares. The web client sends one
# per declared name; they only switch optional fields of the response.
PROVIDED_VARIABLES = {
    "__relay_internal__pv__xclientsfeaturesappviewerisloggedinrelayprovider": True,
    "__relay_internal__pv__xclientsfeaturestweetcomponentsgrokanalyzepostrelayprovider": False,
    "__relay_internal__pv__xclientsfeaturestranslationnoteautotranslationenabledrelayprovider": False,
    "__relay_internal__pv__xclientsfeaturestranslationgroktranslatedpostenabledrelayprovider": True,
    "__relay_internal__pv__liveeventpostcontextenabledrelayprovider": False,
    "__relay_internal__pv__sportspostcontextenabledrelayprovider": False,
}

# In-memory cache
_query_id: str | None = None
_provided_names: list[str] = []
_transaction_ctx: ClientTransaction | None = None
_cache_ts: float = 0
_last_scrape_attempt: float = 0
_last_scrape_error: str | None = None
CACHE_TTL = 3600  # 1 hour
SCRAPE_RETRY_COOLDOWN = 60  # seconds to wait after a failed scrape before retrying


def _asset_names(text: str, prefix: str) -> list[str]:
    """Hashed asset filenames like `sign.o-DInG6T4Q.js` referenced in text."""
    found = re.findall(rf"(?<![\w.-])({re.escape(prefix)}-[\w-]{{8}}\.js)", text)
    return list(dict.fromkeys(found))


async def _scrape_gql_config() -> None:
    """Refresh the createTweetMutation id and the transaction-id context from X's JS."""
    global _query_id, _provided_names, _transaction_ctx, _cache_ts, _last_scrape_attempt, _last_scrape_error

    if _query_id and _transaction_ctx and (time.time() - _cache_ts) < CACHE_TTL:
        return

    # If the last scrape attempt failed recently, don't hammer the network
    now = time.time()
    if _last_scrape_attempt and (now - _last_scrape_attempt) < SCRAPE_RETRY_COOLDOWN:
        return

    _last_scrape_attempt = now
    log.info("Scraping X JS bundles for createTweetMutation + transaction context...")
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None

    try:
        async with AsyncSession(impersonate=BROWSER, proxies=proxies) as s:

            async def fetch_asset(name: str) -> str:
                r = await s.get(ASSETS_URL + name, timeout=15)
                return r.text if r.status_code == 200 else ""

            # Fetch a public X page to find script URLs
            resp = await s.get("https://x.com/x", timeout=15)
            html = resp.text

            # Handle JS redirect
            if ">document.location =" in html:
                url = html.split('document.location = "')[1].split('"')[0]
                resp = await s.get(url, timeout=15)
                html = resp.text

            # The page links a few entry chunks. One of them imports
            # startup-dynamic, which lazy-loads the signing script and composer.
            entries = list(dict.fromkeys(
                re.findall(r"https://abs\.twimg\.com/x-web/x-web/assets/([\w.-]+\.js)", html)
            ))
            dynamic = ""
            for entry in entries:
                names = _asset_names(await fetch_asset(entry), "startup-dynamic")
                if names:
                    dynamic = await fetch_asset(names[0])
                    break
            if not dynamic:
                raise RuntimeError(
                    f"startup-dynamic chunk not found in {len(entries)} entry scripts "
                    f"(x.com returned {resp.status_code}). X may have changed its web client."
                )

            # ── x-client-transaction-id context ──
            ctx_error = None
            sign = _asset_names(dynamic, "sign.o")
            if sign:
                try:
                    _transaction_ctx = ClientTransaction(
                        BeautifulSoup(html, "html.parser"), await fetch_asset(sign[0])
                    )
                    log.info(f"ClientTransaction initialized from {sign[0]}")
                except Exception as exc:
                    ctx_error = f"ClientTransaction init failed: {exc}"
            else:
                ctx_error = "sign.o script not found in startup-dynamic"
            if ctx_error:
                log.warning(ctx_error)

            # ── createTweetMutation id ──
            match = None
            for chunk in COMPOSER_CHUNKS:
                for name in _asset_names(dynamic, chunk):
                    match = CREATE_TWEET_RE.search(await fetch_asset(name))
                    if match:
                        break
                if match:
                    break

            if match:
                _query_id = match.group(1)
                _provided_names = re.findall(r"(__relay_internal__pv__\w+):", match.group(2) or "")
                log.info(f"Scraped {CREATE_TWEET_OP}={_query_id}")
            else:
                log.warning(f"{CREATE_TWEET_OP} not found in composer chunks, keeping cache/fallback")

            if match and not ctx_error:
                _last_scrape_error = None
                _cache_ts = time.time()
                _last_scrape_attempt = 0  # reset so next cache expiry retries immediately
            else:
                _last_scrape_error = ctx_error or f"{CREATE_TWEET_OP} not found in composer chunks"

    except Exception as exc:
        _last_scrape_error = str(exc)
        log.warning(f"Bundle scrape failed: {exc}, using fallback")


async def _get_create_tweet_id(force_refresh: bool = False) -> str:
    """Return the current createTweetMutation id."""
    global _cache_ts, _last_scrape_attempt

    if force_refresh:
        _cache_ts = 0  # bust cache
        _last_scrape_attempt = 0

    await _scrape_gql_config()
    if _query_id:
        return _query_id

    log.warning(f"{CREATE_TWEET_OP} id not scraped, using fallback")
    return FALLBACK_QUERY_ID


def _create_tweet_url(query_id: str) -> str:
    return f"{GRAPHQL_URL}/{query_id}/{CREATE_TWEET_OP}"


def _provided_variables() -> dict:
    names = _provided_names or list(PROVIDED_VARIABLES)
    return {name: PROVIDED_VARIABLES.get(name, False) for name in names}


# ── App setup ───────────────────────────────────────────────────────
app = FastAPI(title="X Automation Service")


@app.on_event("startup")
async def startup():
    """Pre-warm the queryId cache on deploy so first tweet is fast."""
    await _scrape_gql_config()


def require_api_key(x_api_key: str | None = Header(default=None, alias="x-api-key")):
    if SERVICE_API_KEY and x_api_key != SERVICE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-key")


def _build_headers(auth_token: str, ct0: str, method: str = "POST", path: str = "") -> dict:
    headers = {
        "authorization": f"Bearer {BEARER}",
        "cookie": f"auth_token={auth_token}; ct0={ct0}",
        "x-csrf-token": ct0,
        "content-type": "application/json",
        "x-twitter-active-user": "yes",
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-client-language": "en",
        "x-client-uuid": CLIENT_UUID,
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "origin": "https://x.com",
        "referer": "https://x.com/compose/post",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        # Every call goes to api.x.com or upload.x.com from an x.com page
        "sec-fetch-site": "same-site",
    }

    # Generate x-client-transaction-id if we have the context
    if _transaction_ctx and method and path:
        try:
            tid = _transaction_ctx.generate_transaction_id(method=method, path=path)
            headers["x-client-transaction-id"] = tid
        except Exception as exc:
            log.warning(f"Transaction ID generation failed: {exc}")

    return headers


def _build_tweet_payload(
    text: str, query_id: str, media_ids: list[str] | None = None
) -> dict:
    # Same shape as the web composer: optional fields only when set
    variables: dict = {"tweet_text": text}
    if media_ids:
        variables["media"] = {
            "media_entities": [{"media_id": mid} for mid in media_ids],
            "possibly_sensitive": False,
        }
    variables.update(_provided_variables())
    return {"queryId": query_id, "variables": variables}


# ── Media upload ────────────────────────────────────────────────────
UPLOAD_URL = "https://upload.x.com/i/media/upload.json"
MAX_IMAGES = 4
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_GIF_BYTES = 15 * 1024 * 1024
CHUNK_BYTES = 2 * 1024 * 1024
IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}


class MediaError(Exception):
    """An image couldn't be fetched or uploaded. The message is shown to callers."""


def _upload_headers(auth_token: str, ct0: str) -> dict:
    headers = _build_headers(auth_token, ct0)
    headers.pop("content-type", None)  # multipart / query-string requests
    return headers


async def _download_image(url: str) -> tuple[bytes, str]:
    # Fetched directly (not via the proxy): it's our own storage, not X
    async with AsyncSession(impersonate=BROWSER) as s:
        resp = await s.get(url, timeout=30)
    if resp.status_code != 200:
        raise MediaError(f"MEDIA_DOWNLOAD_FAILED: {url} returned {resp.status_code}")
    media_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    if media_type not in IMAGE_TYPES:
        raise MediaError(f"MEDIA_UNSUPPORTED: {media_type or 'unknown type'} (use JPEG, PNG, WebP or GIF)")
    data = resp.content
    limit = MAX_GIF_BYTES if media_type == "image/gif" else MAX_IMAGE_BYTES
    if len(data) > limit:
        raise MediaError(f"MEDIA_TOO_LARGE: {len(data) // 1024} KB is over X's {limit // (1024 * 1024)} MB limit")
    return data, media_type


async def _upload_image(url: str, auth_token: str, ct0: str) -> str:
    """Upload one image with X's chunked INIT/APPEND/FINALIZE flow; returns media_id."""
    data, media_type = await _download_image(url)
    category = "tweet_gif" if media_type == "image/gif" else "tweet_image"
    headers = _upload_headers(auth_token, ct0)
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None

    async with AsyncSession(impersonate=BROWSER, proxies=proxies) as s:
        init = await s.post(
            UPLOAD_URL,
            params={
                "command": "INIT",
                "total_bytes": str(len(data)),
                "media_type": media_type,
                "media_category": category,
            },
            headers=headers,
            timeout=30,
        )
        if init.status_code not in (200, 201, 202):
            try:
                init_body = init.json()
            except Exception:
                init_body = {}
            # Expired cookies show up here first when a tweet has images
            err = _classify_error(init_body, init.status_code)
            if err.startswith("AUTH_EXPIRED"):
                raise MediaError(err)
            raise MediaError(f"MEDIA_UPLOAD_FAILED: INIT returned {init.status_code} {init.text[:200]}")
        media_id = init.json().get("media_id_string")
        if not media_id:
            raise MediaError(f"MEDIA_UPLOAD_FAILED: INIT returned no media_id {init.text[:200]}")

        for index, start in enumerate(range(0, len(data), CHUNK_BYTES)):
            mime = CurlMime()
            mime.addpart(
                name="media",
                content_type="application/octet-stream",
                filename="blob",
                data=data[start : start + CHUNK_BYTES],
            )
            try:
                append = await s.post(
                    UPLOAD_URL,
                    params={"command": "APPEND", "media_id": media_id, "segment_index": str(index)},
                    headers=headers,
                    multipart=mime,
                    timeout=60,
                )
            finally:
                mime.close()
            if append.status_code not in (200, 201, 202, 204):
                raise MediaError(f"MEDIA_UPLOAD_FAILED: APPEND returned {append.status_code} {append.text[:200]}")

        final = await s.post(
            UPLOAD_URL,
            params={"command": "FINALIZE", "media_id": media_id},
            headers=headers,
            timeout=30,
        )
        if final.status_code not in (200, 201, 202):
            raise MediaError(f"MEDIA_UPLOAD_FAILED: FINALIZE returned {final.status_code} {final.text[:200]}")

        # Images are usually ready at once; GIFs may need processing
        info = final.json().get("processing_info")
        for _ in range(10):
            if not info or info.get("state") == "succeeded":
                break
            if info.get("state") == "failed":
                raise MediaError(f"MEDIA_UPLOAD_FAILED: X couldn't process the image ({info.get('error', {}).get('message', 'unknown')})")
            await asyncio.sleep(min(int(info.get("check_after_secs", 1)), 5))
            status = await s.get(
                UPLOAD_URL,
                params={"command": "STATUS", "media_id": media_id},
                headers=headers,
                timeout=30,
            )
            info = status.json().get("processing_info")

    log.info(f"Uploaded {media_type} ({len(data) // 1024} KB) as media {media_id}")
    return media_id


# ── Error classification ────────────────────────────────────────────
def _classify_error(data: dict, status_code: int) -> str:
    """Turn raw X response into an actionable error message."""
    errors = data.get("errors", []) if isinstance(data, dict) else []

    # 403 is also what X returns for a missing/invalid x-client-transaction-id,
    # so only call it expired cookies when X's error code says so (below) or
    # the status is a plain 401.
    if not errors:
        if status_code == 401:
            return "AUTH_EXPIRED: Cookies (auth_token/ct0) are invalid or expired. Re-export from browser."
        if status_code == 403:
            ctx = "active" if _transaction_ctx else "unavailable"
            return (
                f"FORBIDDEN: X refused the request (403) without an error code. "
                f"Usually a blocked IP or missing transaction id (transaction_ctx={ctx}), "
                f"not expired cookies. Check /health and PROXY_URL."
            )
        return ""

    code = errors[0].get("code") or errors[0].get("extensions", {}).get("code")
    msg = errors[0].get("message", "")

    error_map = {
        32: "AUTH_EXPIRED: Could not authenticate. Re-export cookies from browser.",
        36: "ACCOUNT_SUSPENDED: This account is suspended.",
        64: "ACCOUNT_SUSPENDED: This account is suspended.",
        89: "AUTH_EXPIRED: Invalid or expired token. Re-export cookies from browser.",
        130: "RATE_LIMIT: X is over capacity. Wait and retry.",
        131: "INTERNAL_ERROR: X internal error. Wait and retry.",
        187: "DUPLICATE_TWEET: This exact text was already posted recently. Make it unique.",
        226: "AUTOMATION_DETECTED: Request flagged as automated. Check TLS fingerprint / proxy.",
        353: "AUTH_EXPIRED: ct0 doesn't match this session. Re-export both cookies from the same browser.",
        261: "APP_SUSPENDED: Application write access suspended.",
        326: "ACCOUNT_LOCKED: Account temporarily locked. Log in via browser to unlock.",
        344: "RATE_LIMIT: Daily tweet limit reached. Wait 24h.",
    }

    return error_map.get(code, f"X_ERROR_{code}: {msg}")


class TweetRequest(BaseModel):
    text: str = Field(..., description="Tweet content, max 280 characters")
    mediaUrls: list[str] = Field(default=[], description="Public image URLs to attach")


class TweetResponse(BaseModel):
    success: bool
    tweet_id: str | None = None
    error: str | None = None


async def _attempt_tweet(
    text: str,
    query_id: str,
    auth_token: str,
    ct0: str,
    media_ids: list[str] | None = None,
) -> dict:
    """Fire a single createTweetMutation request. Returns raw parsed JSON."""
    url = _create_tweet_url(query_id)
    path = url.removeprefix("https://api.x.com")
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None
    async with AsyncSession(impersonate=BROWSER, proxies=proxies) as session:
        body = _build_tweet_payload(text, query_id, media_ids)
        resp = await session.post(
            url,
            headers=_build_headers(auth_token, ct0, method="POST", path=path),
            json=body,
            timeout=30,
        )
    try:
        data = resp.json()
    except Exception:
        # Blocked requests often come back as an HTML page, not JSON
        data = {"raw": resp.text[:500]}
    return {"status_code": resp.status_code, "data": data}


def _extract_tweet_id(data: dict) -> str | None:
    """Pull tweet_id from the nested response, tolerating shape variations."""
    try:
        tweet_results = data["data"]["create_tweet"]["tweet_results"]
        result = tweet_results.get("result") or tweet_results.get("tweet", {})
        return result.get("rest_id") or result.get("tweet", {}).get("rest_id")
    except (KeyError, TypeError, AttributeError):
        return None


@app.post("/tweet", response_model=TweetResponse, dependencies=[Depends(require_api_key)])
async def post_tweet(
    payload: TweetRequest,
    x_auth_token: str = Header(..., alias="x-auth-token", description="auth_token cookie from your X browser session"),
    x_ct0: str = Header(..., alias="x-ct0", description="ct0 cookie from your X browser session"),
):
    try:
        # Upload images first; a failed upload fails the tweet rather than
        # silently posting it without the image the caller asked for.
        if len(payload.mediaUrls) > MAX_IMAGES:
            return TweetResponse(success=False, error=f"MEDIA_TOO_MANY: X allows up to {MAX_IMAGES} images per post")
        try:
            media_ids = [
                await _upload_image(url, x_auth_token, x_ct0) for url in payload.mediaUrls
            ]
        except MediaError as exc:
            log.warning(str(exc))
            return TweetResponse(success=False, error=str(exc))

        # Attempt 1: use cached queryId
        query_id = await _get_create_tweet_id()
        result = await _attempt_tweet(payload.text, query_id, x_auth_token, x_ct0, media_ids)
        data = result["data"]
        status = result["status_code"]

        # Non-200 → classify and return
        if status != 200:
            err = _classify_error(data, status) or f"X API {status}: {json.dumps(data)}"
            return TweetResponse(success=False, error=err)

        # Try to extract tweet_id first — X may include both errors AND a valid result
        tweet_id = _extract_tweet_id(data)
        if tweet_id:
            return TweetResponse(success=True, tweet_id=tweet_id)

        # No tweet_id found — check for explicit errors
        if "errors" in data:
            err = _classify_error(data, status)
            return TweetResponse(success=False, error=err)

        # Empty tweet_results → likely stale queryId. Force-refresh and retry once.
        log.warning("Empty tweet_results. Refreshing queryId and retrying...")
        new_query_id = await _get_create_tweet_id(force_refresh=True)

        log.info(f"queryId: {query_id} → {new_query_id}. Retrying...")
        result = await _attempt_tweet(payload.text, new_query_id, x_auth_token, x_ct0, media_ids)
        data = result["data"]
        status = result["status_code"]

        if status != 200:
            err = _classify_error(data, status) or f"X API {status}: {json.dumps(data)}"
            return TweetResponse(success=False, error=err)

        tweet_id = _extract_tweet_id(data)
        if tweet_id:
            return TweetResponse(success=True, tweet_id=tweet_id)

        if "errors" in data:
            err = _classify_error(data, status)
            return TweetResponse(success=False, error=err)

        # Still empty after retry
        return TweetResponse(
            success=False,
            error=f"EMPTY_RESULT: Tweet may have been silently rejected (rate-limit, duplicate, or account restriction). Response: {json.dumps(data)}",
        )

    except Exception as exc:
        error_str = str(exc)
        if "proxy" in error_str.lower() or "connect" in error_str.lower():
            return TweetResponse(success=False, error=f"PROXY_ERROR: {error_str}")
        return TweetResponse(success=False, error=error_str)


# ── Login ───────────────────────────────────────────────────────────
# Logs in through X's web login flow (onboarding/task.json) and hands back the
# auth_token + ct0 cookies, so users without DevTools (phones) can connect.
# X can stop the flow to ask for a 2FA code or an email/phone check, so each
# login stays in memory between calls for LOGIN_TTL seconds. The password is
# kept only until X accepts it and is never logged or written anywhere.
TASK_URL = "https://api.x.com/1.1/onboarding/task.json"
TASK_PATH = "/1.1/onboarding/task.json"
LOGIN_TTL = 600
MAX_PENDING_LOGINS = 200
MAX_CODE_ATTEMPTS = 3

# Steps the user has to answer, and what to call them in the response
CHALLENGE_SUBTASKS = {
    "LoginTwoFactorAuthChallenge": "two_factor",
    "LoginAcid": "confirmation_code",
    "LoginEnterAlternateIdentifierSubtask": "email_or_phone",
}


class LoginError(Exception):
    """The login can't go on. The message is a "CODE: reason" shown to callers."""


class _PendingLogin:
    def __init__(self, session: AsyncSession, username: str, password: str):
        self.session = session
        self.username = username
        self.password: str | None = password
        self.guest_token = ""
        self.flow_token = ""
        self.subtasks: list[dict] = []
        self.code_attempts = 0
        self.created = time.time()
        self.lock = asyncio.Lock()


_pending_logins: dict[str, _PendingLogin] = {}


def require_service_key(x_api_key: str | None = Header(default=None, alias="x-api-key")):
    # Without a key, /login would let anyone use this server to try X passwords
    if not SERVICE_API_KEY:
        raise HTTPException(status_code=503, detail="SERVICE_API_KEY must be set to use /login")
    if x_api_key != SERVICE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-key")


def _cookie(cookies, name: str) -> str | None:
    """Read a cookie by name whatever its domain (X sets them on .x.com and x.com)."""
    for c in cookies.jar:
        if c.name == name and c.value:
            return c.value
    return None


async def _close_login(login_id: str) -> None:
    login = _pending_logins.pop(login_id, None)
    if login:
        login.password = None
        try:
            await login.session.close()
        except Exception:
            pass


async def _expire_logins() -> None:
    now = time.time()
    for login_id in [k for k, v in _pending_logins.items() if now - v.created > LOGIN_TTL]:
        await _close_login(login_id)


def _login_headers(login: _PendingLogin) -> dict:
    headers = {
        "authorization": f"Bearer {BEARER}",
        "content-type": "application/json",
        "x-guest-token": login.guest_token,
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "origin": "https://x.com",
        "referer": "https://x.com/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
    }
    # The web client echoes ct0 once X has set one during the flow
    ct0 = _cookie(login.session.cookies, "ct0")
    if ct0:
        headers["x-csrf-token"] = ct0
    if _transaction_ctx:
        try:
            headers["x-client-transaction-id"] = _transaction_ctx.generate_transaction_id(
                method="POST", path=TASK_PATH
            )
        except Exception as exc:
            log.warning(f"Transaction ID generation failed: {exc}")
    return headers


def _subtask_text(subtask: dict) -> str | None:
    """The prompt X shows for a step, e.g. "Check your email for a code"."""
    for key in ("enter_text", "cta", "enter_password"):
        block = subtask.get(key) or {}
        for source in (block.get("header") or {}, block):
            for field in ("secondary_text", "primary_text"):
                text = (source.get(field) or {}).get("text")
                if text:
                    return text
    return None


def _classify_login_error(data: dict, status_code: int) -> str:
    errors = data.get("errors", []) if isinstance(data, dict) else []
    if not errors:
        if status_code in (403, 429):
            return f"FORBIDDEN: X refused the login ({status_code}). The IP may be blocked; check PROXY_URL."
        return f"LOGIN_FAILED: X returned {status_code}."

    code = errors[0].get("code")
    # X appends tracking junk to messages, e.g. "Wrong password! g;1720…"
    msg = (errors[0].get("message") or "").split(" g;")[0].strip()

    if code == 399:
        return f"LOGIN_FAILED: {msg or 'X rejected the login.'}"
    if code == 366:
        return "LOGIN_EXPIRED: This login timed out. Start again."
    if code == 326:
        return "ACCOUNT_LOCKED: Account temporarily locked. Log in on x.com to unlock it."
    if code in (88, 130):
        return "RATE_LIMIT: Too many login attempts. Wait a while and try again."
    if code == 226:
        return "AUTOMATION_DETECTED: X flagged this login as automated."
    return f"X_ERROR_{code}: {msg}"


async def _run_task(login: _PendingLogin, body: dict, params: dict | None = None) -> None:
    resp = await login.session.post(
        TASK_URL, params=params, headers=_login_headers(login), json=body, timeout=30
    )
    try:
        data = resp.json()
    except Exception:
        data = {}
    if resp.status_code != 200 or not data.get("flow_token"):
        raise LoginError(_classify_login_error(data, resp.status_code))
    login.flow_token = data["flow_token"]
    login.subtasks = data.get("subtasks") or []


async def _begin_login(login: _PendingLogin) -> None:
    # Pick up the guest cookies a browser would have before logging in
    await login.session.get("https://x.com/i/flow/login", timeout=15)
    resp = await login.session.post(
        "https://api.x.com/1.1/guest/activate.json",
        headers={"authorization": f"Bearer {BEARER}"},
        timeout=15,
    )
    try:
        guest_token = resp.json().get("guest_token")
    except Exception:
        guest_token = None
    if not guest_token:
        raise LoginError(
            f"FORBIDDEN: X wouldn't start a login ({resp.status_code}). The IP may be blocked; check PROXY_URL."
        )
    login.guest_token = guest_token
    await _run_task(
        login,
        {"input_flow_data": {"flow_context": {"debug_overrides": {}, "start_location": {"location": "splash_screen"}}}},
        params={"flow_name": "login"},
    )


async def _advance_login(login: _PendingLogin, answer: str | None = None) -> dict:
    """Answer every step we can on our own; stop at the first one the user must answer."""
    for _ in range(12):
        ids = [s.get("subtask_id") for s in login.subtasks]
        if "LoginSuccessSubtask" in ids or _cookie(login.session.cookies, "auth_token"):
            return await _finish_login(login)

        subtask = login.subtasks[0] if login.subtasks else {}
        sid = subtask.get("subtask_id") or ""

        if sid == "LoginJsInstrumentationSubtask":
            step = {"js_instrumentation": {"response": "{}", "link": "next_link"}}
        elif sid == "LoginEnterUserIdentifierSSO":
            step = {
                "settings_list": {
                    "setting_responses": [
                        {"key": "user_identifier", "response_data": {"text_data": {"result": login.username}}}
                    ],
                    "link": "next_link",
                }
            }
        elif sid == "LoginEnterPassword":
            if not login.password:
                raise LoginError("LOGIN_EXPIRED: X asked for the password again. Start again.")
            step = {"enter_password": {"password": login.password, "link": "next_link"}}
        elif sid == "AccountDuplicationCheck":
            step = {"check_logged_in_account": {"link": "AccountDuplicationCheck_false"}}
        elif sid in CHALLENGE_SUBTASKS:
            if not answer:
                return {
                    "status": "challenge",
                    "challenge": CHALLENGE_SUBTASKS[sid],
                    "hint": _subtask_text(subtask),
                }
            step = {"enter_text": {"text": answer, "link": "next_link"}}
            answer = None
        elif sid == "DenyLoginSubtask":
            raise LoginError(f"LOGIN_DENIED: {_subtask_text(subtask) or 'X blocked this login.'}")
        elif "Arkose" in sid or "Captcha" in sid:
            raise LoginError(
                "CAPTCHA_REQUIRED: X wants a captcha for this login. Log in on x.com once, then try again."
            )
        else:
            raise LoginError(f"UNSUPPORTED_STEP: X asked for a login step this service doesn't handle ({sid or 'none'}).")

        log.info(f"Login step {sid}")
        await _run_task(login, {"flow_token": login.flow_token, "subtask_inputs": [{"subtask_id": sid, **step}]})
        if sid == "LoginEnterPassword":
            login.password = None

    raise LoginError("LOGIN_FAILED: X kept asking for more login steps.")


async def _finish_login(login: _PendingLogin) -> dict:
    auth_token = _cookie(login.session.cookies, "auth_token")
    if not auth_token:
        raise LoginError("LOGIN_FAILED: X finished the login but sent no session cookie.")

    # The ct0 from the guest flow may not belong to the new session. X answers
    # a mismatched ct0 with a fresh one, so check it and take the new value.
    ct0 = _cookie(login.session.cookies, "ct0") or ""
    path = "/1.1/account/settings.json"
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None
    for _ in range(2):
        async with AsyncSession(impersonate=BROWSER, proxies=proxies) as s:
            resp = await s.get(
                f"https://api.x.com{path}",
                headers=_build_headers(auth_token, ct0, method="GET", path=path),
                timeout=15,
            )
        if resp.status_code == 200:
            try:
                username = resp.json().get("screen_name")
            except Exception:
                username = None
            return {"status": "connected", "auth_token": auth_token, "ct0": ct0, "username": username}
        fresh = _cookie(resp.cookies, "ct0")
        if not fresh or fresh == ct0:
            break
        ct0 = fresh

    try:
        data = resp.json()
    except Exception:
        data = {}
    raise LoginError(_classify_error(data, resp.status_code) or f"LOGIN_FAILED: X didn't accept the new session ({resp.status_code}).")


class LoginStartRequest(BaseModel):
    username: str = Field(..., description="X username, email or phone")
    password: str


class LoginContinueRequest(BaseModel):
    login_id: str
    code: str = Field(..., description="2FA code, confirmation code, or the email/phone X asked for")


class LoginResponse(BaseModel):
    status: str  # "connected" | "challenge" | "failed"
    login_id: str | None = None
    challenge: str | None = None  # "two_factor" | "confirmation_code" | "email_or_phone"
    hint: str | None = None
    auth_token: str | None = None
    ct0: str | None = None
    username: str | None = None
    error: str | None = None


def _login_response(login_id: str, result: dict) -> LoginResponse:
    if result["status"] == "challenge":
        return LoginResponse(login_id=login_id, **result)
    return LoginResponse(**result)


@app.post("/login/start", response_model=LoginResponse, dependencies=[Depends(require_service_key)])
async def login_start(payload: LoginStartRequest):
    await _expire_logins()
    if len(_pending_logins) >= MAX_PENDING_LOGINS:
        return LoginResponse(status="failed", error="RATE_LIMIT: Too many logins in progress. Try again in a few minutes.")

    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None
    login_id = uuid.uuid4().hex
    login = _PendingLogin(
        AsyncSession(impersonate=BROWSER, proxies=proxies),
        payload.username.strip().lstrip("@"),
        payload.password,
    )
    _pending_logins[login_id] = login

    async with login.lock:
        try:
            await _begin_login(login)
            result = await _advance_login(login)
        except LoginError as exc:
            await _close_login(login_id)
            log.warning(f"Login failed: {exc}")
            return LoginResponse(status="failed", error=str(exc))
        except Exception as exc:
            await _close_login(login_id)
            log.warning(f"Login error: {exc}")
            return LoginResponse(status="failed", error=f"NETWORK_ERROR: {exc}")

    if result["status"] != "challenge":
        await _close_login(login_id)
    return _login_response(login_id, result)


@app.post("/login/continue", response_model=LoginResponse, dependencies=[Depends(require_service_key)])
async def login_continue(payload: LoginContinueRequest):
    await _expire_logins()
    login = _pending_logins.get(payload.login_id)
    if not login:
        return LoginResponse(status="failed", error="LOGIN_EXPIRED: This login timed out. Start again.")

    async with login.lock:
        try:
            result = await _advance_login(login, payload.code.strip())
        except LoginError as exc:
            # A mistyped code can be tried again on the same step, a few times
            login.code_attempts += 1
            retry = str(exc).startswith("LOGIN_FAILED") and login.code_attempts < MAX_CODE_ATTEMPTS
            if not retry:
                await _close_login(payload.login_id)
            log.warning(f"Login step failed: {exc}")
            return LoginResponse(
                status="failed",
                login_id=payload.login_id if retry else None,
                error=str(exc),
            )
        except Exception as exc:
            await _close_login(payload.login_id)
            log.warning(f"Login error: {exc}")
            return LoginResponse(status="failed", error=f"NETWORK_ERROR: {exc}")

    if result["status"] != "challenge":
        await _close_login(payload.login_id)
    return _login_response(payload.login_id, result)


@app.get("/health")
async def health():
    """Health check — reports current cache state without triggering a scrape."""
    return {
        "status": "ok",
        "create_tweet_query_id": _query_id or FALLBACK_QUERY_ID,
        "query_id_source": "scraped" if _query_id else "fallback",
        "provided_variables": len(_provided_variables()),
        "transaction_ctx": "active" if _transaction_ctx else "unavailable",
        "cache_age_seconds": int(time.time() - _cache_ts) if _cache_ts else None,
        "last_scrape_error": _last_scrape_error,
        "proxy_configured": bool(PROXY_URL),
        "api_key_required": bool(SERVICE_API_KEY),
    }


@app.get("/ip", dependencies=[Depends(require_api_key)])
async def check_ip():
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None
    async with AsyncSession(impersonate=BROWSER, proxies=proxies) as session:
        resp = await session.get("https://api.ipify.org?format=json", timeout=10)
        return {"proxy_configured": bool(PROXY_URL), "ip": resp.json()}


@app.post("/debug-tweet", dependencies=[Depends(require_api_key)])
async def debug_tweet(
    x_auth_token: str = Header(..., alias="x-auth-token", description="auth_token cookie from your X browser session"),
    x_ct0: str = Header(..., alias="x-ct0", description="ct0 cookie from your X browser session"),
):
    """Fire a test tweet and return the full raw X response for debugging."""
    text = f"debug {datetime.datetime.utcnow().isoformat()}"
    query_id = await _get_create_tweet_id()
    url = _create_tweet_url(query_id)
    path = url.removeprefix("https://api.x.com")
    proxies = {"https": PROXY_URL, "http": PROXY_URL} if PROXY_URL else None
    async with AsyncSession(impersonate=BROWSER, proxies=proxies) as session:
        body = _build_tweet_payload(text, query_id)
        resp = await session.post(
            url,
            headers=_build_headers(x_auth_token, x_ct0, method="POST", path=path),
            json=body,
            timeout=30,
        )
    return {
        "status_code": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body": resp.json(),
        "query_id_used": query_id,
        "transaction_id_active": _transaction_ctx is not None,
        "tweet_text": text,
    }
