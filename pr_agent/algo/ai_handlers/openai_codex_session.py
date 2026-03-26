import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp

from pr_agent.config_loader import get_settings
from pr_agent.log import get_logger

DEFAULT_OPENAI_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_OPENAI_CODEX_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
DEFAULT_OPENAI_CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_OPENAI_CODEX_BASE_URL = "https://chatgpt.com/backend-api"
DEFAULT_OPENAI_CODEX_ORIGINATOR = "pr-agent"
DEFAULT_OPENAI_CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_OPENAI_CODEX_SCOPE = "openid profile email offline_access"
DEFAULT_OPENAI_CODEX_JWT_CLAIM_PATH = "https://api.openai.com/auth"
OPENAI_CODEX_REFRESH_SKEW_MS = 60_000


@dataclass
class OpenAICodexCredentials:
    access_token: str
    refresh_token: str
    expires_at: int
    account_id: str


def _settings_key(key: str) -> str:
    return f"OPENAI_CODEX.{key}"


def _get_setting(key: str, default: Any = None) -> Any:
    return get_settings().get(_settings_key(key), default)


def _set_runtime_setting(key: str, value: Any) -> None:
    get_settings().set(_settings_key(key), value)


def get_openai_codex_secrets_file() -> Path:
    env_override = os.environ.get("PR_AGENT_OPENAI_CODEX_SECRETS_FILE")
    if env_override:
        return Path(env_override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "settings_prod" / ".secrets_openai_codex.toml"


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _write_session_file(credentials: OpenAICodexCredentials | None) -> None:
    secrets_file = get_openai_codex_secrets_file()
    secrets_file.parent.mkdir(parents=True, exist_ok=True)

    if credentials is None:
        if secrets_file.exists():
            secrets_file.unlink()
        return

    content = "\n".join(
        [
            "# This file is managed by `pr-agent-chatgpt-auth`.",
            "# Do not edit access or refresh tokens manually.",
            "",
            "[openai_codex]",
            f'access_token = "{_toml_escape(credentials.access_token)}"',
            f'refresh_token = "{_toml_escape(credentials.refresh_token)}"',
            f"expires_at = {credentials.expires_at}",
            f'account_id = "{_toml_escape(credentials.account_id)}"',
            "",
        ]
    )
    secrets_file.write_text(content, encoding="utf-8")


def _sync_runtime_credentials(credentials: OpenAICodexCredentials | None) -> None:
    values = {
        "ACCESS_TOKEN": credentials.access_token if credentials else "",
        "REFRESH_TOKEN": credentials.refresh_token if credentials else "",
        "EXPIRES_AT": credentials.expires_at if credentials else 0,
        "ACCOUNT_ID": credentials.account_id if credentials else "",
    }
    for key, value in values.items():
        _set_runtime_setting(key, value)


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def create_pkce_codes() -> tuple[str, str]:
    verifier = token_urlsafe(48)
    challenge = _base64url_encode(hashlib.sha256(verifier.encode("utf-8")).digest())
    return verifier, challenge


def create_oauth_state() -> str:
    return token_urlsafe(24)


def decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or not parts[1]:
        raise ValueError("Invalid OpenAI Codex access token.")

    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))


def extract_openai_codex_account_id_from_token(token: str) -> str:
    payload = decode_jwt_payload(token)
    auth_claims = payload.get(DEFAULT_OPENAI_CODEX_JWT_CLAIM_PATH)
    if not isinstance(auth_claims, dict):
        raise ValueError("OpenAI Codex token is missing ChatGPT workspace claims.")

    account_id = auth_claims.get("chatgpt_account_id")
    if not isinstance(account_id, str) or not account_id.strip():
        raise ValueError("Failed to extract ChatGPT workspace id from OpenAI Codex token.")
    return account_id


def _normalize_token_response(payload: dict[str, Any]) -> OpenAICodexCredentials:
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    expires_in = payload.get("expires_in")
    if not isinstance(access_token, str) or not isinstance(refresh_token, str) or not isinstance(expires_in, int):
        raise ValueError("OpenAI Codex OAuth returned an incomplete token payload.")

    return OpenAICodexCredentials(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=int(time.time() * 1000) + expires_in * 1000,
        account_id=extract_openai_codex_account_id_from_token(access_token),
    )


def get_openai_codex_credentials() -> OpenAICodexCredentials | None:
    access_token = _get_setting("ACCESS_TOKEN")
    refresh_token = _get_setting("REFRESH_TOKEN")
    account_id = _get_setting("ACCOUNT_ID")
    expires_at = _get_setting("EXPIRES_AT")

    if not access_token or not refresh_token or not account_id:
        return None

    try:
        expires_at_int = int(expires_at)
    except (TypeError, ValueError):
        return None

    return OpenAICodexCredentials(
        access_token=str(access_token),
        refresh_token=str(refresh_token),
        expires_at=expires_at_int,
        account_id=str(account_id),
    )


def get_openai_codex_auth_status() -> dict[str, Any]:
    credentials = get_openai_codex_credentials()
    if not credentials:
        return {"connected": False, "account_id": None, "expires_at": None, "is_expired": False}

    now_ms = int(time.time() * 1000)
    return {
        "connected": True,
        "account_id": credentials.account_id,
        "expires_at": credentials.expires_at,
        "is_expired": now_ms >= credentials.expires_at,
    }


def clear_pending_openai_codex_oauth() -> None:
    for key in ("OAUTH_STATE", "OAUTH_VERIFIER", "OAUTH_REQUESTED_AT"):
        _set_runtime_setting(key, "")


def save_openai_codex_credentials(credentials: OpenAICodexCredentials) -> None:
    _write_session_file(credentials)
    _sync_runtime_credentials(credentials)
    clear_pending_openai_codex_oauth()


def clear_openai_codex_credentials() -> None:
    _write_session_file(None)
    _sync_runtime_credentials(None)
    clear_pending_openai_codex_oauth()


def build_openai_codex_redirect_uri() -> str:
    return _get_setting("REDIRECT_URI", DEFAULT_OPENAI_CODEX_REDIRECT_URI)


def build_openai_codex_authorize_url(state: str, challenge: str) -> str:
    from urllib.parse import urlencode

    query = urlencode(
        {
            "response_type": "code",
            "client_id": _get_setting("CLIENT_ID", DEFAULT_OPENAI_CODEX_CLIENT_ID),
            "redirect_uri": build_openai_codex_redirect_uri(),
            "scope": _get_setting("SCOPE", DEFAULT_OPENAI_CODEX_SCOPE),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
            "originator": _get_setting("ORIGINATOR", DEFAULT_OPENAI_CODEX_ORIGINATOR),
        }
    )
    return f'{_get_setting("AUTHORIZE_URL", DEFAULT_OPENAI_CODEX_AUTHORIZE_URL)}?{query}'


def parse_openai_codex_authorization_input(value: str) -> dict[str, str]:
    raw_value = value.strip()
    if not raw_value:
        return {}

    try:
        parsed_url = urlparse(raw_value)
        query = parse_qs(parsed_url.query)
        if query:
            return {
                "code": query.get("code", [None])[0] or "",
                "state": query.get("state", [None])[0] or "",
            }
    except Exception:
        pass

    if "#" in raw_value:
        fragment = raw_value.split("#", 1)[1]
        fragment_query = parse_qs(fragment)
        return {
            "code": fragment_query.get("code", [None])[0] or "",
            "state": fragment_query.get("state", [None])[0] or "",
        }

    if "code=" in raw_value:
        query = parse_qs(raw_value)
        return {
            "code": query.get("code", [None])[0] or "",
            "state": query.get("state", [None])[0] or "",
        }

    return {"code": raw_value}


async def _parse_token_error(response: aiohttp.ClientResponse) -> str:
    raw_body = await response.text()
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        return raw_body.strip() or response.reason or "Unknown OpenAI Codex token error."

    if isinstance(parsed, dict):
        error_description = parsed.get("error_description")
        if isinstance(error_description, str) and error_description.strip():
            return error_description
        error = parsed.get("error")
        if isinstance(error, str) and error.strip():
            return error
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message
    return raw_body.strip() or response.reason or "Unknown OpenAI Codex token error."


async def _exchange_openai_codex_tokens(form_data: dict[str, str]) -> OpenAICodexCredentials:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        async with session.post(
            _get_setting("TOKEN_URL", DEFAULT_OPENAI_CODEX_TOKEN_URL),
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            if response.status >= 400:
                raise ValueError(await _parse_token_error(response))
            return _normalize_token_response(await response.json())


async def start_openai_codex_oauth() -> dict[str, str]:
    verifier, challenge = create_pkce_codes()
    state = create_oauth_state()
    _set_runtime_setting("OAUTH_STATE", state)
    _set_runtime_setting("OAUTH_VERIFIER", verifier)
    _set_runtime_setting("OAUTH_REQUESTED_AT", str(int(time.time() * 1000)))
    return {"authorize_url": build_openai_codex_authorize_url(state=state, challenge=challenge)}


async def complete_openai_codex_oauth(user_input: str) -> OpenAICodexCredentials:
    pending_state = _get_setting("OAUTH_STATE")
    pending_verifier = _get_setting("OAUTH_VERIFIER")
    if not pending_state or not pending_verifier:
        raise ValueError("OpenAI Codex sign-in is not pending. Start the connection flow again.")

    parsed_input = parse_openai_codex_authorization_input(user_input)
    code = parsed_input.get("code")
    state = parsed_input.get("state")
    if not code:
        raise ValueError("Missing authorization code from OpenAI Codex callback.")
    if state != pending_state:
        clear_pending_openai_codex_oauth()
        raise ValueError("OpenAI Codex sign-in state mismatch.")

    credentials = await _exchange_openai_codex_tokens(
        {
            "grant_type": "authorization_code",
            "client_id": _get_setting("CLIENT_ID", DEFAULT_OPENAI_CODEX_CLIENT_ID),
            "code": code,
            "code_verifier": pending_verifier,
            "redirect_uri": build_openai_codex_redirect_uri(),
        }
    )
    save_openai_codex_credentials(credentials)
    return credentials


async def refresh_openai_codex_credentials(refresh_token: str) -> OpenAICodexCredentials:
    credentials = await _exchange_openai_codex_tokens(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": _get_setting("CLIENT_ID", DEFAULT_OPENAI_CODEX_CLIENT_ID),
        }
    )
    save_openai_codex_credentials(credentials)
    return credentials


async def ensure_fresh_openai_codex_credentials() -> OpenAICodexCredentials | None:
    credentials = get_openai_codex_credentials()
    if credentials is None:
        return None

    now_ms = int(time.time() * 1000)
    if now_ms + OPENAI_CODEX_REFRESH_SKEW_MS < credentials.expires_at:
        return credentials

    get_logger().info("Refreshing ChatGPT OAuth session for PR-Agent")
    try:
        return await refresh_openai_codex_credentials(credentials.refresh_token)
    except Exception as e:
        get_logger().warning(f"Failed to refresh ChatGPT OAuth session: {e}")
        clear_openai_codex_credentials()
        return None


def resolve_openai_codex_responses_url() -> str:
    base_url = str(_get_setting("BASE_URL", DEFAULT_OPENAI_CODEX_BASE_URL)).rstrip("/")
    if base_url.endswith("/codex/responses"):
        return base_url
    if base_url.endswith("/codex"):
        return f"{base_url}/responses"
    return f"{base_url}/codex/responses"


def build_openai_codex_body(model: str, system: str, user: str) -> dict[str, Any]:
    return {
        "model": model,
        "store": False,
        "stream": True,
        "instructions": system,
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": user}],
            }
        ],
        "text": {"verbosity": "medium"},
    }


def _read_event_data(chunk: str) -> str | None:
    payload_lines = []
    for line in chunk.splitlines():
        if line.startswith("data:"):
            payload_lines.append(line[5:].strip())
    if not payload_lines:
        return None

    payload = "\n".join(payload_lines).strip()
    if not payload or payload == "[DONE]":
        return None
    return payload


def _extract_text_parts(content: Any) -> list[str]:
    if not isinstance(content, list):
        return []

    text_parts = []
    for part in content:
        if not isinstance(part, dict):
            continue
        text_value = part.get("text", "")
        if isinstance(text_value, dict):
            text_value = text_value.get("value", "")
        if part.get("type") in {"output_text", "text", "message_text"} and isinstance(text_value, str) and text_value:
            text_parts.append(text_value)
    return text_parts


def extract_text_from_openai_codex_response(response: Any) -> str:
    if not isinstance(response, dict):
        return ""
    output_text = response.get("output_text")
    if isinstance(output_text, str):
        return output_text

    output = response.get("output")
    if not isinstance(output, list):
        return ""

    text_parts = []
    for item in output:
        if not isinstance(item, dict):
            continue
        text_parts.extend(_extract_text_parts(item.get("content")))
    return "".join(text_parts)


async def parse_openai_codex_error(response: aiohttp.ClientResponse) -> str:
    raw_body = await response.text()
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        return raw_body.strip() or response.reason or "OpenAI Codex request failed."

    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if isinstance(code, str) and any(
                limit_code in code.lower()
                for limit_code in ("usage_limit_reached", "usage_not_included", "rate_limit_exceeded")
            ):
                return "You have hit your ChatGPT usage limit for Codex."
            message = error.get("message")
            if isinstance(message, str) and message.strip():
                return message
    return raw_body.strip() or response.reason or "OpenAI Codex request failed."


async def collect_openai_codex_text(response: aiohttp.ClientResponse) -> tuple[str, str]:
    buffer = ""
    collected_text = ""
    final_response = None

    async for chunk in response.content.iter_chunked(4096):
        buffer += chunk.decode("utf-8", errors="ignore").replace("\r\n", "\n")
        boundary = buffer.find("\n\n")
        while boundary != -1:
            raw_event = buffer[:boundary]
            buffer = buffer[boundary + 2 :]
            payload = _read_event_data(raw_event)
            if payload:
                event = json.loads(payload)
                event_type = event.get("type", "")
                if event_type == "response.output_text.delta" and isinstance(event.get("delta"), str):
                    collected_text += event["delta"]
                elif event_type == "response.output_text.done" and not collected_text and isinstance(event.get("text"), str):
                    collected_text = event["text"]
                elif event_type in {"response.completed", "response.done"}:
                    final_response = event.get("response")
                elif event_type == "response.failed":
                    failed_response = event.get("response")
                    if isinstance(failed_response, dict):
                        failed_error = failed_response.get("error")
                        if isinstance(failed_error, dict) and isinstance(failed_error.get("message"), str):
                            raise ValueError(failed_error["message"])
                    raise ValueError("OpenAI Codex response failed.")
                elif event_type == "error":
                    raise ValueError(str(event.get("message") or "OpenAI Codex returned an error event."))
            boundary = buffer.find("\n\n")

    if not collected_text and final_response is not None:
        collected_text = extract_text_from_openai_codex_response(final_response)

    finish_reason = "stop"
    if isinstance(final_response, dict):
        finish_reason = str(final_response.get("status") or finish_reason)
    return collected_text.strip(), finish_reason


async def request_openai_codex_text(
    credentials: OpenAICodexCredentials, body: dict[str, Any], allow_refresh_retry: bool = True
) -> tuple[str, str]:
    headers = {
        "Authorization": f"Bearer {credentials.access_token}",
        "chatgpt-account-id": credentials.account_id,
        "OpenAI-Beta": "responses=experimental",
        "originator": _get_setting("ORIGINATOR", DEFAULT_OPENAI_CODEX_ORIGINATOR),
        "User-Agent": "PR-Agent",
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
    }

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_get_setting("TIMEOUT", 120))) as session:
        async with session.post(resolve_openai_codex_responses_url(), headers=headers, json=body) as response:
            if response.status == 401 and allow_refresh_retry:
                try:
                    refreshed = await refresh_openai_codex_credentials(credentials.refresh_token)
                except Exception:
                    clear_openai_codex_credentials()
                    raise ValueError(
                        "ChatGPT OAuth session expired and could not be refreshed. Run `pr-agent-chatgpt-auth login` again."
                    )
                return await request_openai_codex_text(refreshed, body, allow_refresh_retry=False)

            if response.status >= 400:
                raise ValueError(await parse_openai_codex_error(response))

            return await collect_openai_codex_text(response)
