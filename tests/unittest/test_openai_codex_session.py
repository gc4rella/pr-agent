import base64
import json

from pr_agent.algo.ai_handlers.openai_codex_session import (
    OpenAICodexCredentials,
    build_openai_codex_authorize_url,
    clear_openai_codex_credentials,
    extract_openai_codex_account_id_from_token,
    extract_text_from_openai_codex_response,
    parse_openai_codex_authorization_input,
    save_openai_codex_credentials,
)
from pr_agent.config_loader import get_settings


def _jwt_with_account(account_id: str) -> str:
    payload = {
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
        }
    }
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"header.{payload_encoded}.signature"


def test_build_openai_codex_authorize_url_contains_expected_parameters():
    url = build_openai_codex_authorize_url(state="state-123", challenge="challenge-123")

    assert url.startswith("https://auth.openai.com/oauth/authorize?")
    assert "client_id=app_EMoamEEZ73f0CkXaXp7hrann" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback" in url
    assert "state=state-123" in url
    assert "code_challenge=challenge-123" in url


def test_extract_openai_codex_account_id_from_token():
    token = _jwt_with_account("workspace_123")
    assert extract_openai_codex_account_id_from_token(token) == "workspace_123"


def test_parse_openai_codex_authorization_input_supports_callback_url():
    parsed = parse_openai_codex_authorization_input(
        "http://localhost:1455/auth/callback?code=abc123&state=xyz987"
    )

    assert parsed["code"] == "abc123"
    assert parsed["state"] == "xyz987"


def test_parse_openai_codex_authorization_input_supports_fragment_query():
    parsed = parse_openai_codex_authorization_input(
        "http://localhost:1455/auth/callback#code=abc123&state=xyz987"
    )

    assert parsed["code"] == "abc123"
    assert parsed["state"] == "xyz987"


def test_extract_text_from_openai_codex_response():
    response = {
        "output": [
            {
                "content": [
                    {"type": "output_text", "text": "hello "},
                    {"type": "message_text", "text": {"value": "world"}},
                ]
            }
        ]
    }

    assert extract_text_from_openai_codex_response(response) == "hello world"


def test_save_and_clear_openai_codex_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("PR_AGENT_OPENAI_CODEX_SECRETS_FILE", str(tmp_path / ".secrets_openai_codex.toml"))
    settings = get_settings()
    clear_openai_codex_credentials()

    credentials = OpenAICodexCredentials(
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=123456789,
        account_id="workspace_123",
    )
    save_openai_codex_credentials(credentials)

    assert settings.get("OPENAI_CODEX.ACCESS_TOKEN") == "access-token"
    assert settings.get("OPENAI_CODEX.REFRESH_TOKEN") == "refresh-token"
    assert settings.get("OPENAI_CODEX.EXPIRES_AT") == 123456789
    assert settings.get("OPENAI_CODEX.ACCOUNT_ID") == "workspace_123"
    assert (tmp_path / ".secrets_openai_codex.toml").exists()

    clear_openai_codex_credentials()

    assert settings.get("OPENAI_CODEX.ACCESS_TOKEN") == ""
    assert settings.get("OPENAI_CODEX.REFRESH_TOKEN") == ""
    assert settings.get("OPENAI_CODEX.ACCOUNT_ID") == ""
    assert not (tmp_path / ".secrets_openai_codex.toml").exists()
