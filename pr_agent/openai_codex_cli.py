import argparse
import asyncio
from datetime import datetime, timezone

from pr_agent.algo.ai_handlers.openai_codex_session import (
    clear_openai_codex_credentials,
    complete_openai_codex_oauth,
    get_openai_codex_auth_status,
    start_openai_codex_oauth,
)


def _format_timestamp(timestamp_ms: int | None) -> str:
    if not timestamp_ms:
        return "n/a"
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    return dt.isoformat()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate PR-Agent against ChatGPT/Codex OAuth so you can use a ChatGPT subscription."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Start OAuth and store the resulting session.")
    login_parser.add_argument(
        "--input",
        dest="user_input",
        default="",
        help="Authorization callback URL, query string, or code. If omitted, you will be prompted interactively.",
    )

    subparsers.add_parser("status", help="Show the stored ChatGPT OAuth session status.")
    subparsers.add_parser("logout", help="Clear the stored ChatGPT OAuth session.")
    return parser


async def _run_login(user_input: str) -> int:
    oauth = await start_openai_codex_oauth()
    print("Open this URL in your browser and complete the ChatGPT sign-in flow:\n")
    print(oauth["authorize_url"])
    print("")

    if not user_input:
        user_input = input("Paste the full callback URL, query string, or authorization code: ").strip()

    credentials = await complete_openai_codex_oauth(user_input)
    print(f"Connected ChatGPT account {credentials.account_id}.")
    print(f"Session expires at {_format_timestamp(credentials.expires_at)}.")
    return 0


def _run_status() -> int:
    status = get_openai_codex_auth_status()
    if not status["connected"]:
        print("ChatGPT OAuth is not connected.")
        return 1

    print(f"Connected: yes")
    print(f"Account ID: {status['account_id']}")
    print(f"Expires at: {_format_timestamp(status['expires_at'])}")
    print(f"Expired: {'yes' if status['is_expired'] else 'no'}")
    return 0


def _run_logout() -> int:
    clear_openai_codex_credentials()
    print("ChatGPT OAuth session cleared.")
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "login":
        return asyncio.run(_run_login(args.user_input))
    if args.command == "status":
        return _run_status()
    if args.command == "logout":
        return _run_logout()
    raise ValueError(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
