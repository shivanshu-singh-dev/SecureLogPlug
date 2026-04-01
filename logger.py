"""CLI interface for SecureLogPlug."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from tamperlog import SecureLogPlug


SECRET_REQUIRED_ERROR = (
    "Error: Secret key is required for SecureLogPlug. "
    "Provide via --secret or SECURELOGPLUG_SECRET."
)


def parse_metadata(metadata_str: str | None) -> dict[str, Any] | None:
    """Parse metadata JSON object if provided."""
    if not metadata_str:
        return None
    parsed = json.loads(metadata_str)
    if not isinstance(parsed, dict):
        raise ValueError("metadata must be a JSON object")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureLogPlug: tamper-evident logging with HMAC-SHA256")
    parser.add_argument(
        "--secret",
        default=None,
        help="HMAC secret key (or set SECURELOGPLUG_SECRET env var)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add a new log entry")
    add_parser.add_argument("event_type", help="Event type (e.g. LOGIN)")
    add_parser.add_argument("description", help="Description text")
    add_parser.add_argument(
        "--metadata",
        help='Optional metadata JSON, e.g. --metadata "{\"ip\":\"127.0.0.1\"}"',
    )

    subparsers.add_parser("verify", help="Verify the log chain")

    view_parser = subparsers.add_parser("view", help="View stored logs")
    view_parser.add_argument("--verify", action="store_true", help="Show verification status")

    return parser


def resolve_secret(cli_secret: str | None) -> str | None:
    """Resolve secret key from CLI or environment."""
    return cli_secret if cli_secret is not None else os.getenv("SECURELOGPLUG_SECRET")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    secret = resolve_secret(args.secret)
    if secret is None or not secret.strip():
        parser.error(SECRET_REQUIRED_ERROR)

    slog = SecureLogPlug(secret_key=secret)

    if args.command == "add":
        metadata = parse_metadata(args.metadata)
        entry = slog.add_log(args.event_type, args.description, metadata)
        print(f"Added log index={entry['index']} hash={entry['current_hash']}")

    elif args.command == "verify":
        result = slog.verify_logs()
        if not result.ok:
            raise SystemExit(1)

    elif args.command == "view":
        slog.view_logs(verify=args.verify)


if __name__ == "__main__":
    main()

