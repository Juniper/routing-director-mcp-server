import json
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import logging

from fastmcp.server.auth import TokenVerifier, AccessToken


logger = logging.getLogger(__name__)


class TokenManager:
    def __init__(self, tokens_file: str = ".tokens"):
        self.tokens_file = tokens_file

    def _load_tokens(self) -> Dict[str, Any]:
        """Load tokens from file, return empty dict if file doesn't exist"""
        if not os.path.exists(self.tokens_file):
            return {}
        try:
            with open(self.tokens_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            raise FileNotFoundError("Tokens file not found at path: %s" % self.tokens_file)

    def _save_tokens(self, tokens: Dict[str, Any]) -> None:
        with open(self.tokens_file, 'w') as f:
            json.dump(tokens, f, indent=2)

    def generate_token_string(self) -> str:
        random_part = secrets.token_urlsafe(24)
        return f"apa_{random_part}"

    def create_token(self, client_id: str, description: str = None) -> Optional[str]:
        tokens = self._load_tokens()
        if client_id in tokens:
            return None

        token = self.generate_token_string()
        tokens[client_id] = {
            "token": token,
            "description": description or f"Token for {client_id}",
            "created": datetime.now(timezone.utc).isoformat()
        }
        self._save_tokens(tokens)
        return token

    def revoke_token(self, client_id: str) -> bool:
        tokens = self._load_tokens()
        if client_id not in tokens:
            return False
        del tokens[client_id]
        self._save_tokens(tokens)
        return True

    def get_token_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        tokens = self._load_tokens()
        return tokens.get(client_id)

    def list_tokens(self) -> Dict[str, Any]:
        return self._load_tokens()

    def tokens_file_exists(self) -> bool:
        return os.path.exists(self.tokens_file)

    def has_tokens(self) -> bool:
        return bool(self._load_tokens())

    def get_verifier(self) -> TokenVerifier:
        return FileTokenVerifier(self)


class FileTokenVerifier(TokenVerifier):
    def __init__(self, manager: TokenManager):
        super().__init__()
        self.manager = manager
        self.base_url = None

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Validate if a token exists in the .tokens file.
        Reads the file on every request to ensure up-to-date validation.
        """
        tokens = self.manager.list_tokens()

        for client_id, token_data in tokens.items():
            if token_data.get('token') == token:
                return AccessToken(client_id=client_id, scopes=[], token=token)

        return None



def handle_generate_command(manager: TokenManager, client_id: str, description: Optional[str]):
    if not client_id:
        print("Error: 'client_id' is required for generate command")
        return

    token = manager.create_token(client_id, description)
    if token:
        print(f"Generated new token:")
        print(f"  ID: {client_id}")
        print(f"  Token: {token}")
        print(f"  Description: {description or 'No description'}")
        print(f"\nSave this token securely - it won't be shown again!")
    else:
        print(f"Error: Token ID '{client_id}' already exists")


def handle_list_command(manager: TokenManager):
    tokens = manager.list_tokens()
    if not tokens:
        print("No tokens found")
        return

    print(f"{'ID':<20} {'Description':<40} {'Created':<25}")
    print("-" * 85)
    for tid, tdata in tokens.items():
        created = tdata.get('created', 'Unknown')
        desc = tdata.get('description', 'No description')
        print(f"{tid:<20} {desc:<40} {created:<25}")


def handle_revoke_command(manager: TokenManager, client_id: str):
    if not client_id:
        print("Error: 'client_id' is required for revoke command")
        return

    if manager.revoke_token(client_id):
        print(f"Token '{client_id}' has been revoked")
    else:
        print(f"Error: Token ID '{client_id}' not found")


def handle_show_command(manager: TokenManager, client_id: str):
    if not client_id:
        print("Error: 'client_id' is required for show command")
        return

    info = manager.get_token_info(client_id)
    if info:
        print(f"Token ID: {client_id}")
        print(f"Token: {info['token']}")
        print(f"Description: {info.get('description', 'No description')}")
        print(f"Created: {info.get('created', 'Unknown')}")
    else:
        print(f"Error: Token ID '{client_id}' not found")
