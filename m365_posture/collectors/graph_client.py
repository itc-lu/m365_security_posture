"""Microsoft Graph API client for retrieving Secure Score and other security data."""

from __future__ import annotations

import json
import subprocess
import sys
import webbrowser
from typing import Optional
from urllib.parse import urlencode

from ..models import TenantConfig


class GraphClient:
    """Client for Microsoft Graph API with app and interactive auth."""

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    AUTH_BASE = "https://login.microsoftonline.com"
    SCOPE = "https://graph.microsoft.com/.default"

    def __init__(self, config: TenantConfig):
        self.config = config
        self._token: Optional[str] = None

    def authenticate(self) -> str:
        """Authenticate and return access token."""
        if self.config.use_interactive:
            return self._interactive_auth()
        else:
            return self._app_auth()

    def _app_auth(self) -> str:
        """Authenticate using client credentials (app registration)."""
        try:
            import requests
        except ImportError:
            raise ImportError("Install 'requests' package: pip install requests")

        tenant_id = self.config.tenant_id
        url = f"{self.AUTH_BASE}/{tenant_id}/oauth2/v2.0/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "scope": self.SCOPE,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        elif self.config.certificate_path:
            raise NotImplementedError(
                "Certificate-based auth requires the 'msal' library. "
                "Install it with: pip install msal"
            )
        else:
            raise ValueError("No client_secret or certificate_path configured")

        resp = requests.post(url, data=data)
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _interactive_auth(self) -> str:
        """Authenticate using device code flow."""
        try:
            import msal
        except ImportError:
            raise ImportError(
                "Install 'msal' package for interactive auth: pip install msal"
            )

        app = msal.PublicClientApplication(
            self.config.client_id or "14d82eec-204b-4c2f-b7e8-296a70dab67e",
            authority=f"{self.AUTH_BASE}/{self.config.tenant_id or 'common'}",
        )

        flow = app.initiate_device_flow(
            scopes=["https://graph.microsoft.com/SecurityEvents.Read.All"]
        )
        if "user_code" not in flow:
            raise ValueError(f"Failed to create device flow: {flow}")

        print(f"\nTo sign in, visit: {flow['verification_uri']}")
        print(f"Enter code: {flow['user_code']}\n")

        result = app.acquire_token_by_device_flow(flow)
        if "access_token" in result:
            self._token = result["access_token"]
            return self._token
        raise ValueError(f"Authentication failed: {result.get('error_description', 'Unknown error')}")

    def _get(self, endpoint: str) -> dict:
        """Make an authenticated GET request to Graph API."""
        try:
            import requests
        except ImportError:
            raise ImportError("Install 'requests' package: pip install requests")

        if not self._token:
            self.authenticate()

        url = f"{self.GRAPH_BASE}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def get_secure_scores(self, top: int = 1) -> dict:
        """Retrieve Secure Score data from MS Graph."""
        return self._get(f"security/secureScores?$top={top}")

    def get_secure_score_profiles(self) -> dict:
        """Retrieve Secure Score control profiles."""
        return self._get("security/secureScoreControlProfiles")

    def fetch_and_save(self, output_path: str) -> str:
        """Fetch Secure Score and save to JSON file."""
        data = self.get_secure_scores(top=1)
        profiles = {}
        try:
            profiles = self.get_secure_score_profiles()
        except Exception:
            pass  # Profiles are optional enrichment

        combined = {
            "secureScores": data,
            "controlProfiles": profiles,
        }

        with open(output_path, "w") as f:
            json.dump(combined, f, indent=2)

        return output_path
