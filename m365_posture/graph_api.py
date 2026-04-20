"""Microsoft Graph API integration using device code authentication.

Provides credential-free access to Secure Score data via the device code
OAuth2 flow. The user authenticates interactively in their browser -- no
client secrets are stored.

Required Azure AD app registration:
  - Register an app in Entra ID > App registrations
  - Set "Allow public client flows" to Yes
  - Add API permission: Microsoft Graph > SecurityEvents.Read.All (delegated)
  - Note the Application (client) ID
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlencode, urlparse, parse_qs

# Default scope for Secure Score read access
GRAPH_SCOPES = "https://graph.microsoft.com/SecurityEvents.Read.All offline_access"


def start_device_code_flow(tenant_id: str, client_id: str) -> dict:
    """Initiate the device code flow. Returns device code response.

    Response includes:
      - user_code: Code the user must enter
      - verification_uri: URL the user must visit
      - device_code: Internal code for polling (do not show to user)
      - interval: Polling interval in seconds
      - expires_in: Seconds until the code expires
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    data = urlencode({
        "client_id": client_id,
        "scope": GRAPH_SCOPES,
    }).encode()

    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            raise RuntimeError(err.get("error_description", body))
        except json.JSONDecodeError:
            raise RuntimeError(f"Device code request failed ({e.code}): {body}")


def poll_for_token(tenant_id: str, client_id: str, device_code: str) -> dict:
    """Poll once for the token. Returns token response or status.

    Returns dict with either:
      - "access_token" key on success
      - "error" key ("authorization_pending" or "slow_down") while waiting
      - "error" key with other value on failure
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urlencode({
        "client_id": client_id,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }).encode()

    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            return err  # Will contain "error": "authorization_pending" etc.
        except json.JSONDecodeError:
            return {"error": "unknown", "error_description": body}


def client_credentials_token(tenant_id: str, client_id: str, client_secret: str) -> dict:
    """Acquire an access token using the client credentials (app-only) flow.

    Requires an app registration with a client secret and
    **application** permission SecurityEvents.Read.All (admin-consented).

    Returns the full token response dict including ``access_token``.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()

    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            raise RuntimeError(err.get("error_description", body))
        except json.JSONDecodeError:
            raise RuntimeError(f"Client credentials auth failed ({e.code}): {body}")


# ── Interactive Browser Auth (Authorization Code + PKCE) ──

def start_interactive_auth(tenant_id: str, client_id: str,
                           redirect_port: int = 8400) -> dict:
    """Start the interactive browser-based OAuth2 Authorization Code flow with PKCE.

    Returns a dict with:
      - auth_url: URL to open in the browser
      - state: CSRF state value
      - code_verifier: PKCE code verifier (needed to exchange code for token)
      - redirect_uri: The local redirect URI
    """
    # Generate PKCE code verifier and challenge
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)

    redirect_uri = f"http://localhost:{redirect_port}/auth/callback"
    params = urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": GRAPH_SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    })
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?{params}"

    return {
        "auth_url": auth_url,
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "redirect_port": redirect_port,
    }


def exchange_auth_code(tenant_id: str, client_id: str, code: str,
                       code_verifier: str, redirect_uri: str) -> dict:
    """Exchange an authorization code for an access token (PKCE flow)."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urlencode({
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }).encode()

    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
            raise RuntimeError(err.get("error_description", body))
        except json.JSONDecodeError:
            raise RuntimeError(f"Token exchange failed ({e.code}): {body}")


# Store pending interactive auth sessions (keyed by state)
_interactive_sessions: dict = {}


def wait_for_auth_callback(state: str, timeout: int = 300) -> dict | None:
    """Wait for the auth callback to arrive. Returns the session data or None on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        session = _interactive_sessions.get(state)
        if session and session.get("code"):
            return session
        if session and session.get("error"):
            return session
        time.sleep(1)
    return None


def fetch_secure_scores(access_token: str) -> dict:
    """Fetch the latest Secure Score data from Microsoft Graph.

    Calls GET /security/secureScores?$top=1 to get the most recent score.
    """
    url = "https://graph.microsoft.com/v1.0/security/secureScores?$top=1"
    req = Request(url)
    req.add_header("Authorization", f"Bearer {access_token}")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        body = e.read().decode()
        if e.code == 403:
            raise RuntimeError(
                f"Graph API error 403: {body}\n\n"
                "This usually means the app registration is missing the required "
                "permissions. To fix:\n"
                "1. In Entra ID > App registrations > your app > API permissions\n"
                "2. Add Microsoft Graph > Application permission > "
                "SecurityEvents.Read.All\n"
                "3. Click 'Grant admin consent' for your tenant\n"
                "Note: For client-credentials (app-only) auth you need "
                "*Application* permissions, not Delegated."
            )
        raise RuntimeError(f"Graph API error ({e.code}): {body}")


def fetch_control_profiles(access_token: str) -> dict:
    """Fetch ALL Secure Score control profiles from Microsoft Graph.

    Handles pagination via @odata.nextLink to ensure every profile is returned.
    Calls GET /security/secureScoreControlProfiles.
    """
    all_profiles = []
    url = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=200"

    while url:
        req = Request(url)
        req.add_header("Authorization", f"Bearer {access_token}")

        try:
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except HTTPError as e:
            body = e.read().decode()
            if e.code == 403:
                raise RuntimeError(
                    f"Graph API error 403: {body}\n\n"
                    "This usually means the app registration is missing the "
                    "required permissions. To fix:\n"
                    "1. In Entra ID > App registrations > your app > "
                    "API permissions\n"
                    "2. Add Microsoft Graph > Application permission > "
                    "SecurityEvents.Read.All\n"
                    "3. Click 'Grant admin consent' for your tenant\n"
                    "Note: For client-credentials (app-only) auth you need "
                    "*Application* permissions, not Delegated."
                )
            raise RuntimeError(f"Graph API error ({e.code}): {body}")

        all_profiles.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    return {"value": all_profiles}
