# backend/app/core/curl_parser.py
"""Parse cURL commands to extract HTTP request configuration."""

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse


@dataclass
class CurlConfig:
    """Configuration extracted from a cURL command."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, Any]] = None
    raw_data: Optional[str] = None

    @property
    def base_url(self) -> str:
        """Get the base URL (scheme + host) without path."""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"


class CurlParseError(Exception):
    """Error raised when cURL parsing fails."""

    pass


def parse_curl(curl_command: str) -> CurlConfig:
    """
    Parse a cURL command string into a CurlConfig object.

    Supports common cURL flags:
        -X, --request: HTTP method
        -H, --header: Request headers
        -d, --data, --data-raw: Request body
        -u, --user: Basic auth (converted to Authorization header)

    Args:
        curl_command: The cURL command string to parse

    Returns:
        CurlConfig with extracted URL, method, headers, and data

    Raises:
        CurlParseError: If the command cannot be parsed

    Example:
        >>> config = parse_curl('''
        ...     curl -X POST https://api.example.com/chat \\
        ...     -H "Authorization: Bearer sk-xxx" \\
        ...     -H "Content-Type: application/json" \\
        ...     -d '{"message": "hello"}'
        ... ''')
        >>> config.url
        'https://api.example.com/chat'
        >>> config.method
        'POST'
        >>> config.headers
        {'Authorization': 'Bearer sk-xxx', 'Content-Type': 'application/json'}
        >>> config.data
        {'message': 'hello'}
    """
    # Normalize the command
    command = _normalize_command(curl_command)

    # Tokenize using shlex
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise CurlParseError(f"Failed to tokenize command: {e}")

    if not tokens:
        raise CurlParseError("Empty command")

    # Remove 'curl' if present
    if tokens[0].lower() == "curl":
        tokens = tokens[1:]

    if not tokens:
        raise CurlParseError("No arguments after 'curl'")

    # Parse tokens
    url: Optional[str] = None
    method = "GET"
    headers: Dict[str, str] = {}
    raw_data: Optional[str] = None

    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Method (-X, --request)
        if token in ("-X", "--request"):
            if i + 1 >= len(tokens):
                raise CurlParseError(f"Missing value after {token}")
            method = tokens[i + 1].upper()
            i += 2
            continue

        # Header (-H, --header)
        if token in ("-H", "--header"):
            if i + 1 >= len(tokens):
                raise CurlParseError(f"Missing value after {token}")
            header_value = tokens[i + 1]
            if ":" in header_value:
                key, value = header_value.split(":", 1)
                headers[key.strip()] = value.strip()
            i += 2
            continue

        # Data (-d, --data, --data-raw, --data-binary)
        if token in ("-d", "--data", "--data-raw", "--data-binary"):
            if i + 1 >= len(tokens):
                raise CurlParseError(f"Missing value after {token}")
            raw_data = tokens[i + 1]
            # If data is provided, default to POST
            if method == "GET":
                method = "POST"
            i += 2
            continue

        # Basic auth (-u, --user)
        if token in ("-u", "--user"):
            if i + 1 >= len(tokens):
                raise CurlParseError(f"Missing value after {token}")
            import base64

            credentials = tokens[i + 1]
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
            i += 2
            continue

        # Skip common flags we don't need
        if token in (
            "-v",
            "--verbose",
            "-s",
            "--silent",
            "-S",
            "--show-error",
            "-k",
            "--insecure",
            "-L",
            "--location",
            "-i",
            "--include",
            "-I",
            "--head",
            "--compressed",
        ):
            i += 1
            continue

        # Skip flags with values we don't need
        if token in (
            "-o",
            "--output",
            "-A",
            "--user-agent",
            "--connect-timeout",
            "--max-time",
            "-m",
            "--cookie",
            "-b",
            "--cookie-jar",
            "-c",
        ):
            i += 2
            continue

        # URL (anything that looks like a URL or doesn't start with -)
        if not token.startswith("-"):
            if _looks_like_url(token):
                url = token
            i += 1
            continue

        # Unknown flag - skip
        i += 1

    if not url:
        raise CurlParseError("No URL found in command")

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Parse JSON data if possible
    data: Optional[Dict[str, Any]] = None
    if raw_data:
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            # Not JSON, keep as raw string
            pass

    return CurlConfig(
        url=url,
        method=method,
        headers=headers,
        data=data,
        raw_data=raw_data,
    )


def _normalize_command(command: str) -> str:
    """Normalize a cURL command by handling line continuations and whitespace."""
    # Remove line continuations (backslash + newline)
    command = re.sub(r"\\\s*\n", " ", command)
    # Replace multiple whitespace with single space
    command = re.sub(r"\s+", " ", command)
    # Strip leading/trailing whitespace
    command = command.strip()
    return command


def _looks_like_url(token: str) -> bool:
    """Check if a token looks like a URL."""
    # Has scheme
    if token.startswith(("http://", "https://")):
        return True
    # Has common TLD or localhost
    if re.search(r"\.(com|org|net|io|dev|app|co|ai|localhost|local)(/|$|:)", token):
        return True
    # Has port number
    if re.search(r":\d+(/|$)", token):
        return True
    # Has path
    if "/" in token and "." in token.split("/")[0]:
        return True
    return False
