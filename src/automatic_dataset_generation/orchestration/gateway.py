"""OpenAI-compatible LiteLLM/Qwen model provider configuration."""

from __future__ import annotations

import logging
import urllib.parse
from typing import Final

import httpx2
from openai import AsyncOpenAI, Timeout
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings

from automatic_dataset_generation.core.settings import AppSettings

_logger = logging.getLogger(__name__)

_DEFAULT_LOCAL_GATEWAY: Final[str] = "http://127.0.0.1:4000/v1"
_DUMMY_KEY_FOR_LOCAL_PROXY: Final[str] = "local-proxy-unauthenticated"
_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


class GatewayConfigurationError(ValueError):
    """Raised when LiteLLM gateway settings fail security or endpoint validation."""


def validate_gateway_endpoint(
    base_url: str | None,
    trusted_hosts: tuple[str, ...],
) -> str:
    """Validate that gateway endpoint URL is safe, scheme-restricted, and host-allowlisted.

    Parameters
    ----------
    base_url:
        Configured base URL string, or None to use default local gateway.
    trusted_hosts:
        Tuple of allowlisted hostnames or IP addresses. Must be non-empty.

    Returns
    -------
    str
        Validated URL string without credentials.

    Raises
    ------
    GatewayConfigurationError
        If scheme is not http/https, if userinfo/query/fragment is present,
        if HTTP is used for remote endpoints, or if host is not allowlisted.
    """
    if not trusted_hosts:
        raise GatewayConfigurationError("trusted_hosts allowlist must not be empty")

    url_to_check = (base_url or _DEFAULT_LOCAL_GATEWAY).strip()
    if not url_to_check:
        raise GatewayConfigurationError("Gateway base URL must not be empty")

    if "\x00" in url_to_check:
        raise GatewayConfigurationError("Gateway base URL must not contain NUL bytes")

    try:
        parsed = urllib.parse.urlsplit(url_to_check)
    except Exception as exc:
        raise GatewayConfigurationError("Malformed gateway base URL") from exc

    if parsed.scheme not in ("http", "https"):
        raise GatewayConfigurationError(
            f"Gateway URL scheme must be 'http' or 'https', got {parsed.scheme!r}"
        )

    if not parsed.hostname:
        raise GatewayConfigurationError("Gateway URL must specify a valid hostname")

    if parsed.username or parsed.password:
        raise GatewayConfigurationError(
            "Gateway URL must not contain embedded user credentials; "
            "supply gateway_api_key separately"
        )

    if parsed.query:
        raise GatewayConfigurationError("Gateway URL must not contain query parameters")

    if parsed.fragment:
        raise GatewayConfigurationError("Gateway URL must not contain URL fragments")

    host = parsed.hostname.rstrip(".").lower()
    if parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise GatewayConfigurationError(
            "Plaintext HTTP is only allowed for loopback hosts ('localhost', '127.0.0.1', '::1'); "
            "remote gateway endpoints must use HTTPS"
        )

    trusted_set = {h.rstrip(".").lower() for h in trusted_hosts}
    if host not in trusted_set:
        raise GatewayConfigurationError(
            f"Gateway host {host!r} is not in trusted allowlist: {sorted(trusted_set)}"
        )

    # Return normalized URL
    return url_to_check


def create_model_provider(
    settings: AppSettings | None = None,
    *,
    base_url: str | None = None,
    model_alias: str | None = None,
) -> OpenAIChatModel:
    """Create an OpenAI-compatible model provider pointing to a LiteLLM/Qwen gateway.

    Construction is deterministic, performs no network activity, and sets up
    hardened HTTP client configuration:
    - Bounded connect and read/write timeouts.
    - Explicit maximum retries at the transport layer (physical retries).
    - HTTP redirect following explicitly disabled (`follow_redirects=False`) to prevent SSRF.

    Note on retries:
    - Transport retries (`gateway_max_retries`) govern low-level network failures per request.
    - Logical turns (`agent_request_limit`) govern high-level agent reasoning / tool calling.

    Parameters
    ----------
    settings:
        Application settings instance. If omitted, default settings are loaded.
    base_url:
        Optional override for gateway URL.
    model_alias:
        Optional override for model alias.

    Returns
    -------
    OpenAIChatModel
        Configured PydanticAI model instance.
    """
    cfg = settings or AppSettings()

    effective_url = base_url or cfg.gateway_base_url
    validated_url = validate_gateway_endpoint(effective_url, cfg.gateway_trusted_hosts)

    effective_model = (model_alias or cfg.gateway_model_alias).strip()
    if not effective_model or "\x00" in effective_model:
        raise GatewayConfigurationError("Model alias must be a non-empty string without NUL bytes")

    api_key_str: str
    if cfg.gateway_api_key is not None:
        api_key_str = cfg.gateway_api_key.get_secret_value()
    else:
        # LiteLLM proxies frequently run keyless on internal networks or require a placeholder
        api_key_str = _DUMMY_KEY_FOR_LOCAL_PROXY

    connect_timeout = (
        cfg.gateway_connect_timeout_seconds
        if cfg.gateway_connect_timeout_seconds is not None
        else cfg.gateway_timeout_seconds
    )
    timeout_obj = Timeout(
        cfg.gateway_timeout_seconds,
        connect=connect_timeout,
    )

    http_client = httpx2.AsyncClient(
        timeout=timeout_obj,
        follow_redirects=False,
    )

    openai_client = AsyncOpenAI(
        base_url=validated_url,
        api_key=api_key_str,
        timeout=timeout_obj,
        max_retries=cfg.gateway_max_retries,
        http_client=http_client,
    )

    provider = OpenAIProvider(openai_client=openai_client)

    return OpenAIChatModel(
        model_name=effective_model,
        provider=provider,
    )


def build_model_settings(settings: AppSettings | None = None) -> ModelSettings:
    """Construct model execution settings from configuration."""
    cfg = settings or AppSettings()
    return ModelSettings(
        timeout=cfg.gateway_timeout_seconds,
        parallel_tool_calls=cfg.agent_parallel_tool_calls,
    )
