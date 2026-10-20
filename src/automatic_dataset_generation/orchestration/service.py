"""Execution coordination and application-level error handling for agent orchestration."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from typing import TYPE_CHECKING, Final

from pydantic import ValidationError
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

from automatic_dataset_generation.core.settings import AppSettings
from automatic_dataset_generation.orchestration.agent import (
    AgentDependencies,
    create_database_agent,
    validate_agent_tool_registry,
)
from automatic_dataset_generation.orchestration.contracts import (
    AgentExecutionContext,
    DatabaseAgentRequest,
    DatabaseAgentRunResult,
    DatabaseUnderstandingResponse,
    SafeAgentUsage,
)
from automatic_dataset_generation.orchestration.secure_tools import SecureDatabaseTools

if TYPE_CHECKING:
    from pydantic_ai import Agent

_logger = logging.getLogger(__name__)

_JSON_BLOCK_RE: Final[re.Pattern[str]] = re.compile(r"\{.*\}", re.DOTALL)
_MAX_FALLBACK_TEXT_CHARS: Final[int] = 50_000


class DatabaseAgentService:
    """Coordinates bounded, secure asynchronous execution of the database understanding agent."""

    __slots__ = ("_agent", "_settings", "_tools")

    def __init__(
        self,
        tools: SecureDatabaseTools,
        *,
        agent: Agent[AgentDependencies, DatabaseUnderstandingResponse] | None = None,
        settings: AppSettings | None = None,
    ) -> None:
        if not isinstance(tools, SecureDatabaseTools):
            raise TypeError("tools must be SecureDatabaseTools")

        self._tools = tools
        self._settings = settings or AppSettings()
        self._agent = agent or create_database_agent(settings=self._settings)

        # Finding 7: Validate tool registry at service boundary
        validate_agent_tool_registry(self._agent, allow_custom_agent=True)

    async def run(
        self,
        request: DatabaseAgentRequest,
    ) -> DatabaseAgentRunResult:
        """Execute one bounded agent understanding run against an enterprise database.

        Parameters
        ----------
        request:
            Validated, bounded user request.

        Returns
        -------
        DatabaseAgentRunResult
            Complete, safe execution result including structured response, usage, and audit log.
        """
        if not isinstance(request, DatabaseAgentRequest):
            raise TypeError("request must be DatabaseAgentRequest")

        context = AgentExecutionContext(request=request)
        deps = AgentDependencies(tools=self._tools, context=context)

        usage_limits = UsageLimits(
            request_limit=self._settings.agent_request_limit,
            tool_calls_limit=self._settings.agent_tool_calls_limit,
            total_tokens_limit=self._settings.agent_total_tokens_limit,
            output_tokens_limit=self._settings.agent_output_tokens_limit,
        )

        context.record_audit("run:started")

        response: DatabaseUnderstandingResponse
        safe_usage = SafeAgentUsage()

        try:
            async with asyncio.timeout(self._settings.gateway_timeout_seconds):
                run_result = await self._agent.run(
                    request.user_prompt,
                    deps=deps,
                    usage_limits=usage_limits,
                )

            # Extract structured response
            response = run_result.output
            context.record_audit("run:completed")

            # Extract usage metrics safely from RunUsage object
            try:
                raw_usage = run_result.usage
                safe_usage = SafeAgentUsage(
                    requests=getattr(raw_usage, "requests", 0),
                    tool_calls=getattr(raw_usage, "tool_calls", 0),
                    input_tokens=getattr(raw_usage, "input_tokens", None),
                    output_tokens=getattr(raw_usage, "output_tokens", None),
                    total_tokens=getattr(raw_usage, "total_tokens", None),
                )
            except Exception:  # noqa: BLE001 — safe usage extraction cannot abort run.
                safe_usage = SafeAgentUsage()

        except TimeoutError:
            _logger.warning(
                "Agent run timed out after %s seconds",
                self._settings.gateway_timeout_seconds,
            )
            context.record_audit("run:timed_out")
            context.record_security_violation("timeout_budget_exceeded")
            response = DatabaseUnderstandingResponse(
                summary="Agent execution timed out while waiting for model or tool responses.",
                can_fulfill=False,
                security_notes=("The request exceeded the configured execution timeout budget.",),
            )

        except UsageLimitExceeded:
            _logger.warning("Agent run exceeded configured usage limits")
            context.record_audit("run:usage_limit_exceeded")
            context.record_security_violation("usage_limit_exceeded")
            response = DatabaseUnderstandingResponse(
                summary="Agent execution exceeded configured model request or tool call limits.",
                can_fulfill=False,
                security_notes=("The request exceeded configured resource budgets.",),
            )

        except asyncio.CancelledError:
            context.record_audit("run:cancelled")
            raise

        except (UnexpectedModelBehavior, ValidationError) as exc:
            _logger.warning(
                "Model output structured validation failure: %s",
                type(exc).__name__,
            )
            context.record_audit("run:validation_fallback")
            # Bounded fallback: attempt to recover structured JSON from model output text
            recovered = self._attempt_json_fallback(exc)
            if recovered is not None:
                response = recovered
            else:
                response = DatabaseUnderstandingResponse(
                    summary=(
                        "Model response could not be validated as DatabaseUnderstandingResponse."
                    ),
                    can_fulfill=False,
                    security_notes=("Model structured output schema validation failed.",),
                )

        except Exception as exc:  # noqa: BLE001
            # Finding 2: Safe exception logging without stack traces or raw messages
            incident_id = f"inc_{context.run_id[:8]}_{uuid.uuid4().hex[:8]}"
            _logger.error(  # noqa: TRY400
                "Agent execution encountered an unhandled error [incident=%s, error_type=%s]",
                incident_id,
                type(exc).__name__,
            )
            context.record_audit(f"run:error:{incident_id}")
            response = DatabaseUnderstandingResponse(
                summary="An unexpected error occurred during database understanding.",
                can_fulfill=False,
                security_notes=(
                    f"Operation terminated due to an internal execution error [ref={incident_id}].",
                ),
            )

        return DatabaseAgentRunResult(
            run_id=context.run_id,
            response=response,
            usage=safe_usage,
            audit_events=tuple(context.audit_events),
        )

    def _attempt_json_fallback(
        self,
        exc: Exception | str,
    ) -> DatabaseUnderstandingResponse | None:
        """Attempt bounded fallback parsing of JSON if model generated text rather than schema."""
        if isinstance(exc, str):
            raw_text = exc
        else:
            raw_text = getattr(exc, "output", None) or getattr(exc, "body", None) or str(exc)
        if not raw_text or len(raw_text) > _MAX_FALLBACK_TEXT_CHARS:
            return None

        match = _JSON_BLOCK_RE.search(raw_text)
        if not match:
            return None

        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return DatabaseUnderstandingResponse.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError):
            pass

        return None
