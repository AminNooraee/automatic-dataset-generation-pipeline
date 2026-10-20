"""Restricted database capability facade enforcing Phase 3E, 3F, and final boundary revalidation."""

from __future__ import annotations

import json
import logging
import math
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from fastmcp.exceptions import ToolError

from automatic_dataset_generation.database.adapter import DatabaseAdapter
from automatic_dataset_generation.database.errors import (
    DatabaseAdapterError,
    DatabaseObjectNotFoundError,
)
from automatic_dataset_generation.orchestration.contracts import (
    SafeColumnInfo,
    SafeRelationshipInfo,
    SafeRowCountResult,
    SafeSampleResponse,
    SafeScalar,
    SafeServerInfo,
    SafeTableDescription,
    SafeTableInfo,
    is_valid_database_identifier_syntax,
)
from automatic_dataset_generation.security.leakage import (
    _AUTH_HEADER_RE,
    _CARD_CANDIDATE_RE,
    _CARD_MAX_DIGITS,
    _CARD_MIN_DIGITS,
    _EMAIL_EMBEDDED_RE,
    _IBAN_CANDIDATE_RE,
    _INTL_PHONE_RE,
    _JWT_RE,
    _MASKED_MARKER,
    _PHONE_CANDIDATE_RE,
    _PRIVATE_KEY_RE,
    _PSEUDONYM_PATTERN,
    _REDACTED_MARKER,
    _SSN_RE,
    _UNICODE_FORMAT_CHARS_RE,
    LeakageValidationError,
    LeakageValidator,
    _has_connection_string_with_password,
    _is_iban,
    _luhn_valid,
)
from automatic_dataset_generation.security.sanitizer import (
    SanitizationOrchestrator,
    SanitizationOrchestratorError,
)

if TYPE_CHECKING:
    from automatic_dataset_generation.database.models import (
        DatabaseServerInfo,
        RelationshipInfo,
        SampleResult,
        TableDescription,
        TableInfo,
    )
    from automatic_dataset_generation.security.sanitizer import SanitizationResult

_logger = logging.getLogger(__name__)

_MAX_IDENTIFIER_LENGTH: Final[int] = 256
_MAX_TEXT_CHARS: Final[int] = 16_384
_MAX_TOTAL_CHARS: Final[int] = 1_000_000

_MIN_RESULT_SIZE: Final[int] = 1_000
_ASCII_CONTROL_LIMIT: Final[int] = 32
_ASCII_DEL: Final[int] = 127

_ABSOLUTE_MAX_SAMPLE_ROWS: Final[int] = 25
_ABSOLUTE_MAX_SAMPLE_COLUMNS: Final[int] = 128
_ABSOLUTE_MAX_RESULT_SIZE: Final[int] = 500_000
_ABSOLUTE_MAX_METADATA_ITEMS: Final[int] = 500
_MAX_VERSION_LENGTH: Final[int] = 128

_PROMPT_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+|any\s+)?"
        r"(?:previous|prior|above|existing|system)\s+(?:instructions|prompts|rules|commands|directives)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:system\s+prompt|system\s+message|system\s+instruction|system\s+override)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:you\s+are\s+now|act\s+as\s+a|pretend\s+to\s+be|jailbreak|developer\s+mode)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:output\s+the\s+(?:following|password|secret|key|token|prompt))",
        re.IGNORECASE,
    ),
    re.compile(r"(?:new\s+instructions?:|instruction\s+injection)", re.IGNORECASE),
    re.compile(
        r"(?:do\s+not\s+follow|stop\s+following)\s+(?:the\s+)?(?:rules|instructions|system)",
        re.IGNORECASE,
    ),
)


_CREDENTIAL_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s{,;&?_])"
    r"[\"']?(?:password|passwd|pwd|passphrase|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"client[_-]?secret|credentials?|connection[_-]?string)[\"']?"
    r"\s*(?:=|:)\s*([\"']?[^\"\r\n\s,;&}{]+[\"']?)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[\s{,;&?_])[\"']?(?:secret|private[_-]?key|secret[_-]?key|"
    r"signing[_-]?key|encryption[_-]?key)[\"']?"
    r"\s*(?:=|:)\s*([\"']?[^\"\r\n\s,;&}{]+[\"']?)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SecureDatabasePolicy:
    """Configurable and strictly bounded limits for the secure database capability facade."""

    max_sample_rows: int = 25
    max_sample_columns: int = 128
    max_result_size_chars: int = 50_000
    max_metadata_items: int = 200

    def __post_init__(self) -> None:
        if not (1 <= self.max_sample_rows <= _ABSOLUTE_MAX_SAMPLE_ROWS):
            msg = (
                f"max_sample_rows must be between 1 and {_ABSOLUTE_MAX_SAMPLE_ROWS}, "
                f"got {self.max_sample_rows}"
            )
            raise ValueError(msg)
        if not (1 <= self.max_sample_columns <= _ABSOLUTE_MAX_SAMPLE_COLUMNS):
            msg = (
                f"max_sample_columns must be between 1 and {_ABSOLUTE_MAX_SAMPLE_COLUMNS}, "
                f"got {self.max_sample_columns}"
            )
            raise ValueError(msg)
        if not (_MIN_RESULT_SIZE <= self.max_result_size_chars <= _ABSOLUTE_MAX_RESULT_SIZE):
            msg = (
                f"max_result_size_chars must be between {_MIN_RESULT_SIZE} and "
                f"{_ABSOLUTE_MAX_RESULT_SIZE}, got {self.max_result_size_chars}"
            )
            raise ValueError(msg)
        if not (1 <= self.max_metadata_items <= _ABSOLUTE_MAX_METADATA_ITEMS):
            msg = (
                f"max_metadata_items must be between 1 and {_ABSOLUTE_MAX_METADATA_ITEMS}, "
                f"got {self.max_metadata_items}"
            )
            raise ValueError(msg)


def _safe_tool_error(message: str) -> ToolError:
    """Create a detached ToolError without sensitive context or cause."""
    err = ToolError(message)
    err.__context__ = None
    err.__cause__ = None
    return err


def canonicalize_metadata_text(text: str, max_passes: int = 2) -> str:
    """Bounded canonicalization stripping Unicode format characters, applying NFKC,
    and performing bounded multi-pass percent-decoding."""
    cur = _UNICODE_FORMAT_CHARS_RE.sub("", text)
    cur = unicodedata.normalize("NFKC", cur)
    for _ in range(max_passes):
        if "%" not in cur:
            break
        try:
            unquoted = urllib.parse.unquote(cur, errors="replace")
            if unquoted == cur:
                break
            cur = _UNICODE_FORMAT_CHARS_RE.sub("", unquoted)
            cur = unicodedata.normalize("NFKC", cur)
        except Exception:  # noqa: BLE001
            break
    return cur


def scan_text_for_residual_secrets(text: str) -> bool:  # noqa: PLR0911, PLR0912
    """Scan text for residual secrets and sensitive PII using authoritative Phase 3F rules."""
    if _has_connection_string_with_password(text):
        return True
    if _PRIVATE_KEY_RE.search(text):
        return True
    if _AUTH_HEADER_RE.search(text):
        return True
    if _JWT_RE.search(text):
        return True

    for cred_match in _CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        val = cred_match.group(1).strip("\"' ")
        if val not in (_REDACTED_MARKER, _MASKED_MARKER):
            return True

    for secret_match in _SECRET_ASSIGNMENT_RE.finditer(text):
        val = secret_match.group(1).strip("\"' ")
        if val not in (_REDACTED_MARKER, _MASKED_MARKER):
            return True

    if _EMAIL_EMBEDDED_RE.search(text):
        return True

    for phone_match in _PHONE_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[\s\-().]", "", phone_match.group(0))
        if _INTL_PHONE_RE.fullmatch(digits):
            return True

    for card_match in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[\s-]", "", card_match.group(0))
        if (
            _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS
            and digits.isdigit()
            and _luhn_valid(digits)
        ):
            return True

    for iban_match in _IBAN_CANDIDATE_RE.finditer(text):
        clean_iban = re.sub(r"\s", "", iban_match.group(0)).upper()
        if _is_iban(clean_iban):
            return True

    return bool(_SSN_RE.search(text))


def has_instruction_injection(text: str) -> bool:
    """Return True if text matches known prompt injection or instruction patterns."""
    return any(p.search(text) for p in _PROMPT_INJECTION_PATTERNS)


def is_safe_metadata_text(value: object, max_length: int = 512) -> bool:
    """Verify that a metadata text field is safe for LLM prompt exposure.

    Checks both original and canonicalized representations for residual secrets,
    credentials, and prompt-injection/instruction patterns.
    """
    if not isinstance(value, str):
        return False
    trimmed = value.strip()
    if not trimmed or len(trimmed) > max_length:
        return False
    if "\x00" in trimmed or "\r" in trimmed or "\n" in trimmed:
        return False
    if any(ord(c) < _ASCII_CONTROL_LIMIT or ord(c) == _ASCII_DEL for c in trimmed):
        return False

    # Check original representation
    if scan_text_for_residual_secrets(trimmed) or has_instruction_injection(trimmed):
        return False

    # Check canonicalized representation
    canon = canonicalize_metadata_text(trimmed)
    return not (
        canon != trimmed
        and (scan_text_for_residual_secrets(canon) or has_instruction_injection(canon))
    )


def is_safe_metadata_identifier(value: object) -> bool:
    """Verify that an identifier string is safe for LLM prompt exposure.

    Validates identifier syntax (allowing legitimate Unicode, spaces, $, etc.,
    while forbidding SQL injection punctuation like ';', '--', '/*') and ensures
    it satisfies the authoritative metadata security policy.
    """
    if not isinstance(value, str):
        return False
    trimmed = value.strip()
    if not is_valid_database_identifier_syntax(trimmed):
        return False
    return is_safe_metadata_text(trimmed, max_length=_MAX_IDENTIFIER_LENGTH)


def validate_model_visible_response(
    response: object,
    max_size_chars: int,
) -> None:
    """Validate that the complete model-visible serialized tool response satisfies
    size limits and contains no residual secrets or prompt-injection markers."""
    if hasattr(response, "model_dump_json"):
        serialized = response.model_dump_json()
    else:
        serialized = json.dumps(response, default=str)

    if len(serialized) > max_size_chars:
        msg = (
            f"Database tool response size ({len(serialized)} chars) "
            f"exceeds maximum allowed limit ({max_size_chars} chars)"
        )
        raise _safe_tool_error(msg)

    # Check complete serialized string for secrets and injections
    if scan_text_for_residual_secrets(serialized):
        raise _safe_tool_error("Database tool response rejected by secret leakage policy")
    if has_instruction_injection(serialized):
        raise _safe_tool_error("Database tool response rejected by instruction injection policy")

    canon = canonicalize_metadata_text(serialized)
    if canon != serialized:
        if scan_text_for_residual_secrets(canon):
            raise _safe_tool_error(
                "Database tool response rejected by canonicalized secret leakage policy"
            )
        if has_instruction_injection(canon):
            raise _safe_tool_error(
                "Database tool response rejected by canonicalized instruction injection policy"
            )


def final_revalidate_sample(  # noqa: PLR0911, PLR0912, PLR0915
    sample_obj: object,
    *,
    max_cells: int = 100_000,
    max_text_chars: int = _MAX_TEXT_CHARS,
    max_total_text_chars: int = _MAX_TOTAL_CHARS,
) -> tuple[tuple[str, ...], tuple[tuple[SafeScalar, ...], ...], str, str] | None:
    """Perform mandatory independent revalidation at final prompt boundary.

    ADR 0014: ValidatedSample protects against pipeline miswiring but is not an unforgeable
    authorization token. This function re-inspects the exact snapshot structure, version metadata,
    and all cell values using authoritative Phase 3F checks.
    """
    if sample_obj is None:
        return None

    # Check required attributes
    for attr in (
        "schema_name",
        "table_name",
        "columns",
        "rows",
        "row_count",
        "policy_version",
        "validator_version",
    ):
        if not hasattr(sample_obj, attr):
            return None

    schema_name = getattr(sample_obj, "schema_name", None)
    table_name = getattr(sample_obj, "table_name", None)
    policy_version = getattr(sample_obj, "policy_version", None)
    validator_version = getattr(sample_obj, "validator_version", None)
    columns_obj = getattr(sample_obj, "columns", None)
    rows_obj = getattr(sample_obj, "rows", None)
    row_count = getattr(sample_obj, "row_count", None)

    # Validate versions: non-empty strings, no NUL bytes, max length bounded
    if (
        not isinstance(policy_version, str)
        or not policy_version.strip()
        or "\x00" in policy_version
        or len(policy_version) > _MAX_VERSION_LENGTH
    ):
        return None
    if (
        not isinstance(validator_version, str)
        or not validator_version.strip()
        or "\x00" in validator_version
        or len(validator_version) > _MAX_VERSION_LENGTH
    ):
        return None

    # Validate identifiers
    if not is_safe_metadata_identifier(schema_name) or not is_safe_metadata_identifier(table_name):
        return None

    if not isinstance(columns_obj, tuple) or not columns_obj:
        return None
    columns = tuple(str(c) for c in columns_obj)
    if len(set(columns)) != len(columns) or not all(
        is_safe_metadata_identifier(c) for c in columns
    ):
        return None

    if not isinstance(rows_obj, tuple) or not isinstance(row_count, int) or row_count < 0:
        return None
    if len(rows_obj) != row_count:
        return None

    col_count = len(columns)
    total_cells = 0
    total_chars = 0
    revalidated_rows: list[tuple[SafeScalar, ...]] = []

    for row_obj in rows_obj:
        if not isinstance(row_obj, tuple) or len(row_obj) != col_count:
            return None
        reval_row: list[SafeScalar] = []
        for cell_val in row_obj:
            total_cells += 1
            if total_cells > max_cells:
                return None

            # EXACT scalar types check
            cell_type = type(cell_val)
            if cell_val is None:
                reval_row.append(None)
                continue
            if cell_type is bool:
                reval_row.append(cell_val)
                continue
            if cell_type is int:
                reval_row.append(cell_val)
                continue
            if cell_type is float:
                if not math.isfinite(cell_val):
                    return None
                reval_row.append(cell_val)
                continue
            if cell_type is str:
                # String cell validation
                if len(cell_val) > max_text_chars or "\x00" in cell_val:
                    return None
                total_chars += len(cell_val)
                if total_chars > max_total_text_chars:
                    return None

                # Accepted safe markers
                if cell_val in (_REDACTED_MARKER, _MASKED_MARKER) or _PSEUDONYM_PATTERN.fullmatch(
                    cell_val
                ):
                    reval_row.append(cell_val)
                    continue

                # Residual secrets & leakage scan on raw and canonicalized
                if scan_text_for_residual_secrets(cell_val):
                    return None
                canon = canonicalize_metadata_text(cell_val)
                if canon != cell_val and scan_text_for_residual_secrets(canon):
                    return None

                reval_row.append(cell_val)
                continue

            # Non-scalar types (date, datetime, list, dict, custom object) -> reject!
            return None

        revalidated_rows.append(tuple(reval_row))

    return columns, tuple(revalidated_rows), policy_version, validator_version


class SecureDatabaseTools:
    """Trusted security facade providing constrained read-only database operations to the agent."""

    __slots__ = (
        "_adapter",
        "_policy",
        "_sanitizer",
        "_validator",
    )

    def __init__(
        self,
        adapter: DatabaseAdapter,
        sanitizer: SanitizationOrchestrator,
        validator: LeakageValidator,
        *,
        policy: SecureDatabasePolicy | None = None,
    ) -> None:
        if not isinstance(adapter, DatabaseAdapter):
            raise TypeError("adapter must implement DatabaseAdapter")
        if not isinstance(sanitizer, SanitizationOrchestrator):
            raise TypeError("sanitizer must be SanitizationOrchestrator")
        if not isinstance(validator, LeakageValidator):
            raise TypeError("validator must be LeakageValidator")

        self._adapter = adapter
        self._sanitizer = sanitizer
        self._validator = validator
        self._policy = policy or SecureDatabasePolicy()

    async def get_database_metadata(self) -> SafeServerInfo:
        """Return safe database server metadata without credentials or host details."""
        err_msg: str | None = None
        info: DatabaseServerInfo | None = None
        try:
            info = await self._adapter.get_server_info()
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Database metadata operation failed"

        if err_msg is not None or info is None:
            raise _safe_tool_error(err_msg or "Database metadata operation failed") from None

        safe_version = None
        if info.version and is_safe_metadata_text(info.version):
            safe_version = info.version

        safe_database = None
        if info.database and is_safe_metadata_identifier(info.database):
            safe_database = info.database

        engine_val = info.engine.value
        if not is_safe_metadata_identifier(engine_val):
            raise _safe_tool_error("Invalid engine identifier in server info") from None

        res = SafeServerInfo(
            engine=engine_val,
            version=safe_version,
            database=safe_database,
        )
        validate_model_visible_response(res, self._policy.max_result_size_chars)
        return res

    async def list_schemas(self) -> tuple[str, ...]:
        """List database schema names visible to read-only access."""
        err_msg: str | None = None
        schemas: tuple[str, ...] = ()
        try:
            schemas = await self._adapter.list_schemas()
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Failed to list database schemas"

        if err_msg is not None:
            raise _safe_tool_error(err_msg) from None

        filtered = tuple(s for s in schemas if is_safe_metadata_identifier(s))
        bounded = filtered[: self._policy.max_metadata_items]
        validate_model_visible_response(bounded, self._policy.max_result_size_chars)
        return bounded

    async def list_tables(self, schema: str) -> tuple[SafeTableInfo, ...]:
        """List read-only tables and views in one schema."""
        if not is_safe_metadata_identifier(schema):
            raise _safe_tool_error("Invalid schema identifier") from None

        err_msg: str | None = None
        tables: tuple[TableInfo, ...] = ()
        try:
            tables = await self._adapter.list_tables(schema)
        except DatabaseObjectNotFoundError:
            err_msg = "Database schema is unavailable"
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Database tool operation failed"

        if err_msg is not None:
            raise _safe_tool_error(err_msg) from None

        res = tuple(
            SafeTableInfo(
                schema_name=t.schema_name,
                table_name=t.table_name,
                table_type=t.table_type,
            )
            for t in tables
            if is_safe_metadata_identifier(t.table_name)
            and is_safe_metadata_identifier(t.schema_name)
            and is_safe_metadata_text(t.table_type, max_length=64)
        )[: self._policy.max_metadata_items]

        validate_model_visible_response(res, self._policy.max_result_size_chars)
        return res

    async def describe_table(self, schema: str, table: str) -> SafeTableDescription:
        """Describe column metadata for one table."""
        if not is_safe_metadata_identifier(schema) or not is_safe_metadata_identifier(table):
            raise _safe_tool_error("Invalid database table identifier") from None

        err_msg: str | None = None
        desc: TableDescription | None = None
        try:
            desc = await self._adapter.describe_table(schema, table)
        except DatabaseObjectNotFoundError:
            err_msg = "Database table is unavailable"
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Database tool operation failed"

        if err_msg is not None or desc is None:
            raise _safe_tool_error(err_msg or "Database tool operation failed") from None

        if not is_safe_metadata_identifier(desc.schema_name) or not is_safe_metadata_identifier(
            desc.table_name
        ):
            raise _safe_tool_error("Invalid or unsafe table metadata returned by adapter") from None

        safe_columns = []
        for col in desc.columns:
            if not is_safe_metadata_identifier(col.name) or not is_safe_metadata_text(
                col.data_type, max_length=64
            ):
                continue
            def_val = getattr(col, "default_value", None)
            comment_val = getattr(col, "comment", None)
            safe_columns.append(
                SafeColumnInfo(
                    name=col.name,
                    data_type=col.data_type,
                    nullable=col.nullable,
                    primary_key=col.primary_key,
                    default_value=def_val if def_val and is_safe_metadata_text(def_val) else None,
                    comment=comment_val
                    if comment_val and is_safe_metadata_text(comment_val)
                    else None,
                )
            )

        bounded_columns = tuple(safe_columns[: self._policy.max_sample_columns])

        res = SafeTableDescription(
            schema_name=desc.schema_name,
            table_name=desc.table_name,
            columns=bounded_columns,
        )
        validate_model_visible_response(res, self._policy.max_result_size_chars)
        return res

    async def get_relationships(
        self, schema: str, table: str | None = None
    ) -> tuple[SafeRelationshipInfo, ...]:
        """Return relationship metadata constrained to a schema and optional table."""
        if not is_safe_metadata_identifier(schema):
            raise _safe_tool_error("Invalid schema identifier") from None
        if table is not None and not is_safe_metadata_identifier(table):
            raise _safe_tool_error("Invalid table identifier") from None

        err_msg: str | None = None
        rels: tuple[RelationshipInfo, ...] = ()
        try:
            rels = await self._adapter.get_relationships(schema, table)
        except DatabaseObjectNotFoundError:
            err_msg = "Database object is unavailable"
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Database tool operation failed"

        if err_msg is not None:
            raise _safe_tool_error(err_msg) from None

        res = tuple(
            SafeRelationshipInfo(
                source_schema=r.source_schema,
                source_table=r.source_table,
                source_column=r.source_column,
                target_schema=r.target_schema,
                target_table=r.target_table,
                target_column=r.target_column,
                constraint_name=r.constraint_name
                if r.constraint_name and is_safe_metadata_identifier(r.constraint_name)
                else None,
            )
            for r in rels
            if is_safe_metadata_identifier(r.source_schema)
            and is_safe_metadata_identifier(r.source_table)
            and is_safe_metadata_identifier(r.source_column)
            and is_safe_metadata_identifier(r.target_schema)
            and is_safe_metadata_identifier(r.target_table)
            and is_safe_metadata_identifier(r.target_column)
        )[: self._policy.max_metadata_items]

        validate_model_visible_response(res, self._policy.max_result_size_chars)
        return res

    async def get_row_count(self, schema: str, table: str) -> SafeRowCountResult:
        """Return exact row count for one table."""
        if not is_safe_metadata_identifier(schema) or not is_safe_metadata_identifier(table):
            raise _safe_tool_error("Invalid database table identifier") from None

        err_msg: str | None = None
        count = 0
        try:
            count = await self._adapter.get_row_count(schema, table)
        except DatabaseObjectNotFoundError:
            err_msg = "Database table is unavailable"
        except (DatabaseAdapterError, Exception):  # noqa: BLE001
            err_msg = "Database tool operation failed"

        if err_msg is not None:
            raise _safe_tool_error(err_msg) from None

        res = SafeRowCountResult(schema_name=schema, table_name=table, row_count=count)
        validate_model_visible_response(res, self._policy.max_result_size_chars)
        return res

    def _validate_sampling_args(
        self,
        schema: str,
        table: str,
        limit: int,
        columns: list[str] | None,
    ) -> tuple[tuple[str, ...] | None, str | None]:
        """Validate tool arguments for sampling; returns (columns_tuple, error_msg)."""
        if not is_safe_metadata_identifier(schema) or not is_safe_metadata_identifier(table):
            return None, "Invalid database identifiers supplied for sampling"

        max_rows = self._policy.max_sample_rows
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= max_rows:
            return None, f"Sample limit must be an integer between 1 and {max_rows}"

        if columns is None:
            return None, None

        max_cols = self._policy.max_sample_columns
        if not isinstance(columns, (list, tuple)) or not columns or len(columns) > max_cols:
            return None, f"Columns must be a non-empty list of at most {max_cols}"

        for c in columns:
            if not is_safe_metadata_identifier(c):
                return None, "Invalid column identifier requested"

        return tuple(columns), None

    async def sample_validated_rows(
        self,
        schema: str,
        table: str,
        limit: int = 10,
        columns: list[str] | None = None,
    ) -> SafeSampleResponse:
        """Retrieve sanitized, leakage-validated row samples. Raw data is never exposed."""
        cols_tuple, err = self._validate_sampling_args(schema, table, limit, columns)
        if err is not None:
            return SafeSampleResponse(
                status="rejected",
                message=err,
                schema_name=str(schema)[:_MAX_IDENTIFIER_LENGTH],
                table_name=str(table)[:_MAX_IDENTIFIER_LENGTH],
            )

        raw_sample = await self._fetch_raw_sample(schema, table, limit, cols_tuple)
        if isinstance(raw_sample, SafeSampleResponse):
            return raw_sample

        sanitization_result = self._run_sanitization(raw_sample, schema, table)
        if isinstance(sanitization_result, SafeSampleResponse):
            return sanitization_result

        return self._run_validation_and_packaging(
            sanitization_result,
            schema=schema,
            table=table,
            truncated=raw_sample.truncated,
        )

    async def _fetch_raw_sample(
        self,
        schema: str,
        table: str,
        limit: int,
        columns: tuple[str, ...] | None,
    ) -> SampleResult | SafeSampleResponse:
        """Fetch raw sample from database adapter in trusted code."""
        try:
            raw_sample = await self._adapter.sample_rows(
                schema, table, limit=limit, columns=columns
            )
        except DatabaseObjectNotFoundError:
            return SafeSampleResponse(
                status="error",
                message="Requested database table or columns do not exist",
                schema_name=schema,
                table_name=table,
            )
        except (DatabaseAdapterError, Exception) as exc:  # noqa: BLE001
            _logger.debug("Database adapter sampling failed: %s", type(exc).__name__)
            return SafeSampleResponse(
                status="error",
                message="Failed to retrieve sample rows from database adapter",
                schema_name=schema,
                table_name=table,
            )

        # Pre-sanitization bounds check (Finding 4)
        if len(raw_sample.rows) > limit or len(raw_sample.rows) > self._policy.max_sample_rows:
            return SafeSampleResponse(
                status="error",
                message="Database adapter returned more rows than requested limit",
                schema_name=schema,
                table_name=table,
            )

        if len(raw_sample.columns) > self._policy.max_sample_columns:
            return SafeSampleResponse(
                status="error",
                message="Database adapter returned more columns than allowed policy limit",
                schema_name=schema,
                table_name=table,
            )

        return raw_sample

    def _run_sanitization(
        self,
        raw_sample: SampleResult,
        schema: str,
        table: str,
    ) -> SanitizationResult | SafeSampleResponse:
        """Run Phase 3E sanitization orchestrator on raw sample."""
        try:
            return self._sanitizer.sanitize(raw_sample)
        except (SanitizationOrchestratorError, Exception) as exc:  # noqa: BLE001
            _logger.debug("Sanitization orchestrator failed: %s", type(exc).__name__)
            return SafeSampleResponse(
                status="rejected",
                message="Sample data could not be sanitized under security policy",
                schema_name=schema,
                table_name=table,
            )

    def _run_validation_and_packaging(
        self,
        sanitization_result: SanitizationResult,
        *,
        schema: str,
        table: str,
        truncated: bool,
    ) -> SafeSampleResponse:
        """Run Phase 3F validation, final boundary revalidation, and size budgeting."""
        pol_ver = sanitization_result.report.policy_version
        try:
            val_res = self._validator.validate(sanitization_result)
        except (LeakageValidationError, Exception) as exc:  # noqa: BLE001
            _logger.debug("Leakage validator failed: %s", type(exc).__name__)
            return SafeSampleResponse(
                status="rejected",
                message="Sample data failed leakage validation check",
                schema_name=schema,
                table_name=table,
                policy_version=pol_ver,
            )

        if not val_res.accepted or val_res.sample is None:
            return SafeSampleResponse(
                status="rejected",
                message="Sample data was rejected due to detected residual sensitive information",
                schema_name=schema,
                table_name=table,
                policy_version=pol_ver,
                validator_version=val_res.report.validator_version,
            )

        # Mandatory final boundary revalidation
        revalidated = final_revalidate_sample(val_res.sample)
        if revalidated is None:
            return SafeSampleResponse(
                status="rejected",
                message="Sample data failed final prompt boundary security revalidation",
                schema_name=schema,
                table_name=table,
                policy_version=pol_ver,
                validator_version=val_res.report.validator_version,
            )

        cols, rows, pol_version, val_version = revalidated
        initial_resp = SafeSampleResponse(
            status="success",
            message="Sample retrieved and validated successfully",
            schema_name=schema,
            table_name=table,
            columns=cols,
            rows=rows,
            row_count=len(rows),
            truncated=truncated,
            policy_version=pol_version,
            validator_version=val_version,
        )
        resp = self._apply_size_budget(initial_resp)

        try:
            validate_model_visible_response(resp, self._policy.max_result_size_chars)
        except Exception:  # noqa: BLE001
            return SafeSampleResponse(
                status="rejected",
                message="Sample response rejected by prompt boundary security policy",
                schema_name=schema,
                table_name=table,
                policy_version=pol_version,
                validator_version=val_version,
            )

        return resp

    def _apply_size_budget(self, response: SafeSampleResponse) -> SafeSampleResponse:
        """Apply model-visible character budget limit to sample rows by dropping whole rows."""
        budget = self._policy.max_result_size_chars
        if len(response.model_dump_json()) <= budget:
            return response

        kept = list(response.rows)
        while kept:
            kept.pop()
            candidate = response.model_copy(
                update={
                    "rows": tuple(kept),
                    "row_count": len(kept),
                    "truncated": True,
                }
            )
            if len(candidate.model_dump_json()) <= budget:
                return candidate

        return response.model_copy(
            update={
                "rows": (),
                "row_count": 0,
                "truncated": True,
            }
        )


__all__ = [
    "SecureDatabasePolicy",
    "SecureDatabaseTools",
    "canonicalize_metadata_text",
    "final_revalidate_sample",
    "has_instruction_injection",
    "is_safe_metadata_identifier",
    "is_safe_metadata_text",
    "scan_text_for_residual_secrets",
    "validate_model_visible_response",
]
