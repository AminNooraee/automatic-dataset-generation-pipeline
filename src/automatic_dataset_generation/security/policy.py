"""Immutable, deterministic Phase 3A sanitization policy."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003 - Pydantic resolves field types at runtime.
from types import MappingProxyType
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from automatic_dataset_generation.security.models import (
    FieldClassification,
    SanitizationAction,
    SanitizationDecision,
    SensitivityClass,
)

_MAX_POLICY_VERSION_LENGTH = 64


def _default_actions() -> dict[SensitivityClass, SanitizationAction]:
    return {
        SensitivityClass.NON_SENSITIVE: SanitizationAction.ALLOW,
        SensitivityClass.PII: SanitizationAction.PSEUDONYMIZE,
        SensitivityClass.SECRET: SanitizationAction.REDACT,
        SensitivityClass.CREDENTIAL: SanitizationAction.REDACT,
        SensitivityClass.UNKNOWN: SanitizationAction.REDACT,
    }


class SanitizationPolicy(BaseModel):
    """Complete fail-closed classification-to-action policy with stable lineage."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    policy_version: str = Field(default="1", max_length=_MAX_POLICY_VERSION_LENGTH)
    actions: Mapping[SensitivityClass, SanitizationAction] = Field(default_factory=_default_actions)

    @field_validator("policy_version")
    @classmethod
    def validate_policy_version(cls, value: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("policy_version must be non-empty text without NUL")
        return value

    @model_validator(mode="after")
    def validate_and_freeze_actions(self) -> Self:
        expected = set(SensitivityClass)
        if set(self.actions) != expected or len(self.actions) != len(expected):
            raise ValueError("policy must configure every sensitivity exactly once")
        for sensitivity in (
            SensitivityClass.PII,
            SensitivityClass.SECRET,
            SensitivityClass.CREDENTIAL,
            SensitivityClass.UNKNOWN,
        ):
            if self.actions[sensitivity] is SanitizationAction.ALLOW:
                raise ValueError("policy cannot allow sensitive or unknown data")
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))
        return self

    @field_serializer("actions")
    def serialize_actions(
        self, actions: Mapping[SensitivityClass, SanitizationAction]
    ) -> dict[SensitivityClass, SanitizationAction]:
        """Serialize the immutable runtime mapping as ordinary configuration data."""
        return dict(actions)

    def action_for(self, sensitivity: SensitivityClass) -> SanitizationAction:
        """Return the deterministic configured action for one classification."""
        if not isinstance(sensitivity, SensitivityClass):
            raise TypeError("sensitivity must be a SensitivityClass")
        return self.actions[sensitivity]

    def decide(self, classification: FieldClassification) -> SanitizationDecision:
        """Build a metadata-only decision from policy and classification metadata."""
        return SanitizationDecision(
            field=classification.field,
            sensitivity=classification.sensitivity,
            action=self.action_for(classification.sensitivity),
            policy_version=self.policy_version,
            reason_code="policy_mapping",
        )
