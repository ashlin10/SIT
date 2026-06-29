"""Deterministic pre-push validation & sanitization for FMC device config.

Public API:
    validate_config(config, target_interfaces, ...) -> ValidationReport
    sanitize_config(config, ...) -> {sanitized_config, changes, diff}
"""
from .engine import sanitize_config, validate_config
from .models import Issue, InterfaceConflict, TargetInfo, ValidationReport

__all__ = [
    "validate_config",
    "sanitize_config",
    "ValidationReport",
    "Issue",
    "InterfaceConflict",
    "TargetInfo",
]
