"""Structured exception hierarchy."""

from __future__ import annotations


class DirsearchByPassError(Exception):
    """Base error for the project."""


class ConfigurationError(DirsearchByPassError):
    """Invalid or incomplete configuration."""


class AssetError(DirsearchByPassError):
    """Missing, invalid, or unreadable runtime asset."""


class CapabilityError(DirsearchByPassError):
    """A requested optional capability is unavailable."""


class RequestError(DirsearchByPassError):
    """A network request failed after the executor's policy was applied."""


class BudgetExceeded(RequestError):
    """A request budget or rate policy stopped the next network send."""


class CancelledError(DirsearchByPassError):
    """The run was cancelled before the request was sent."""


class ComponentError(DirsearchByPassError):
    """A component failed while producing a result."""
