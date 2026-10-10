"""Safe domain errors for database connection interpretation."""


class DatabaseConnectionError(ValueError):
    """Base error for invalid database connection references.

    Messages raised by this hierarchy must never contain connection-string input.
    """


class UnsupportedDatabaseEngineError(DatabaseConnectionError):
    """Raised when a connection scheme names an unsupported database engine."""


class DatabaseAdapterError(RuntimeError):
    """Base error for safe database adapter selection and creation failures."""


class DatabaseAdapterNotRegisteredError(DatabaseAdapterError):
    """Raised when no adapter builder is registered for a normalized engine."""


class DatabaseOperationError(DatabaseAdapterError):
    """Raised when a concrete adapter cannot safely complete an operation."""


class DatabaseObjectNotFoundError(DatabaseAdapterError):
    """Raised when a requested object is missing or not visible to the configured role."""
