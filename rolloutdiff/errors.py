"""Shared exception types."""


class MalformedInputError(Exception):
    """Raised when input YAML/paths cannot be parsed into valid k8s object docs.

    Maps to CLI exit code 2.
    """
