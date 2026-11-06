"""Typed local connector persistence failures."""


class LocalCliCatalogLimitError(ValueError):
    """A catalog update would silently omit observed tools."""
