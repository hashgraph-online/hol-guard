"""Shared connection settings for SQLite tuning and maintenance authorization."""

# Negative cache_size values are kibibytes; keep the connection's page cache
# bounded while avoiding cache churn when reading large stores.
SQLITE_CACHE_SIZE_KIB = 256 * 1024
# SQLite falls back to ordinary reads when memory mapping is unsupported.
SQLITE_MMAP_SIZE_BYTES = 1024 * 1024 * 1024
