"""Base dependencies reexported by the daemon namespace."""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import inspect
import json
import logging
import math
import mimetypes
import os
import platform
import secrets
import socket
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, TypeAlias, TypedDict, TypeGuard, cast
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from ...version import __version__
from ..action_lattice import is_guard_action as _is_guard_action

__all__ = [
    "Any",
    "BaseHTTPRequestHandler",
    "BinaryIO",
    "Callable",
    "ClassVar",
    "Mapping",
    "Path",
    "TypeAlias",
    "TypeGuard",
    "TypedDict",
    "__version__",
    "_is_guard_action",
    "base64",
    "cast",
    "datetime",
    "errno",
    "hashlib",
    "hmac",
    "inspect",
    "json",
    "logging",
    "math",
    "mimetypes",
    "os",
    "parse_qs",
    "parse_qsl",
    "platform",
    "secrets",
    "socket",
    "sqlite3",
    "stat",
    "suppress",
    "tempfile",
    "threading",
    "time",
    "timezone",
    "unquote",
    "urlencode",
    "urlparse",
    "urlunparse",
    "uuid",
]
