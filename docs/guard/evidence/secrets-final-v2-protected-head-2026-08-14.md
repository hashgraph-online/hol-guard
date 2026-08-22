# HOL Guard Secrets final v2 protected head

This connector-authored commit follows the validated permanent hardening commit and triggers normal protected pull-request checks on the exact head.

Required evidence includes repository CI, Security Gates, CodeQL, Linux, macOS, and Windows exact-wheel and pipx installation, real Git and pre-commit lifecycle, privacy-safe setup diagnostics, fail-honest file and Git-object coverage, pinned hook identity, resolved review, and post-merge target verification. The base remains `release/3.0` and must never be retargeted to `main`.
