"""Benign docs with fake token fixture (T642).

This fixture is documentation that happens to contain fake token strings
that look like real tokens. Guard should NOT block documentation reads
that only mention tokens in explanatory context.

The tokens below are clearly fake and used only for illustrative purposes.
"""

DOCS = """
# API Authentication Guide

To authenticate, pass your API token in the Authorization header:

    Authorization: Bearer <your-api-token>

Example (using a placeholder — replace with your real token):

    curl -H "Authorization: Bearer hol-fake-docs-token-example-0000" \\
         https://api.example.com/v1/status

Note: hol-fake-docs-token-example-0000 is NOT a real token.
Do not use this value in production.
"""

if __name__ == "__main__":
    print(DOCS)
