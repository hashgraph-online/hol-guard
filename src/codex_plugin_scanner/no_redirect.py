"""HTTP redirect policy shared by authenticated and verification transports."""

from __future__ import annotations

import urllib.request


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Return redirect responses to the caller without issuing a second request."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None
