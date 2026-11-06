"""Located metadata objects. Fetching establishes integrity, never authority."""

from __future__ import annotations

import base64

from .metadata_objects import ObjectStore
from .object_native import addressed, objects_read, sessioned, verify
from .pack_store import MAX_OBJECT_BYTES, missing_object, publish_object


class LocatedStore(ObjectStore):
    def __init__(self, directory, fetch=None):
        super().__init__(directory)
        self.fetch = fetch

    @sessioned
    def blob(self, reference, depth=0):
        # The runtime walks the reference and names every object the cache lacks;
        # each is fetched, verified natively, then published before asking again.
        fetched: set[str] = set()
        while True:
            reply = addressed(
                "expand",
                sources=objects_read(self.directory),
                mode="located",
                directory=str(self.directory),
                reference=reference,
                depth=depth,
                invalid="located delivery reference invalid",
            )
            if "need" not in reply:
                break
            self._transfer(reply["need"], fetched)
        self.reads.update(reply["reads"])
        return base64.b64decode(reply["data"], validate=True)

    def _transfer(self, need, fetched):
        if self.fetch is None:
            raise missing_object(self.directory, need[0]["sha256"])
        for row in need:
            if row["sha256"] in fetched:
                raise ValueError("located delivery object missing after fetch")
            fetched.add(row["sha256"])
            data = self.fetch(row["location"], row["length"])
            if len(data) > MAX_OBJECT_BYTES:
                # Too large to send for checking; no object is this big.
                raise ValueError("fetched delivery object integrity invalid")
            verify(data, row["sha256"], row["length"])
            publish_object(self.directory, row["sha256"], data)
