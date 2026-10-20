"""Shared build-time reachability accounting without directory rendering imports."""

from extension_delivery_located_store import LocatedStore


class InventoryStore(LocatedStore):
    def __init__(self, directory):
        super().__init__(directory)
        self.assets = {}

    def mark(self, kind, digest, length, target):
        key = (target["tag"], target["asset"])
        if "member" in target:
            row = self.assets.setdefault(
                key, {"kind": "container", "location": {"tag": key[0], "asset": key[1]}, "members": {}}
            )
            member = {"sha256": digest, "length": length}
            if row["kind"] != "container" or (
                target["member"] in row["members"] and row["members"][target["member"]] != member
            ):
                raise ValueError("delivery container has conflicting members")
            row["members"][target["member"]] = member
            return
        row = {"sha256": digest, "length": length, "kind": kind, "location": target}
        if key in self.assets and self.assets[key] != row:
            raise ValueError("delivery asset location has conflicting content")
        self.assets[key] = row

    def blob(self, reference, depth=0):
        value = super().blob(reference, depth)
        self.mark("object", reference["sha256"], reference["length"], reference["location"])
        return value
