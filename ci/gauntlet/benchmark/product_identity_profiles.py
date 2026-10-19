"""Fixed unprivileged identities; profiles cannot choose arbitrary host UIDs."""

PROFILES={'native-product-v1':10004,'private-cell-mcp-v2':10005}


def product_uid(profile):
    if type(profile) is not str or profile not in PROFILES:
        raise ValueError('explicit supported product identity profile required')
    return PROFILES[profile]
