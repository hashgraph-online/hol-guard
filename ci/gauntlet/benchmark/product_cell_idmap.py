"""Versioned identities of trusted idmapped-mount helpers on owned VMs."""
import hashlib
from pathlib import Path

PROFILES = {
    'ubuntu2404-product-v1': (
        'd1f8e1f8e0b78f702f9d4ee0d996abd27f290ce0aa8a5490aa497d1c87b39092',
        '507b07264482e5e29171d9bf202abcac55ce85d0eb5d8b7100f07f1081578a63'),
    'ubuntu2404-controller-v1': (
        'a4e2960330ff237a185306d9d92df1fc69ee77d8abe9d3282f662f54e13f01f4',
        'cfa453687fb8eee3c6f8e06de6ab2c1f9dfc59b94d05477593fae99fe7fe1e6d'),
}
PATHS = ('/usr/bin/mount', '/usr/lib/aarch64-linux-gnu/libmount.so.1.1.0')


def verify(profile, *, trusted):
    if type(profile) is not str or profile not in PROFILES:
        raise ValueError('versioned idmapping runtime identity required')
    for name, pin in zip(PATHS, PROFILES[profile], strict=True):
        path = Path(name)
        trusted(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            raise ValueError('task idmapping runtime digest mismatch')
