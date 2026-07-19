# Third-Party Notices

This file documents third-party software included with or used by HOL Guard's
tray icon feature.

## HOL Guard

Licensed under the Apache License, Version 2.0.

## pystray

- **Version**: >= 0.19.5, < 0.20
- **License**: LGPLv3 (GNU Lesser General Public License v3.0)
- **Author**: Moses Palmer
- **URL**: https://github.com/moses-palmer/pystray

pystray provides cross-platform system tray icon support. It is imported
dynamically at runtime — HOL Guard does not statically link or bundle pystray
source code. The LGPLv3 license permits use as a dynamically-linked library
without copyleft obligations on the consuming application.

**LGPLv3 obligations satisfied**:
- The pystray package is installed as an independent dependency via pip/pipx,
  not bundled into HOL Guard's wheel or sdist.
- HOL Guard's source code is available under Apache-2.0, which is compatible
  with LGPLv3's requirements for combined works.
- Users can replace the pystray library independently of HOL Guard.

## Pillow

- **Version**: >= 11.0, < 13
- **License**: MIT-CMU (MIT License with CMU historical attribution)
- **URL**: https://python-pillow.org

Pillow provides image loading for tray icon assets. Used to load PNG icons
via `importlib.resources`.

## PyObjC (macOS only)

- **Component**: pyobjc-framework-Quartz
- **Version**: >= 10.0
- **License**: MIT
- **URL**: https://pyobjc.readthedocs.io

PyObjC provides the AppKit backend for pystray on macOS. Installed only on
macOS via a platform marker in `pyproject.toml`.

## python-xlib (Linux x86_64 only)

- **Version**: >= 0.33
- **License**: LGPLv2.1+
- **URL**: https://github.com/python-xlib/python-xlib

python-xlib provides the X11 backend for pystray on Linux. Installed only on
Linux x86_64 via a platform marker in `pyproject.toml.

## six

- **License**: MIT
- **URL**: https://github.com/benjaminp/six

Transitive dependency of pystray. Provides Python 2/3 compatibility shims.
