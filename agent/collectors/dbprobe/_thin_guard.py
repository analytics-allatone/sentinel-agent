"""
collectors/dbprobe/_thin_guard.py
─────────────────────────────────
Import this BEFORE `import oracledb` on hosts where an Application Control
policy (WDAC / AppLocker) blocks the thick-mode binary:

    DLL load failed while importing thick_impl:
    An Application Control policy has blocked this file.

Why this is needed
------------------
oracledb/__init__.py does, unconditionally:

    from . import base_impl, thick_impl, thin_impl

so `thick_impl.pyd` is loaded the moment the package is imported — long before
any thin/thick decision is made. Simply "using thin mode" therefore does NOT
avoid the blocked file.

What this does
--------------
Pre-seeds sys.modules["oracledb.thick_impl"] with a stub, so Python finds it
already imported and never touches the blocked binary. Thin mode (pure Python
Oracle protocol, implemented in thin_impl) keeps working normally.

Thick mode becomes unavailable — calling init_oracle_client() raises a clear
error. That is intentional: thick mode is exactly what the policy blocks.
"""

import sys
import types

_MOD = "oracledb.thick_impl"


def install(force: bool = False) -> bool:
    """Install the stub. Returns True if the stub is in place.

    By default this is a no-op if the real thick_impl already imported fine
    (i.e. the host has no blocking policy), so unaffected machines keep full
    thick-mode capability. Pass force=True to always stub it.
    """
    if "oracledb" in sys.modules and not force:
        # oracledb already imported successfully — nothing to protect against.
        return _MOD in sys.modules and _is_stub(sys.modules[_MOD])

    if not force and _real_thick_loads():
        return False

    stub = types.ModuleType(_MOD)
    stub.__dict__["_is_thin_guard_stub"] = True

    def _unavailable(*_a, **_kw):
        raise RuntimeError(
            "Oracle thick mode is unavailable on this host: thick_impl is "
            "blocked by an Application Control policy. Use thin mode "
            "(do not call init_oracle_client)."
        )

    # Called by oracledb/__init__.py during package init — must be a no-op.
    stub.init_oracle_client = _unavailable
    stub.clientversion = _unavailable
    stub.init_thick_impl = lambda package=None: None

    # Referenced by connection.py / pool.py isinstance() checks.
    class ThickConnImpl:  # noqa: D401
        pass

    class ThickPoolImpl:
        pass

    stub.ThickConnImpl = ThickConnImpl
    stub.ThickPoolImpl = ThickPoolImpl

    sys.modules[_MOD] = stub
    return True


def _is_stub(mod) -> bool:
    return bool(getattr(mod, "_is_thin_guard_stub", False))


def _real_thick_loads() -> bool:
    """Probe whether the genuine thick_impl binary can be loaded."""
    try:
        import importlib
        importlib.import_module(_MOD)
        return True
    except BaseException:
        # ImportError on a normal miss; OSError/DLL-load error when blocked.
        return False


def active() -> bool:
    """True if the stub is currently installed."""
    mod = sys.modules.get(_MOD)
    return bool(mod and _is_stub(mod))
