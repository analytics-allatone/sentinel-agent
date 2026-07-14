"""Shared helpers for engine inspectors: JSON-safe value coercion + row fetch."""
from decimal import Decimal
import datetime as _dt
from datetime import datetime, date, time as _time, timedelta
from decimal import Decimal
import uuid

def na(value, default="N/A"):
    """Return value, or a placeholder when it's missing/empty (Not Available)."""
    if value is None:
        return default
    if isinstance(value, str) and value.strip() == "":
        return default
    return value

def jsonable(obj):
    """Recursively convert DB/driver values into JSON/MQTT-safe Python types."""
    if obj is None or isinstance(obj, (str, bool, int, float)):
        return obj
    if isinstance(obj, Decimal):
        try:
            return int(obj) if obj == obj.to_integral_value() else float(obj)
        except Exception:
            return float(obj)
    if isinstance(obj, (datetime, date, _time)):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        try:
            return b.decode("utf-8")
        except Exception:
            return b.hex()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(x) for x in obj]
    if hasattr(obj, "read"):            # cx_Oracle / oracledb LOB (CLOB/BLOB)
        try:
            return jsonable(obj.read())
        except Exception:
            pass
    return str(obj)

def jsonify(v):
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, _dt.timedelta):
        return round(v.total_seconds(), 3)          # intervals/lags -> seconds
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()
    if isinstance(v, (bytes, memoryview)):
        try:
            return bytes(v).decode("utf-8", "ignore")
        except Exception:
            return str(v)
    return v


def rows(cur, sql, params=None):
    """Run sql, return list of dicts keyed by column name, JSON-safe."""
    cur.execute(sql, params or ())
    if not cur.description:
        return []
    cols = [c[0] for c in cur.description]
    return [{cols[i]: jsonify(val) for i, val in enumerate(r)} for r in cur.fetchall()]


def one(cur, sql, params=None):
    rs = rows(cur, sql, params)
    return rs[0] if rs else {}


def safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default
